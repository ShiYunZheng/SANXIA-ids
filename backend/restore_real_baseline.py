"""Back up and restore the SANXIA MongoDB database to the verified real baseline.

The command is intentionally guarded by exact pre-cleanup counts.  It refuses to
delete anything if the database no longer matches the read-only audit on which
the cleanup plan was based.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

from bson import BSON, decode_file_iter
from pymongo import MongoClient
from pymongo.uri_parser import parse_uri

from app.config import Config


BACKUP_COLLECTIONS = (
    "dashboard",
    "event",
    "record",
    "dashboard_batches",
    "realtime_inference_results",
    "judgements",
)

DELETE_QUERIES = {
    "dashboard": {"machine_component": {"$regex": "^test$", "$options": "i"}},
    "event": {
        "$or": [
            {"eventType": {"$regex": "test", "$options": "i"}},
            {"detail.component": {"$regex": "test", "$options": "i"}},
        ]
    },
    "record": {"pipelineRunId": {"$exists": True}},
    "dashboard_batches": {"kind": {"$ne": "baseline"}},
    "realtime_inference_results": {},
    "judgements": {},
}

EXPECTED_TOTALS_BEFORE = {
    "dashboard": 80_418,
    "event": 42,
    "record": 90,
    "dashboard_batches": 209,
    "realtime_inference_results": 2_817,
    "judgements": 2,
}

EXPECTED_DELETE_COUNTS = {
    "dashboard": 39_449,
    "event": 37,
    "record": 56,
    "dashboard_batches": 208,
    "realtime_inference_results": 2_817,
    "judgements": 2,
}

EXPECTED_TOTALS_AFTER = {
    "dashboard": 40_969,
    "event": 5,
    "record": 34,
    "dashboard_batches": 1,
    "realtime_inference_results": 0,
    "judgements": 0,
}

PRESERVED_COLLECTIONS = ("users", "detect_metrics", "detect_uploads")


def _database():
    parsed = parse_uri(Config.MONGO_URI)
    database_name = parsed.get("database")
    if not database_name:
        raise RuntimeError("MONGO_URI must include a database name")
    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5_000)
    client.admin.command("ping")
    return client, client[database_name]


def _counts(db, queries):
    return {name: db[name].count_documents(query) for name, query in queries.items()}


def _assert_equal(label, actual, expected):
    if actual != expected:
        raise RuntimeError(
            f"{label} does not match the verified cleanup plan. "
            f"expected={expected}, actual={actual}"
        )


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dump_collection(collection, path):
    count = 0
    with path.open("wb") as stream:
        for document in collection.find({}):
            stream.write(BSON.encode(document))
            count += 1
    return count


def _read_backup(path):
    with path.open("rb") as stream:
        yield from decode_file_iter(stream)


def _restore_from_backup(db, backup_dir, manifest):
    for name in BACKUP_COLLECTIONS:
        db[name].delete_many({})
        documents = list(_read_backup(backup_dir / f"{name}.bson"))
        if documents:
            db[name].insert_many(documents, ordered=False)
    restored = {name: db[name].count_documents({}) for name in BACKUP_COLLECTIONS}
    _assert_equal("automatic rollback counts", restored, manifest["countsBefore"])


def _write_json(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _preflight(db):
    totals = {name: db[name].count_documents({}) for name in BACKUP_COLLECTIONS}
    deletes = _counts(db, DELETE_QUERIES)
    _assert_equal("pre-cleanup collection totals", totals, EXPECTED_TOTALS_BEFORE)
    _assert_equal("pre-cleanup deletion counts", deletes, EXPECTED_DELETE_COUNTS)

    attack_count = db.dashboard.count_documents({"attack_type": {"$ne": "Normal"}})
    expected_attack_before = 50_746
    _assert_equal("pre-cleanup attack count", attack_count, expected_attack_before)

    return totals, deletes, attack_count


def _verify_after(db, preserved_before):
    totals = {name: db[name].count_documents({}) for name in BACKUP_COLLECTIONS}
    _assert_equal("post-cleanup collection totals", totals, EXPECTED_TOTALS_AFTER)

    verification = {
        "dashboard": totals["dashboard"],
        "attackSamples": db.dashboard.count_documents({"attack_type": {"$ne": "Normal"}}),
        "events": totals["event"],
        "records": totals["record"],
        "baselineBatches": db.dashboard_batches.count_documents({"kind": "baseline"}),
        "testDashboardRows": db.dashboard.count_documents(DELETE_QUERIES["dashboard"]),
        "testEvents": db.event.count_documents(DELETE_QUERIES["event"]),
        "runtimeRecords": db.record.count_documents(DELETE_QUERIES["record"]),
        "nonBaselineBatches": db.dashboard_batches.count_documents(
            DELETE_QUERIES["dashboard_batches"]
        ),
        "realtimeInferenceResults": totals["realtime_inference_results"],
        "judgements": totals["judgements"],
    }
    expected = {
        "dashboard": 40_969,
        "attackSamples": 32_308,
        "events": 5,
        "records": 34,
        "baselineBatches": 1,
        "testDashboardRows": 0,
        "testEvents": 0,
        "runtimeRecords": 0,
        "nonBaselineBatches": 0,
        "realtimeInferenceResults": 0,
        "judgements": 0,
    }
    _assert_equal("post-cleanup baseline verification", verification, expected)

    preserved_after = {
        name: db[name].count_documents({}) for name in PRESERVED_COLLECTIONS
    }
    _assert_equal("preserved collection counts", preserved_after, preserved_before)
    return verification, preserved_after


def run(apply):
    client, db = _database()
    try:
        totals, deletes, attack_count = _preflight(db)
        preserved = {name: db[name].count_documents({}) for name in PRESERVED_COLLECTIONS}
        preview = {
            "database": db.name,
            "countsBefore": totals,
            "deleteCounts": deletes,
            "attackSamplesBefore": attack_count,
            "preservedCollectionCounts": preserved,
            "expectedCountsAfter": EXPECTED_TOTALS_AFTER,
        }
        print(json.dumps(preview, ensure_ascii=False, indent=2))
        if not apply:
            print("DRY RUN ONLY: pass --apply to create the backup and perform cleanup.")
            return

        timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%z")
        backup_dir = Path(__file__).resolve().parent / "backups" / f"restore-real-{timestamp}"
        backup_dir.mkdir(parents=True, exist_ok=False)

        target_ids = {
            name: [str(item["_id"]) for item in db[name].find(query, {"_id": 1})]
            for name, query in DELETE_QUERIES.items()
        }
        _write_json(backup_dir / "deleted-document-ids.json", target_ids)

        files = {}
        for name in BACKUP_COLLECTIONS:
            path = backup_dir / f"{name}.bson"
            dumped = _dump_collection(db[name], path)
            _assert_equal(f"backup count for {name}", dumped, totals[name])
            decoded = sum(1 for _ in _read_backup(path))
            _assert_equal(f"decoded backup count for {name}", decoded, totals[name])
            files[name] = {
                "file": path.name,
                "documents": dumped,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }

        manifest = {
            "status": "backup_verified",
            "createdAt": datetime.now().astimezone().isoformat(),
            **preview,
            "deleteQueryDescriptions": {
                "dashboard": "machine_component equals test (case-insensitive)",
                "event": "eventType or detail.component contains test (case-insensitive)",
                "record": "pipelineRunId exists",
                "dashboard_batches": "kind is not baseline",
                "realtime_inference_results": "all documents",
                "judgements": "all documents",
            },
            "files": files,
        }
        _write_json(backup_dir / "manifest.json", manifest)

        deleted = {}
        try:
            for name, query in DELETE_QUERIES.items():
                deleted[name] = db[name].delete_many(query).deleted_count
            _assert_equal("actual deletion counts", deleted, EXPECTED_DELETE_COUNTS)
            verification, preserved_after = _verify_after(db, preserved)
        except Exception as exc:
            manifest["status"] = "cleanup_failed_rolling_back"
            manifest["failure"] = repr(exc)
            manifest["deletedCounts"] = deleted
            _write_json(backup_dir / "manifest.json", manifest)
            _restore_from_backup(db, backup_dir, manifest)
            manifest["status"] = "rolled_back"
            manifest["rolledBackAt"] = datetime.now().astimezone().isoformat()
            _write_json(backup_dir / "manifest.json", manifest)
            raise

        manifest.update(
            {
                "status": "complete",
                "completedAt": datetime.now().astimezone().isoformat(),
                "deletedCounts": deleted,
                "verification": verification,
                "preservedCollectionCountsAfter": preserved_after,
            }
        )
        _write_json(backup_dir / "manifest.json", manifest)
        print(json.dumps({"backupDir": str(backup_dir), **verification}, ensure_ascii=False, indent=2))
    finally:
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create a verified BSON backup and apply the guarded cleanup.",
    )
    arguments = parser.parse_args()
    try:
        run(arguments.apply)
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

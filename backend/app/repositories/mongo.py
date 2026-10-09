from datetime import datetime, timezone

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import BulkWriteError, DuplicateKeyError


class UserRepository:
    def __init__(self, collection):
        self.collection = collection

    def ensure_indexes(self):
        self.collection.create_index([("username", ASCENDING)], unique=True)

    def find_by_id(self, object_id):
        return self.collection.find_one({"_id": object_id}, {"password": 0})

    def find_by_username(self, username, include_password=False):
        projection = {} if include_password else {"password": 0}
        return self.collection.find_one({"username": username}, projection)

    def list(self, role=None):
        query = {} if role is None else {"role": role}
        return self.collection.find(query, {"password": 0}).sort("username", ASCENDING)

    def insert(self, user):
        return self.collection.insert_one(user)

    def update(self, object_id, fields):
        return self.collection.update_one({"_id": object_id}, {"$set": fields})


class DashboardRepository:
    def __init__(self, collection, batch_collection):
        self.collection = collection
        self.batch_collection = batch_collection

    def ensure_indexes(self):
        self.batch_collection.create_index([("batch_hash", ASCENDING)], unique=True)
        self.collection.create_index(
            [("source_sample_id", ASCENDING)],
            unique=True,
            partialFilterExpression={"source_sample_id": {"$type": "string"}},
        )
        self.collection.create_index([("timestamp", DESCENDING)])
        self.collection.create_index([("attack_type", ASCENDING), ("machine_component", ASCENDING)])

    def insert_batch_marker(self, marker):
        return self.batch_collection.insert_one(marker)

    def has_batch_marker(self, batch_hash):
        return self.batch_collection.count_documents({"batch_hash": batch_hash}, limit=1) > 0

    def insert_unique(self, items):
        try:
            self.collection.insert_many(items, ordered=False)
            return list(range(len(items)))
        except BulkWriteError as error:
            write_errors = error.details.get("writeErrors", [])
            unexpected = [item for item in write_errors if item.get("code") != 11000]
            if unexpected:
                raise
            duplicate_indices = {int(item["index"]) for item in write_errors}
            return [index for index in range(len(items)) if index not in duplicate_indices]

    def count(self, query):
        return self.collection.count_documents(query)

    def summary_counts(self):
        return list(self.collection.aggregate([
            {"$group": {
                "_id": {
                    "attack_type": "$attack_type",
                    "machine_component": "$machine_component",
                },
                "count": {"$sum": 1},
            }},
        ]))

    def latest_timestamp(self):
        item = self.collection.find_one(
            {"timestamp": {"$type": "number"}},
            {"timestamp": 1, "_id": 0},
            sort=[("timestamp", DESCENDING)],
        )
        return float(item["timestamp"]) if item and item.get("timestamp") is not None else None

    def history(self, start_seconds, end_seconds, bucket_seconds, attack_types):
        pipeline = [
            {"$match": {
                "timestamp": {"$gte": start_seconds, "$lte": end_seconds},
                "attack_type": {"$in": list(attack_types)},
            }},
            {"$project": {
                "attack_type": 1,
                "bucket": {"$floor": {"$divide": [{"$subtract": ["$timestamp", start_seconds]}, bucket_seconds]}},
            }},
            {"$group": {
                "_id": {"bucket": "$bucket", "attack_type": "$attack_type"},
                "count": {"$sum": 1},
            }},
        ]
        return list(self.collection.aggregate(pipeline))


class RecordRepository:
    def __init__(self, collection):
        self.collection = collection

    def insert(self, record):
        return self.collection.insert_one(record)

    def page(self, page, page_size, query, projection):
        return self.collection.find(query, projection).sort("_id", DESCENDING).skip((page - 1) * page_size).limit(page_size)

    def count(self, query):
        return self.collection.count_documents(query)


class EventRepository:
    def __init__(self, collection):
        self.collection = collection

    def ensure_indexes(self):
        self.collection.create_index(
            [("archiveKey", ASCENDING)],
            unique=True,
            partialFilterExpression={"archiveKey": {"$type": "string"}},
        )

    def normalize_severities(self, severity_by_label, severity_names, policy_version):
        modified = 0
        for attack_label, severity in severity_by_label.items():
            query = {"engine": {"$ne": "standalone"}, "attackLabel": attack_label}
            result = self.collection.update_many(query, {"$set": {
                "eventSeverity": int(severity),
                "severityPolicyVersion": policy_version,
            }})
            modified += int(result.modified_count)
            self.collection.update_many(
                {**query, "judgement": {"$type": "object"}},
                {"$set": {
                    "judgement.eventSeverity": int(severity),
                    "judgement.attackInfo.severity": severity_names[int(severity)],
                }},
            )
        return modified

    def normalize_risk_assessments(self, risk_policy):
        modified = 0
        query = {
            "engine": {"$ne": "standalone"},
            "severitySource": {"$ne": "human"},
            "severityLocked": {"$ne": True},
            "severityPolicyVersion": {"$ne": "attack-rule-v2"},
        }
        for event in self.collection.find(query):
            risk = risk_policy.assess_event(event)
            fields = {**risk}
            severity = int(risk["eventSeverity"])
            fields["judgement.eventSeverity"] = severity
            fields["judgement.attackInfo.severity"] = ("critical", "high", "medium", "low")[severity]
            result = self.collection.update_one(
                {"_id": event["_id"], "severityLocked": {"$ne": True}},
                {"$set": fields},
            )
            modified += int(result.modified_count)
        return modified

    def insert(self, event):
        return self.collection.insert_one(event)

    def find_by_id(self, object_id):
        return self.collection.find_one({"_id": object_id})

    def find_matching_archive(self, archive_key, attack_label, data_source, timestamps):
        queries = [{"archiveKey": archive_key}]
        timestamp_values = [float(value) for value in timestamps if value is not None]
        if timestamp_values:
            queries.append({
                "attackLabel": attack_label,
                "dataSource": data_source,
                "detail.timestamp": {"$in": timestamp_values[:1] + timestamp_values[-1:]},
            })
        return self.collection.find_one({"$or": queries})

    def update_judgement(self, object_id, judgement):
        return self.collection.update_one({"_id": object_id}, {"$set": {"judgement": judgement}})

    def update_disposition(self, object_id, disposition, history_entry, severity_fields=None):
        fields = {"disposition": disposition}
        fields.update(severity_fields or {})
        return self.collection.find_one_and_update(
            {"_id": object_id},
            {
                "$set": fields,
                "$push": {"dispositionHistory": history_entry},
            },
            return_document=ReturnDocument.AFTER,
        )

    def page(self, page, page_size, query=None):
        return self.collection.find(query or {}).sort("_id", DESCENDING).skip((page - 1) * page_size).limit(page_size)

    def count(self, query=None):
        return self.collection.count_documents(query or {})

    def severity_counts(self, query=None):
        rows = self.collection.aggregate([
            {"$match": query or {}},
            {"$group": {"_id": "$eventSeverity", "count": {"$sum": 1}}},
        ])
        return {str(row["_id"]): int(row["count"]) for row in rows if row.get("_id") is not None}


class RealtimeInferenceRepository:
    def __init__(self, collection):
        self.collection = collection

    def ensure_indexes(self):
        self.collection.create_index([("windowKey", ASCENDING)], unique=True)
        self.collection.create_index([("createdAt", DESCENDING)])

    def insert_if_new(self, document):
        try:
            result = self.collection.insert_one(document)
            document["_id"] = result.inserted_id
            return document
        except DuplicateKeyError:
            return None

    def latest(self, limit=5):
        abnormal = list(
            self.collection.find({"predictedLabel": {"$ne": "normal"}})
            .sort("createdAt", DESCENDING)
            .limit(limit)
        )
        if len(abnormal) >= limit:
            return abnormal
        normal = list(
            self.collection.find({"predictedLabel": "normal"})
            .sort("createdAt", DESCENDING)
            .limit(limit - len(abnormal))
        )
        return abnormal + normal


class JudgementRepository:
    def __init__(self, collection):
        self.collection = collection

    def ensure_indexes(self):
        self.collection.create_index([("subject_type", ASCENDING), ("subject_key", ASCENDING)], unique=True)

    def find(self, subject_type, subject_key):
        return self.collection.find_one({"subject_type": subject_type, "subject_key": subject_key})

    def create_if_missing(self, subject_type, subject_key, content, engine):
        now = datetime.now(timezone.utc)
        return self.collection.find_one_and_update(
            {"subject_type": subject_type, "subject_key": subject_key},
            {"$setOnInsert": {
                "subject_type": subject_type,
                "subject_key": subject_key,
                "content": content,
                "engine": engine,
                "version": 1,
                "generated_at": now,
                "updated_at": now,
            }},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

    def regenerate(self, subject_type, subject_key, content, engine):
        now = datetime.now(timezone.utc)
        return self.collection.find_one_and_update(
            {"subject_type": subject_type, "subject_key": subject_key},
            {
                "$set": {"content": content, "engine": engine, "generated_at": now, "updated_at": now},
                "$inc": {"version": 1},
                "$setOnInsert": {"subject_type": subject_type, "subject_key": subject_key},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

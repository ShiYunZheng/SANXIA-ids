import hashlib
import json
import logging
import queue
import random
import threading
from collections import deque
from datetime import datetime, timezone

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from ..constants import ATTACK_TYPES, MACHINE_COMPONENTS
from ..errors import ApiError
from ..risk import DEFAULT_RISK_POLICY


def _iso_timestamp(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    if isinstance(value, datetime):
        current = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return current.isoformat()
    return str(value)


class EventQueue:
    def __init__(self, levels=4):
        self._queues = [queue.Queue() for _ in range(levels)]

    def push(self, event):
        severity = int(event.get("eventSeverity", 3))
        severity = min(max(severity, 0), len(self._queues) - 1)
        self._queues[severity].put(event)

    def pop(self):
        for current in self._queues:
            try:
                return current.get_nowait()
            except queue.Empty:
                continue
        return None


class EventBroadcaster:
    def __init__(self):
        self._subscribers = set()
        self._lock = threading.Lock()

    def subscribe(self):
        subscriber = queue.Queue(maxsize=200)
        with self._lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber):
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, event):
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(event)
                except queue.Empty:
                    pass


class DashboardService:
    def __init__(self, repository):
        self.repository = repository
        self._history = deque(maxlen=5)

    def insert_predictions(self, labels, machine_components, timestamps, source_sample_ids):
        labels = [int(label) for label in labels]
        source_sample_ids = list(source_sample_ids)
        marker_payload = {
            "labels": labels,
            "machineComponents": list(machine_components),
            "timestamps": list(timestamps),
            "sourceSampleIds": source_sample_ids,
        }
        batch_hash = hashlib.sha256(json.dumps(marker_payload, sort_keys=True, default=str).encode()).hexdigest()
        if self.repository.has_batch_marker(batch_hash):
            return {"inserted_indices": [], "inserted_count": 0, "duplicate_count": len(labels)}
        items = [
            {
                "attack_type": ATTACK_TYPES[label],
                "machine_component": component,
                "timestamp": float(timestamp),
                "source_sample_id": source_sample_id,
            }
            for label, component, timestamp, source_sample_id in zip(
                labels, machine_components, timestamps, source_sample_ids
            )
            if 0 <= label < len(ATTACK_TYPES)
        ]
        inserted_indices = self.repository.insert_unique(items) if items else []
        try:
            self.repository.insert_batch_marker({
                "batch_hash": batch_hash,
                "sample_count": len(items),
                "inserted_count": len(inserted_indices),
                "created_at": datetime.now(timezone.utc),
            })
        except DuplicateKeyError:
            pass
        return {
            "inserted_indices": inserted_indices,
            "inserted_count": len(inserted_indices),
            "duplicate_count": len(items) - len(inserted_indices),
        }

    def summary(self):
        pie_data = [{"name": attack_type, "total": 0} for attack_type in ATTACK_TYPES]
        attack_totals = {item["name"]: item for item in pie_data}
        list_data = [{"name": component, **{attack_type: 0 for attack_type in ATTACK_TYPES}} for component in MACHINE_COMPONENTS]
        component_rows = {item["name"]: item for item in list_data}
        if hasattr(self.repository, "summary_counts"):
            for result in self.repository.summary_counts():
                identifier = result.get("_id") or {}
                attack_type = identifier.get("attack_type")
                component = identifier.get("machine_component")
                count = int(result.get("count", 0))
                if attack_type in attack_totals:
                    attack_totals[attack_type]["total"] += count
                if component in component_rows and attack_type in attack_totals:
                    component_rows[component][attack_type] += count
        else:
            for row in list_data:
                for attack_type in ATTACK_TYPES:
                    count = self.repository.count({"attack_type": attack_type, "machine_component": row["name"]})
                    row[attack_type] = count
                    attack_totals[attack_type]["total"] += count
        malicious_total = sum(item["total"] for item in pie_data if item["name"] != "Normal")
        percentages = {
            item["name"]: item["total"] / malicious_total if malicious_total else 0
            for item in pie_data
            if item["name"] != "Normal"
        }
        return {"list_data": list_data, "pie_data": pie_data, "percentage_data": percentages}

    def realtime(self, interval_ms, end_timestamp, points, pipeline, events):
        summary = self.summary()
        history = self.history(interval_ms, end_timestamp, points)
        pipeline_status = pipeline.status()
        label_distribution = pipeline_status.get("labelDistribution") or {}
        persisted_distribution = pipeline_status.get("persistedLabelDistribution") or {}
        live_delta = {
            name: max(0, int(count or 0) - int(persisted_distribution.get(name, 0) or 0))
            for name, count in label_distribution.items()
        }

        pie_by_name = {item["name"]: item for item in summary["pie_data"]}
        for name, count in live_delta.items():
            if name in pie_by_name:
                pie_by_name[name]["total"] += count
        malicious_total = sum(item["total"] for item in summary["pie_data"] if item["name"] != "Normal")
        summary["percentage_data"] = {
            item["name"]: item["total"] / malicious_total if malicious_total else 0
            for item in summary["pie_data"] if item["name"] != "Normal"
        }

        if history:
            history[-1] = dict(history[-1])
            for name, count in live_delta.items():
                if name != "Normal" and name in history[-1]:
                    history[-1][name] = int(history[-1].get(name, 0)) + count

        canonical_total = sum(int(item.get("total", 0)) for item in summary["pie_data"]) - sum(live_delta.values())
        canonical_attacks = sum(int(item.get("total", 0)) for item in summary["pie_data"] if item["name"] != "Normal") - sum(
            count for name, count in live_delta.items() if name != "Normal"
        )
        try:
            event_total = events.total()
        except AttributeError:
            event_total = events.page(1, 1)["page"]["totalTotal"]
        pending_events = max(
            0,
            int(pipeline_status.get("candidateAlerts", 0) or 0) - int(pipeline_status.get("eventsCreated", 0) or 0),
        )
        return {
            "summary": summary,
            "history": history,
            "totals": {
                "monitoredTraffic": canonical_total + int(pipeline_status.get("processedSamples", 0) or 0) - int(pipeline_status.get("insertedSamples", 0) or 0),
                "attackAlerts": canonical_attacks + int(pipeline_status.get("attackPredictions", pipeline_status.get("attackSamples", 0)) or 0) - sum(
                    int(value or 0) for name, value in persisted_distribution.items() if name != "Normal"
                ),
                "riskEvents": int(event_total or 0) + pending_events,
            },
            "pipeline": {
                key: pipeline_status.get(key)
                for key in (
                    "runId", "runStatus", "running", "startedAt", "completedAt", "processedSamples",
                    "attackSamples", "attackPredictions", "candidateAlerts", "eventsCreated", "eventsRecovered", "labelDistribution",
                    "persistedLabelDistribution", "shadowMode", "lastError",
                )
            },
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }

    def history(self, interval_ms, end_timestamp=None, points=12):
        if interval_ms <= 0:
            raise ApiError("VALIDATION_ERROR", "intervalMs 必须大于 0", 400, {"field": "intervalMs"})
        points = max(1, min(int(points), 180))
        end_seconds = end_timestamp / 1000 if end_timestamp is not None else datetime.now(timezone.utc).timestamp()
        duration_seconds = interval_ms / 1000
        start_seconds = end_seconds - duration_seconds
        bucket_seconds = duration_seconds / points

        def load_window(window_start, window_end):
            rows = self.repository.history(window_start, window_end, bucket_seconds, ATTACK_TYPES[1:])
            buckets = [{attack_type: 0 for attack_type in ATTACK_TYPES[1:]} for _ in range(points)]
            for row in rows:
                identifier = row.get("_id", {})
                index = int(identifier.get("bucket", -1))
                attack_type = identifier.get("attack_type")
                if 0 <= index < points and attack_type in buckets[index]:
                    buckets[index][attack_type] = int(row.get("count", 0))
            return buckets

        buckets = load_window(start_seconds, end_seconds)
        # Existing deployments may contain an older imported dataset. When the
        # requested current window is empty, show that real historical window
        # instead of rendering a misleading all-zero chart.
        if not any(sum(bucket.values()) for bucket in buckets):
            latest = self.repository.latest_timestamp()
            if latest is not None and latest < start_seconds:
                end_seconds = latest
                start_seconds = end_seconds - duration_seconds
                buckets = load_window(start_seconds, end_seconds)

        return [
            {
                "time": datetime.fromtimestamp(start_seconds + bucket_seconds * (index + 1), tz=timezone.utc).isoformat(),
                **bucket,
            }
            for index, bucket in enumerate(buckets)
        ]

    def component(self, name):
        if name not in MACHINE_COMPONENTS:
            raise ApiError("COMPONENT_NOT_FOUND", "未知的设备组件", 404)
        return [
            {"attack_type": attack_type, "attack_count": self.repository.count({"attack_type": attack_type, "machine_component": name})}
            for attack_type in ATTACK_TYPES[1:]
        ]


class RecordService:
    accepts_run_metadata = True

    def __init__(self, repository):
        self.repository = repository

    def insert_detection(self, labels, pipeline_run_id=None):
        counts = {attack_type: 0 for attack_type in ATTACK_TYPES}
        for label in labels:
            index = int(label)
            if 0 <= index < len(ATTACK_TYPES):
                counts[ATTACK_TYPES[index]] += 1
        record = {attack_type: counts[attack_type] for attack_type in ATTACK_TYPES[1:]}
        record.update({"attack_total": sum(record.values()), "benign": counts["Normal"], "created_at": datetime.now(timezone.utc)})
        if pipeline_run_id:
            record["pipelineRunId"] = pipeline_run_id
        result = self.repository.insert(record)
        record["_id"] = result.inserted_id
        return record

    def page(self, page, page_size, start_at=None, end_at=None):
        query = {}
        if start_at or end_at:
            object_query = {}
            if start_at:
                object_query["$gte"] = ObjectId.from_datetime(start_at)
            if end_at:
                object_query["$lte"] = ObjectId.from_datetime(end_at)
            query["_id"] = object_query
        projection = {"timestamp": 1, "attack_total": 1, "benign": 1, **{name: 1 for name in ATTACK_TYPES[1:]}}
        items = []
        for record in self.repository.page(page, page_size, query, projection):
            record["timestamp"] = record.get("created_at", record["_id"].generation_time).astimezone(timezone.utc).isoformat()
            record["total"] = int(record.get("attack_total", 0)) + int(record.get("benign", 0))
            items.append(record)
        return {"items": items, "attackTypes": ATTACK_TYPES, "page": {"page": page, "pageSize": page_size, "totalTotal": self.repository.count(query)}}


class EventService:
    accepts_network_metadata = True
    accepts_source_metadata = True
    accepts_run_metadata = True
    accepts_model_evidence = True
    accepts_recovery_metadata = True

    def __init__(self, repository, risk_policy=None):
        self.repository = repository
        self.risk_policy = risk_policy or DEFAULT_RISK_POLICY
        self.events = EventQueue()
        self.broadcaster = EventBroadcaster()
        self.association_service = None

    def analyze(
        self, labels, timestamps, machine_components, source_ips=None, destination_ips=None,
        source_type=None, pipeline_run_id=None, model_evidence=None,
        unknown_threshold=None, skipped_packets=0, archive_key=None,
        restored_from_duplicate=False, source_fingerprint=None,
    ):
        labels = [int(label) for label in labels]
        created = []
        source_ips = list(source_ips or [None] * len(labels))
        destination_ips = list(destination_ips or [None] * len(labels))
        model_evidence = list(model_evidence or [{} for _ in labels])
        for label in sorted(set(labels)):
            if label == 0 or not 0 <= label < len(ATTACK_TYPES):
                continue
            matches = [
                (
                    timestamps[index], machine_components[index],
                    source_ips[index] if index < len(source_ips) else None,
                    destination_ips[index] if index < len(destination_ips) else None,
                    model_evidence[index] if index < len(model_evidence) else {},
                )
                for index, value in enumerate(labels) if value == label
            ]
            attacked_components = sorted({component for _, component, _, _, _ in matches})
            attack_label = ATTACK_TYPES[label]
            risk = self.risk_policy.assess(
                attack_label,
                [item[0] for item in matches],
                [item[1] for item in matches],
                [item[2] for item in matches],
                [item[3] for item in matches],
                [item[4] for item in matches],
                unknown_threshold,
            )
            detail = [
                {
                    "timestamp": float(timestamp),
                    "target": destination or component or "多节点",
                    "source": source or "未知源",
                    "component": component,
                    "source_ip": source,
                    "destination_ip": destination,
                }
                for timestamp, component, source, destination, evidence in matches
            ]
            for item, (_, _, _, _, evidence) in zip(detail, matches):
                item["knownConfidence"] = _finite_number(evidence.get("knownConfidence"))
                item["unknownScore"] = _finite_number(evidence.get("unknownScore"))
            event = {
                "eventType": f"{' '.join(attacked_components)} {attack_label}",
                **risk,
                "attackLabel": attack_label,
                "associationLabel": self.association_label({"attackLabel": attack_label}),
                "engine": "sanxia",
                "modelEvidence": _sanxia_evidence(matches, unknown_threshold, skipped_packets),
                "disposition": _default_disposition(),
                "dispositionHistory": [],
                "detail": detail,
            }
            source_label = {"interface": "WLAN实时", "replay": "PCAP回放", "pcap": "PCAP文件", "csv": "CSV文件"}.get(source_type)
            if source_label:
                event["dataSource"] = source_label
            if pipeline_run_id:
                event["pipelineRunId"] = pipeline_run_id
            if archive_key:
                event["archiveKey"] = archive_key
            if restored_from_duplicate:
                event["restoredFromDuplicate"] = True
            if source_fingerprint:
                event["sourceFingerprint"] = source_fingerprint
            try:
                result = self.repository.insert(event)
            except DuplicateKeyError:
                # A concurrent replay may have restored the same group first.
                # The unique archiveKey keeps recovery idempotent.
                continue
            event["_id"] = result.inserted_id
            try:
                event["judgement"] = self.ensure_judgement(event, self.association_service)
            except Exception as error:
                logging.getLogger(__name__).exception("新告警自动研判失败: %s", event["_id"])
                content = self._failed_judgement(event, error)
                if hasattr(self.repository, "update_judgement"):
                    self.repository.update_judgement(event["_id"], content)
                event["judgement"] = content
            serialized = self._serialize(event)
            self.events.push(serialized)
            self.broadcaster.publish(serialized)
            created.append(serialized)
        return created

    def restore_missing(
        self, labels, timestamps, machine_components, source_ips=None, destination_ips=None,
        source_type=None, pipeline_run_id=None, model_evidence=None,
        unknown_threshold=None, skipped_packets=0, archive_key=None,
        source_fingerprint=None,
    ):
        """Restore a deleted formal event without reinserting duplicate samples."""
        labels = [int(label) for label in labels]
        attack_labels = sorted({label for label in labels if 0 < label < len(ATTACK_TYPES)})
        if len(attack_labels) != 1 or not archive_key:
            return {"event": None, "created": False}

        attack_label = ATTACK_TYPES[attack_labels[0]]
        data_source = {
            "interface": "WLAN实时", "replay": "PCAP回放",
            "pcap": "PCAP文件", "csv": "CSV文件",
        }.get(source_type)
        existing = self.repository.find_matching_archive(
            archive_key, attack_label, data_source, timestamps,
        )
        if existing:
            return {"event": self._serialize(existing), "created": False}

        created = self.analyze(
            labels, timestamps, machine_components, source_ips, destination_ips,
            source_type, pipeline_run_id=pipeline_run_id,
            model_evidence=model_evidence, unknown_threshold=unknown_threshold,
            skipped_packets=skipped_packets, archive_key=archive_key,
            restored_from_duplicate=True, source_fingerprint=source_fingerprint,
        )
        if created:
            return {"event": created[0], "created": True}

        # If insertion lost a race, return the winning event so the runtime
        # alert still links to the formal archive.
        existing = self.repository.find_matching_archive(
            archive_key, attack_label, data_source, timestamps,
        )
        return {
            "event": self._serialize(existing) if existing else None,
            "created": False,
        }

    def create_modbus_event(self, window):
        association = window.get("association") or {}
        severity_name = (association.get("attackInfo") or {}).get("severity") or window.get("severity")
        severity = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(str(severity_name).lower(), 2)
        timestamp = float(window.get("startTimestamp") or datetime.now(timezone.utc).timestamp())
        end_timestamp = float(window.get("endTimestamp") or timestamp)
        label = window.get("predictedLabel") or "unknown"
        source_type = window.get("sourceType")
        source_label = {"interface": "WLAN实时", "replay": "PCAP回放", "pcap": "PCAP文件", "csv": "CSV文件"}.get(source_type, source_type or "实时推理")
        detail = [{
            "timestamp": timestamp,
            "end_timestamp": end_timestamp,
            "target": window.get("destinationIp") or "Modbus设备",
            "source": window.get("sourceIp") or "未知源",
            "component": association.get("affectedSubsystem") or "Modbus/TCP",
            "source_ip": window.get("sourceIp"),
            "destination_ip": window.get("destinationIp"),
        }]
        judgement = {
            "eventId": None,
            "timestamp": _iso_timestamp(timestamp),
            "eventType": (association.get("attackInfo") or {}).get("name") or label,
            "eventSeverity": severity,
            "dataSource": source_label,
            "sourceIp": window.get("sourceIp"),
            "destinationIp": window.get("destinationIp"),
            "status": "已完成窗口研判",
            "engine": "standalone",
            "generatedAt": window.get("createdAt"),
            "version": 1,
            **association,
        }
        event = {
            "eventType": f"Modbus {(association.get('attackInfo') or {}).get('name') or label}",
            "eventSeverity": severity,
            "attackLabel": label,
            "associationLabel": label,
            "engine": "standalone",
            "inferenceResultId": str(window.get("_id")),
            "windowKey": window.get("windowKey"),
            "windowIndex": window.get("windowIndex"),
            "packetStart": window.get("packetStart"),
            "packetEnd": window.get("packetEnd"),
            "confidence": window.get("confidence"),
            "evidence": window.get("evidence"),
            "features": window.get("features") or {},
            "modelEvidence": {
                "engine": window.get("engine") or "modbus-fast",
                "sampleCount": max(0, int((window.get("packetEnd") or 0) - (window.get("packetStart") or 0))),
                "confidence": _finite_number(window.get("confidence")),
                "detectionTier": window.get("detectionTier"),
                "windowIndex": window.get("windowIndex"),
                "packetStart": window.get("packetStart"),
                "packetEnd": window.get("packetEnd"),
                "evidence": window.get("evidence"),
            },
            "disposition": _default_disposition(),
            "dispositionHistory": [],
            "dataSource": source_label,
            "detail": detail,
            "judgement": judgement,
        }
        result = self.repository.insert(event)
        event["_id"] = result.inserted_id
        judgement["eventId"] = str(result.inserted_id)
        self.repository.update_judgement(result.inserted_id, judgement)
        serialized = self._serialize(event)
        self.events.push(serialized)
        self.broadcaster.publish(serialized)
        return serialized

    def next_event(self):
        return self.events.pop()

    def subscribe(self):
        return self.broadcaster.subscribe()

    def unsubscribe(self, subscriber):
        self.broadcaster.unsubscribe(subscriber)

    def page(self, page, page_size, pipeline_run_id=None):
        query = {"engine": {"$ne": "standalone"}}
        if pipeline_run_id:
            query["pipelineRunId"] = pipeline_run_id
        try:
            rows = self.repository.page(page, page_size, query)
            total = self.repository.count(query)
            by_severity = self.repository.severity_counts(query)
        except TypeError:
            rows = self.repository.page(page, page_size)
            total = self.repository.count()
            by_severity = {}
        items = [self._serialize(event) for event in rows]
        if not by_severity:
            by_severity = {
                str(level): sum(1 for event in items if int(event.get("eventSeverity", -1)) == level)
                for level in range(4)
            }
        return {
            "items": items,
            "summary": {"total": total, "bySeverity": by_severity},
            "page": {"page": page, "pageSize": page_size, "totalTotal": total},
        }

    def total(self):
        query = {"engine": {"$ne": "standalone"}}
        try:
            return self.repository.count(query)
        except TypeError:
            return self.repository.count()

    @staticmethod
    def association_label(event):
        text = " ".join(str(event.get(key) or "") for key in ("associationLabel", "attackLabel", "eventType"))
        aliases = {
            "Modbus模糊测试": "fuzzing",
            "模糊测试攻击": "fuzzing",
            "寄存器写入攻击": "write_single_register",
            "写寄存器攻击": "write_single_register",
            "寄存器读取攻击": "read_holding_register",
            "读保持寄存器攻击": "read_holding_register",
            "线圈读取攻击": "read_coils",
            "读线圈攻击": "read_coils",
            "UID枚举攻击": "uid_scan",
            "从站地址扫描": "uid_scan",
            "功能码读取攻击": "getfunc_scan",
            "功能码探测": "getfunc_scan",
            "功能码爆破": "getfunc_scan",
        }
        for alias, label in aliases.items():
            if alias in text:
                return label
        return event.get("associationLabel") if event.get("associationLabel") in set(aliases.values()) else None

    def judgements(self, limit, association_service):
        events = self.page(1, limit)["items"]
        return {"items": [self.ensure_judgement(event, association_service) for event in events], "limit": limit}

    def ensure_judgement(self, event, association_service):
        existing = event.get("judgement")
        # Legacy records stored the placeholder "待研判". Rebuild and replace
        # that incomplete snapshot the first time it is read.
        if existing and existing.get("status") not in {None, "", "待研判"}:
            if event.get("engine") != "standalone" and existing.get("engine") == "standalone":
                existing = {
                    **existing,
                    "engine": "sanxia-rule",
                    "status": "规则辅助研判" if existing.get("status") in {"已自动研判", "已完成窗口研判"} else existing.get("status"),
                }
                if hasattr(self.repository, "update_judgement") and event.get("_id"):
                    self.repository.update_judgement(ObjectId(str(event["_id"])), existing)
            return existing
        association_service = association_service or self.association_service
        if association_service is None:
            content = self._failed_judgement(event, RuntimeError("standalone 研判服务未初始化"))
        else:
            content = self._build_judgement(event, association_service)
        content.update({
            "engine": "sanxia-rule",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "version": int((existing or {}).get("version", 0)) + 1,
        })
        if hasattr(self.repository, "update_judgement") and event.get("_id"):
            self.repository.update_judgement(ObjectId(str(event["_id"])), content)
        return content

    def regenerate_judgement(self, event_id, association_service):
        event = self._event_or_error(event_id)
        content = self._build_judgement(event, association_service)
        if content.get("status") in {"已自动研判", "规则辅助研判"}:
            content["status"] = "规则辅助研判（已重新生成）"
        content.update({"engine": "sanxia-rule", "generatedAt": datetime.now(timezone.utc).isoformat(), "version": int((event.get("judgement") or {}).get("version", 0)) + 1})
        self.repository.update_judgement(event["_id"], content)
        return content

    def _event_or_error(self, event_id):
        if not ObjectId.is_valid(event_id):
            raise ApiError("INVALID_EVENT_ID", "事件 ID 格式无效", 400)
        event = self.repository.find_by_id(ObjectId(event_id))
        if event is None or event.get("engine") == "standalone":
            raise ApiError("EVENT_NOT_FOUND", "未找到对应的告警事件", 404)
        return event
    def detail(self, event_id, association_service):
        event = self._event_or_error(event_id)
        serialized = self._serialize(event)
        return {
            "event": serialized,
            "judgement": self.ensure_judgement(event, association_service),
        }

    def update_disposition(self, event_id, actor, data, association_service):
        event = self._event_or_error(event_id)
        allowed_statuses = {"pending", "investigating", "contained", "resolved", "false_positive", "closed"}
        current = {**_default_disposition(), **(event.get("disposition") or {})}
        status = data.get("status", current.get("status", "pending"))
        if status not in allowed_statuses:
            raise ApiError("VALIDATION_ERROR", "无效的事件处置状态", 400, {"field": "status"})
        role = int(actor.get("role", 2))
        is_admin = role == 0
        if status in {"false_positive", "closed"} and not is_admin:
            raise ApiError("FORBIDDEN", "只有管理员可以标记误报或关闭事件", 403)
        if current.get("status") in {"false_positive", "closed"} and status != current.get("status") and not is_admin:
            raise ApiError("FORBIDDEN", "只有管理员可以重新打开已结束事件", 403)
        actor_name = str(actor.get("username") or "未知用户")
        assignee = str(data.get("assignee") or current.get("assignee") or actor_name).strip()
        if len(assignee) > 80:
            raise ApiError("VALIDATION_ERROR", "负责人长度不能超过 80 个字符", 400, {"field": "assignee"})
        if not is_admin and assignee not in {actor_name, current.get("assignee", "")}:
            raise ApiError("FORBIDDEN", "普通用户只能将事件认领给自己", 403)
        conclusion = str(data.get("conclusion") or current.get("conclusion") or "").strip()
        confirmed_attack_type = str(data.get("confirmedAttackType") or current.get("confirmedAttackType") or "").strip()
        actual_impact = str(data.get("actualImpact") or current.get("actualImpact") or "").strip()
        note = str(data.get("note") or "").strip()
        if len(confirmed_attack_type) > 160:
            raise ApiError("VALIDATION_ERROR", "人工确认攻击类型长度不能超过 160 个字符", 400, {"field": "confirmedAttackType"})
        if len(actual_impact) > 2000:
            raise ApiError("VALIDATION_ERROR", "实际影响长度不能超过 2000 个字符", 400, {"field": "actualImpact"})
        if len(conclusion) > 2000:
            raise ApiError("VALIDATION_ERROR", "人工结论长度不能超过 2000 个字符", 400, {"field": "conclusion"})
        if len(note) > 2000:
            raise ApiError("VALIDATION_ERROR", "备注长度不能超过 2000 个字符", 400, {"field": "note"})
        now = datetime.now(timezone.utc)
        disposition = {
            "status": status,
            "assignee": assignee,
            "confirmedAttackType": confirmed_attack_type,
            "actualImpact": actual_impact,
            "conclusion": conclusion,
            "updatedAt": now,
            "updatedBy": actor_name,
        }
        history_entry = {
            "fromStatus": current.get("status", "pending"),
            "toStatus": status,
            "assignee": assignee,
            "confirmedAttackType": confirmed_attack_type,
            "actualImpact": actual_impact,
            "conclusion": conclusion,
            "note": note,
            "actorId": str(actor.get("sub") or ""),
            "actorName": actor_name,
            "actorRole": role,
            "createdAt": now,
        }
        severity_fields = None
        requested_severity = data.get("eventSeverity")
        requested_lock = data.get("severityLocked")
        if requested_severity is not None or requested_lock is not None:
            if not is_admin:
                raise ApiError("FORBIDDEN", "只有管理员可以人工调整或锁定风险等级", 403)
            try:
                manual_severity = int(requested_severity if requested_severity is not None else event.get("eventSeverity", 2))
            except (TypeError, ValueError):
                raise ApiError("VALIDATION_ERROR", "风险等级必须是 0 到 3", 400, {"field": "eventSeverity"})
            if manual_severity not in range(4):
                raise ApiError("VALIDATION_ERROR", "风险等级必须是 0 到 3", 400, {"field": "eventSeverity"})
            severity_fields = {
                "eventSeverity": manual_severity,
                "severitySource": "human",
                "severityStatus": "confirmed",
                "severityLocked": bool(requested_lock if requested_lock is not None else True),
                "riskAssessment.finalSeverity": manual_severity,
                "riskAssessment.requiresHumanReview": False,
                "riskAssessment.reason": f"管理员 {actor_name} 已人工确认风险等级。",
                "riskAssessment.assessedAt": now.isoformat(),
                "judgement.eventSeverity": manual_severity,
                "judgement.attackInfo.severity": ("critical", "high", "medium", "low")[manual_severity],
            }
            history_entry["eventSeverity"] = manual_severity
            history_entry["severityLocked"] = severity_fields["severityLocked"]
        try:
            updated = self.repository.update_disposition(event["_id"], disposition, history_entry, severity_fields)
        except TypeError:
            updated = self.repository.update_disposition(event["_id"], disposition, history_entry)
        if updated is None:
            raise ApiError("EVENT_NOT_FOUND", "未找到对应的告警事件", 404)
        return {
            "event": self._serialize(updated),
            "judgement": self.ensure_judgement(updated, association_service),
        }
    @classmethod
    def _build_judgement(cls, event, association_service):
        detail = (event.get("detail") or [{}])[0]
        label = cls.association_label(event)
        severity_index = max(0, min(3, int(event.get("eventSeverity", 3))))
        severity_name = ("critical", "high", "medium", "low")[severity_index]
        try:
            analysis = association_service.associate({
                "predictedLabel": label,
                "features": {
                    "src_ips": detail.get("source_ip") or detail.get("source"),
                    "dst_ips": detail.get("destination_ip") or detail.get("target"),
                    "component": detail.get("component"),
                },
            }) if label else None
            if analysis and analysis.get("ok") is False:
                raise RuntimeError(analysis.get("error") or analysis.get("message") or "standalone 研判失败")
        except Exception as error:
            return cls._failed_judgement(event, error, severity_index)
        if analysis is None:
            analysis = {
                "label": None,
                "cause": "该告警尚未匹配到现有攻击—故障规则，需要结合流量、设备日志和现场状态人工确认。",
                "attackInfo": {"name": event.get("attackLabel") or event.get("eventType") or "未知攻击", "severity": severity_name, "description": "暂无可验证的规则化攻击关联。"},
                "affectedSubsystem": "待人工确认",
                "physicalConsequence": "现有规则无法确定物理后果，请勿将其解释为已确认的设备影响。",
                "historicalMatch": {"matched": False, "reason": "攻击类型未匹配现有规则", "totalMatchingRecords": 0, "uniqueFaultModes": 0, "topFaults": []},
                "recommendations": [{"priority": "人工研判", "domain": "安全运营", "action": "检查源地址相关通信记录、目标设备日志和同期告警，确认攻击链及实际影响。", "source": "fallback"}],
            }
        return {
            "eventId": str(event.get("_id")) if event.get("_id") else None,
            "timestamp": event.get("start_timestamp"),
            "eventType": event.get("eventType"),
            "eventSeverity": severity_index,
            "dataSource": event.get("dataSource") or "事件告警",
            "sourceIp": detail.get("source_ip") or detail.get("source"),
            "destinationIp": detail.get("destination_ip") or detail.get("target"),
            "status": "规则辅助研判" if label else "规则未匹配，需人工确认",
            **analysis,
        }

    @classmethod
    def _failed_judgement(cls, event, error, severity_index=None):
        detail = (event.get("detail") or [{}])[0]
        if severity_index is None:
            severity_index = max(0, min(3, int(event.get("eventSeverity", 3))))
        severity_name = ("critical", "high", "medium", "low")[severity_index]
        return {
            "eventId": str(event.get("_id")) if event.get("_id") else None,
            "timestamp": event.get("start_timestamp"),
            "eventType": event.get("eventType"),
            "eventSeverity": severity_index,
            "dataSource": event.get("dataSource") or "事件告警",
            "sourceIp": detail.get("source_ip") or detail.get("source"),
            "destinationIp": detail.get("destination_ip") or detail.get("target"),
            "status": "研判失败",
            "label": cls.association_label(event),
            "cause": "规则关联执行失败，告警已保留，请检查服务日志后重新生成。",
            "attackInfo": {"name": event.get("attackLabel") or event.get("eventType") or "未知攻击", "severity": severity_name, "description": "研判服务未能生成完整结果。"},
            "affectedSubsystem": "研判失败，待人工确认",
            "physicalConsequence": "研判失败，当前无法确认物理后果。",
            "historicalMatch": {"matched": False, "reason": "研判服务执行失败", "totalMatchingRecords": 0, "uniqueFaultModes": 0, "topFaults": []},
            "recommendations": [{"priority": "人工研判", "domain": "安全运营", "action": "检查研判服务日志并核对该告警的流量、设备日志和现场状态。", "source": "fallback"}],
            "error": str(error),
        }
    @staticmethod
    def _serialize(event):
        current = dict(event)
        current["_id"] = str(current["_id"])
        current["detail"] = [{**item, "timestamp": _iso_timestamp(item["timestamp"])} for item in current.get("detail", [])]
        if current["detail"]:
            current["start_timestamp"] = current["detail"][0]["timestamp"]
            current["end_timestamp"] = _iso_timestamp(current["detail"][-1].get("end_timestamp") or current["detail"][-1]["timestamp"])
        current["disposition"] = {**_default_disposition(), **(current.get("disposition") or {})}
        current["dispositionHistory"] = current.get("dispositionHistory") or []
        return current


def _finite_number(value):
    try:
        number = float(value)
        return number if number == number and number not in {float("inf"), float("-inf")} else None
    except (TypeError, ValueError):
        return None


def _numeric_summary(values):
    valid = [_finite_number(value) for value in values]
    valid = [value for value in valid if value is not None]
    if not valid:
        return None
    return {
        "count": len(valid),
        "min": min(valid),
        "max": max(valid),
        "average": sum(valid) / len(valid),
    }


def _sanxia_evidence(matches, unknown_threshold, skipped_packets):
    known = _numeric_summary([(evidence or {}).get("knownConfidence") for *_, evidence in matches])
    unknown_values = [_finite_number((evidence or {}).get("unknownScore")) for *_, evidence in matches]
    unknown_values = [value for value in unknown_values if value is not None]
    threshold = _finite_number(unknown_threshold)
    unknown = _numeric_summary(unknown_values)
    if unknown is not None:
        unknown["threshold"] = threshold
        unknown["aboveThresholdCount"] = sum(1 for value in unknown_values if threshold is not None and value >= threshold)
    return {
        "engine": "sanxia-cascade",
        "sampleCount": len(matches),
        "skippedPackets": int(skipped_packets or 0),
        "knownConfidence": known,
        "unknownScore": unknown,
    }


def _default_disposition():
    return {
        "status": "pending",
        "assignee": "",
        "confirmedAttackType": "",
        "actualImpact": "",
        "conclusion": "",
        "updatedAt": None,
        "updatedBy": None,
    }

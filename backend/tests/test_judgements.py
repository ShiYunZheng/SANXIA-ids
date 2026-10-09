from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from bson import ObjectId

from app.errors import ApiError
from app.constants import ATTACK_SEVERITY_BY_LABEL, ATTACK_TYPES, SEVERITY_NAMES, SEVERITY_POLICY_VERSION
from app.modbus.engine import ModbusInferenceEngine
from app.modbus.fault_association import RecommendationEngine
from app.repositories.mongo import EventRepository as MongoEventRepository
from app.services.analytics import EventService


class EventRepository:
    def __init__(self, events):
        self.events = events
        self.last_page_size = None

    def page(self, page, page_size):
        self.last_page_size = page_size
        return self.events[:page_size]

    def find_by_id(self, object_id):
        return next((item for item in self.events if item["_id"] == object_id), None)

    def insert(self, event):
        stored = dict(event)
        stored["_id"] = ObjectId()
        self.events.append(stored)
        return SimpleNamespace(inserted_id=stored["_id"])

    def update_judgement(self, object_id, judgement):
        selected = self.find_by_id(object_id)
        selected["judgement"] = judgement

    def update_disposition(self, object_id, disposition, history_entry, severity_fields=None):
        selected = self.find_by_id(object_id)
        if selected is None:
            return None
        selected["disposition"] = disposition
        selected.setdefault("dispositionHistory", []).append(history_entry)
        for key, value in (severity_fields or {}).items():
            if "." not in key:
                selected[key] = value
                continue
            parent, child = key.split(".", 1)
            selected.setdefault(parent, {})[child] = value
        return selected

    def count(self):
        return len(self.events)


class EmptyFaultIndex:
    def search_by_keywords(self, _keywords):
        return []


def association_service():
    service = ModbusInferenceEngine.__new__(ModbusInferenceEngine)
    service.association = RecommendationEngine(EmptyFaultIndex())
    return service


def event(index, attack_label="Modbus模糊测试", severity=1):
    timestamp = datetime(2026, 4, 14, 9, 16, index, tzinfo=timezone.utc).timestamp()
    return {
        "_id": ObjectId(),
        "eventType": f"PLC控制器 {attack_label}",
        "attackLabel": attack_label,
        "eventSeverity": severity,
        "dataSource": "PCAP回放",
        "detail": [{
            "timestamp": timestamp,
            "source": "192.168.101.41",
            "target": "192.168.101.11",
            "source_ip": "192.168.101.41",
            "destination_ip": "192.168.101.11",
            "component": "PLC控制器",
        }],
    }


def test_event_page_total_is_not_limited_by_page_size_and_excludes_standalone():
    class SummaryRepository:
        def __init__(self):
            self.events = [
                {**event(index % 59, severity=index % 4), "engine": "sanxia"}
                for index in range(35)
            ] + [
                {**event(index, severity=1), "engine": "standalone"}
                for index in range(5)
            ]

        def _filtered(self, query):
            if query and query.get("engine") == {"$ne": "standalone"}:
                return [item for item in self.events if item.get("engine") != "standalone"]
            return list(self.events)

        def page(self, page, page_size, query=None):
            rows = self._filtered(query)
            return rows[(page - 1) * page_size:page * page_size]

        def count(self, query=None):
            return len(self._filtered(query))

        def severity_counts(self, query=None):
            rows = self._filtered(query)
            return {str(level): sum(1 for item in rows if item["eventSeverity"] == level) for level in range(4)}

    result = EventService(SummaryRepository()).page(1, 30)

    assert len(result["items"]) == 30
    assert result["page"]["totalTotal"] == 35
    assert result["summary"]["total"] == 35
    assert sum(result["summary"]["bySeverity"].values()) == 35
    assert all(item.get("engine") != "standalone" for item in result["items"])


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Modbus模糊测试", "fuzzing"),
        ("寄存器写入攻击", "write_single_register"),
        ("寄存器读取攻击", "read_holding_register"),
        ("线圈读取攻击", "read_coils"),
        ("UID枚举攻击", "uid_scan"),
        ("功能码探测", "getfunc_scan"),
    ],
)
def test_association_label_compatibility(name, expected):
    assert EventService.association_label({"eventType": name}) == expected


@pytest.mark.parametrize(("attack_label", "expected"), ATTACK_SEVERITY_BY_LABEL.items())
def test_new_sanxia_events_use_rule_severity(attack_label, expected):
    repository = EventRepository([])
    service = EventService(repository)

    created = service.analyze(
        [ATTACK_TYPES.index(attack_label)], [123.0], ["test"],
        ["192.168.101.41"], ["192.168.101.11"], "replay",
    )

    assert created[0]["eventSeverity"] == expected
    assert repository.events[0]["eventSeverity"] == expected


def test_severity_normalization_excludes_standalone_and_updates_existing_judgement():
    class Collection:
        def __init__(self):
            self.calls = []

        def update_many(self, query, update):
            self.calls.append((query, update))
            return SimpleNamespace(modified_count=1)

    collection = Collection()
    modified = MongoEventRepository(collection).normalize_severities(
        ATTACK_SEVERITY_BY_LABEL, SEVERITY_NAMES, SEVERITY_POLICY_VERSION,
    )

    assert modified == len(ATTACK_SEVERITY_BY_LABEL)
    assert len(collection.calls) == len(ATTACK_SEVERITY_BY_LABEL) * 2
    assert all(query["engine"] == {"$ne": "standalone"} for query, _ in collection.calls)
    first_event_update = collection.calls[0][1]["$set"]
    first_judgement_update = collection.calls[1][1]["$set"]
    assert first_event_update["severityPolicyVersion"] == SEVERITY_POLICY_VERSION
    assert first_judgement_update["judgement.attackInfo.severity"] in SEVERITY_NAMES


def test_judgements_are_limited_and_use_real_fuzzing_rule():
    events = [event(index) for index in range(5, -1, -1)]
    repository = EventRepository(events)
    result = EventService(repository).judgements(5, association_service())

    assert repository.last_page_size == 5
    assert len(result["items"]) == 5
    judgement = result["items"][0]
    assert judgement["attackInfo"]["name"] == "模糊测试攻击 (Fuzzing)"
    assert judgement["attackInfo"]["severity"] == "high"
    assert "PLC控制器" in judgement["affectedSubsystem"]
    assert judgement["sourceIp"] == "192.168.101.41"
    assert judgement["destinationIp"] == "192.168.101.11"
    assert judgement["recommendations"][0]["priority"] == "最高"
    assert judgement["recommendations"][0]["action"] == "建议立即将受影响控制系统切换至离线/手动模式，阻断所有非授权Modbus通信"


def test_unmapped_attack_requires_manual_confirmation():
    service = EventService(EventRepository([event(1, "ARP投毒", 1)]))
    judgement = service.judgements(5, association_service())["items"][0]

    assert judgement["label"] is None
    assert judgement["affectedSubsystem"] == "待人工确认"
    assert "人工确认" in judgement["cause"]
    assert judgement["recommendations"][0]["priority"] == "人工研判"


def test_event_detail_returns_matching_event_and_judgement():
    selected = event(2)
    service = EventService(EventRepository([event(1), selected]))

    result = service.detail(str(selected["_id"]), association_service())

    assert result["event"]["_id"] == str(selected["_id"])
    assert result["judgement"]["eventId"] == str(selected["_id"])
    assert result["judgement"]["sourceIp"] == "192.168.101.41"
    assert result["judgement"]["attackInfo"]["name"] == "模糊测试攻击 (Fuzzing)"


def test_event_detail_rejects_invalid_id():
    service = EventService(EventRepository([]))

    with pytest.raises(ApiError) as raised:
        service.detail("not-an-object-id", association_service())

    assert raised.value.code == "INVALID_EVENT_ID"
    assert raised.value.status == 400


def test_event_detail_returns_not_found_for_unknown_id():
    service = EventService(EventRepository([]))

    with pytest.raises(ApiError) as raised:
        service.detail(str(ObjectId()), association_service())

    assert raised.value.code == "EVENT_NOT_FOUND"
    assert raised.value.status == 404


def test_event_detail_hides_existing_standalone_event():
    selected = {**event(2), "engine": "standalone"}
    service = EventService(EventRepository([selected]))

    with pytest.raises(ApiError) as raised:
        service.detail(str(selected["_id"]), association_service())

    assert raised.value.code == "EVENT_NOT_FOUND"
    assert raised.value.status == 404

def test_legacy_pending_judgement_is_rebuilt():
    selected = event(3, "ARP投毒", 1)
    selected["judgement"] = {
        "status": "待研判",
        "cause": "旧占位内容",
        "version": 1,
    }
    result = EventService(EventRepository([selected])).detail(str(selected["_id"]), association_service())

    assert result["judgement"]["status"] == "规则未匹配，需人工确认"
    assert result["judgement"]["cause"] != "旧占位内容"
    assert selected["judgement"] == result["judgement"]
    assert result["judgement"]["version"] == 2
class FailingAssociationService:
    def associate(self, _payload):
        raise RuntimeError("test association failure")


def test_failed_judgement_is_saved_with_explicit_status():
    selected = event(4)
    repository = EventRepository([selected])

    result = EventService(repository).detail(str(selected["_id"]), FailingAssociationService())

    assert result["judgement"]["status"] == "研判失败"
    assert "test association failure" in result["judgement"]["error"]
    assert selected["judgement"] == result["judgement"]


def test_new_alert_is_automatically_judged_and_saved():
    repository = EventRepository([])
    service = EventService(repository)
    service.association_service = association_service()

    service.analyze(
        [1],
        [datetime(2026, 4, 14, 9, 16, tzinfo=timezone.utc).timestamp()],
        ["PLC控制器"],
        ["192.168.101.41"],
        ["192.168.101.11"],
        "pcap",
    )

    assert len(repository.events) == 1
    assert repository.events[0]["engine"] == "sanxia"
    assert repository.events[0]["judgement"]["status"] == "规则辅助研判"
    assert repository.events[0]["judgement"]["engine"] == "sanxia-rule"


def test_sanxia_event_persists_unknown_score_and_threshold_evidence():
    repository = EventRepository([])
    service = EventService(repository)
    service.association_service = association_service()

    service.analyze(
        [18, 18],
        [1.0, 2.0],
        ["PLC控制器", "PLC控制器"],
        ["10.0.0.1", "10.0.0.1"],
        ["10.0.0.2", "10.0.0.2"],
        "replay",
        pipeline_run_id="run-evidence",
        model_evidence=[
            {"knownConfidence": 0.51, "unknownScore": 0.72},
            {"knownConfidence": 0.48, "unknownScore": 0.91},
        ],
        unknown_threshold=0.60,
        skipped_packets=3,
    )

    evidence = repository.events[0]["modelEvidence"]
    assert evidence["sampleCount"] == 2
    assert evidence["unknownScore"]["average"] == pytest.approx(0.815)
    assert evidence["unknownScore"]["max"] == pytest.approx(0.91)
    assert evidence["unknownScore"]["threshold"] == pytest.approx(0.60)
    assert evidence["unknownScore"]["aboveThresholdCount"] == 2
    assert evidence["skippedPackets"] == 3
    assert repository.events[0]["detail"][0]["unknownScore"] == pytest.approx(0.72)


def test_disposition_acl_and_audit_history():
    selected = event(8, "ARP投毒", 1)
    repository = EventRepository([selected])
    service = EventService(repository)
    regular = {"sub": str(ObjectId()), "username": "operator", "role": 2}
    admin = {"sub": str(ObjectId()), "username": "admin", "role": 0}

    with pytest.raises(ApiError) as forbidden:
        service.update_disposition(str(selected["_id"]), regular, {"status": "closed"}, association_service())
    assert forbidden.value.status == 403

    investigating = service.update_disposition(
        str(selected["_id"]),
        regular,
        {
            "status": "investigating",
            "assignee": "operator",
            "confirmedAttackType": "授权扫描待复核",
            "actualImpact": "暂未发现设备影响",
            "conclusion": "正在核验",
            "note": "已检查通信记录",
        },
        association_service(),
    )
    assert investigating["event"]["disposition"]["status"] == "investigating"
    assert investigating["event"]["disposition"]["confirmedAttackType"] == "授权扫描待复核"
    assert investigating["event"]["disposition"]["actualImpact"] == "暂未发现设备影响"
    assert investigating["event"]["dispositionHistory"][0]["actorName"] == "operator"
    assert investigating["event"]["dispositionHistory"][0]["confirmedAttackType"] == "授权扫描待复核"

    closed = service.update_disposition(
        str(selected["_id"]),
        admin,
        {"status": "closed", "assignee": "operator", "conclusion": "处置完成", "note": "管理员关闭"},
        association_service(),
    )
    assert closed["event"]["disposition"]["status"] == "closed"
    assert len(closed["event"]["dispositionHistory"]) == 2
    assert closed["event"]["dispositionHistory"][-1]["fromStatus"] == "investigating"


def test_admin_can_confirm_and_lock_severity_while_operator_cannot():
    selected = event(9, "未知攻击", 1)
    selected["riskAssessment"] = {"baseSeverity": 1, "finalSeverity": 1, "requiresHumanReview": True}
    repository = EventRepository([selected])
    service = EventService(repository)
    regular = {"sub": str(ObjectId()), "username": "operator", "role": 2}
    admin = {"sub": str(ObjectId()), "username": "admin", "role": 0}

    with pytest.raises(ApiError) as forbidden:
        service.update_disposition(str(selected["_id"]), regular, {"eventSeverity": 2}, association_service())
    assert forbidden.value.status == 403

    result = service.update_disposition(
        str(selected["_id"]), admin,
        {"status": "investigating", "eventSeverity": 2, "severityLocked": True},
        association_service(),
    )

    assert result["event"]["eventSeverity"] == 2
    assert result["event"]["severitySource"] == "human"
    assert result["event"]["severityLocked"] is True
    assert result["event"]["riskAssessment"]["requiresHumanReview"] is False

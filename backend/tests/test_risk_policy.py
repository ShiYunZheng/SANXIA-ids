from types import SimpleNamespace

from bson import ObjectId

from app.repositories.mongo import EventRepository
from app.risk import RiskPolicy, SEVERITY_POLICY_VERSION


def test_unmapped_attack_falls_back_to_medium_without_density_escalation():
    result = RiskPolicy().assess(
        "未覆盖的新攻击", [1.0], ["test"], ["10.0.0.1"], ["10.0.0.2"],
        [{"knownConfidence": 0.99}],
    )

    assert result["eventSeverity"] == 2
    assert result["severitySource"] == "rule-fallback"
    assert result["severityStatus"] == "pending_confirmation"
    assert "UNMAPPED_ATTACK_FALLBACK_MEDIUM" in result["riskAssessment"]["matchedRules"]


def test_unknown_score_above_threshold_stays_high_without_impact_evidence():
    result = RiskPolicy().assess(
        "未知攻击", [1.0, 2.0, 3.0], ["PLC控制器"] * 3,
        ["10.0.0.1"] * 3, ["10.0.0.2"] * 3,
        [{"unknownScore": score} for score in (0.629, 0.65, 0.686)],
        0.6073,
    )

    assert result["eventSeverity"] == 1
    assert result["severityStatus"] == "pending_confirmation"
    assert "CRITICAL_GATE_BLOCKED" in result["riskAssessment"]["matchedRules"]


def test_single_low_confidence_mac_overflow_is_medium():
    result = RiskPolicy().assess(
        "MAC溢出", [1.0], ["以太网交换机"], ["10.0.0.1"], ["10.0.0.2"],
        [{"knownConfidence": 0.518}],
    )

    assert result["eventSeverity"] == 2
    assert "MAC_SINGLE_SAMPLE_CAP_MEDIUM" in result["riskAssessment"]["matchedRules"]


def test_register_write_requires_sensitive_critical_evidence_for_critical():
    policy = RiskPolicy()
    ordinary = policy.assess(
        "寄存器写入攻击", [1.0], ["PLC控制器"], ["10.0.0.1"], ["10.0.0.2"],
        [{"knownConfidence": 0.95}],
    )
    sensitive = policy.assess(
        "寄存器写入攻击", [1.0], ["PLC控制器"], ["10.0.0.1"], ["10.0.0.2"],
        [{"knownConfidence": 0.95, "sensitiveWrite": True}],
    )

    assert ordinary["eventSeverity"] == 1
    assert sensitive["eventSeverity"] == 0


def test_historical_event_without_model_evidence_is_medium_and_insufficient():
    result = RiskPolicy().assess_event({
        "attackLabel": "ARP投毒",
        "detail": [{"timestamp": 1.0, "component": "test"}],
    })

    assert result["eventSeverity"] == 2
    assert result["severitySource"] == "historical"
    assert result["severityStatus"] == "evidence_insufficient"


def test_history_migration_is_idempotent_and_preserves_human_lock():
    unlocked_id = ObjectId()
    locked_id = ObjectId()

    class Collection:
        def __init__(self):
            self.rows = [
                {"_id": unlocked_id, "engine": "sanxia", "attackLabel": "未知攻击", "detail": [{"timestamp": 1.0}], "modelEvidence": {"sampleCount": 1, "unknownScore": {"max": 0.65, "threshold": 0.6073}}},
                {"_id": locked_id, "engine": "sanxia", "attackLabel": "未知攻击", "eventSeverity": 0, "severitySource": "human", "severityLocked": True},
            ]

        def find(self, _query):
            return [row for row in self.rows if row.get("severityPolicyVersion") != SEVERITY_POLICY_VERSION and not row.get("severityLocked") and row.get("severitySource") != "human"]

        def update_one(self, query, update):
            row = next(item for item in self.rows if item["_id"] == query["_id"])
            row.update(update["$set"])
            return SimpleNamespace(modified_count=1)

    collection = Collection()
    repository = EventRepository(collection)

    assert repository.normalize_risk_assessments(RiskPolicy()) == 1
    assert repository.normalize_risk_assessments(RiskPolicy()) == 0
    assert collection.rows[0]["eventSeverity"] == 1
    assert collection.rows[1]["eventSeverity"] == 0

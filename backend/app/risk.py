from datetime import datetime, timezone


SEVERITY_NAMES = ("critical", "high", "medium", "low")
SEVERITY_POLICY_VERSION = "attack-rule-v2"

BASE_SEVERITY_BY_LABEL = {
    "寄存器写入攻击": 1,
    "Modbus模糊测试": 1,
    "未知攻击": 1,
    "寄存器读取攻击": 2,
    "线圈读取攻击": 2,
    "MAC溢出": 2,
    "功能码读取攻击": 3,
    "UID枚举攻击": 3,
}

RULE_CODES = {
    "寄存器写入攻击": "REGISTER_WRITE_BASE_HIGH",
    "Modbus模糊测试": "MODBUS_FUZZING_BASE_HIGH",
    "未知攻击": "UNKNOWN_ATTACK_BASE_HIGH",
    "寄存器读取攻击": "REGISTER_READ_BASE_MEDIUM",
    "线圈读取攻击": "COIL_READ_BASE_MEDIUM",
    "MAC溢出": "MAC_OVERFLOW_BASE_MEDIUM",
    "功能码读取攻击": "FUNCTION_SCAN_BASE_LOW",
    "UID枚举攻击": "UID_SCAN_BASE_LOW",
}

CRITICAL_ASSET_MARKERS = ("PLC", "控制器", "阀门", "变频器", "执行机构")
IMPACT_KEYS = (
    "physicalImpact", "confirmedPhysicalImpact", "serviceUnavailable",
    "communicationInterrupted", "controlStateChanged", "deviceOffline",
)
SENSITIVE_WRITE_KEYS = ("sensitiveRegister", "sensitiveWrite", "controlWrite", "dangerousValue")
DEVICE_ANOMALY_KEYS = ("deviceAnomaly", "serviceUnavailable", "communicationInterrupted", "deviceOffline")


def _finite_number(value):
    try:
        number = float(value)
        return number if number == number and number not in {float("inf"), float("-inf")} else None
    except (TypeError, ValueError):
        return None


def _truthy_evidence(items, keys):
    return any(any(bool((item or {}).get(key)) for key in keys) for item in items)


def _severity_label(value):
    return ("严重", "高危", "中危", "低危")[max(0, min(3, int(value)))]


class RiskPolicy:
    """Deterministic, evidence-gated severity policy for SANXIA events."""

    def __init__(self, duration_seconds=30.0, sample_threshold=10, target_threshold=3, confidence_threshold=0.60):
        self.duration_seconds = max(float(duration_seconds), 0.0)
        self.sample_threshold = max(int(sample_threshold), 1)
        self.target_threshold = max(int(target_threshold), 1)
        self.confidence_threshold = max(0.0, min(1.0, float(confidence_threshold)))

    def assess(
        self, attack_label, timestamps=None, components=None, source_ips=None,
        destination_ips=None, model_evidence=None, unknown_threshold=None,
        historical_without_evidence=False,
    ):
        label = str(attack_label or "").strip()
        timestamps = [_finite_number(value) for value in (timestamps or [])]
        timestamps = [value for value in timestamps if value is not None]
        components = [str(value) for value in (components or []) if value]
        source_ips = [str(value) for value in (source_ips or []) if value]
        destination_ips = [str(value) for value in (destination_ips or []) if value]
        evidence_items = [item or {} for item in (model_evidence or [])]
        sample_count = max(len(evidence_items), len(timestamps), 1)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        target_count = len(set(destination_ips))
        source_count = len(set(source_ips))
        mapped = label in BASE_SEVERITY_BY_LABEL

        if historical_without_evidence:
            return self._result(
                label, 2, 2, "historical", "evidence_insufficient",
                ["HISTORICAL_EVIDENCE_INSUFFICIENT"], [],
                ["历史事件未保存模型证据", "无法验证资产影响和攻击持续性"],
                "历史事件缺少模型证据，按统一规则暂定为中危。",
                sample_count, duration, source_count, target_count,
            )

        base = BASE_SEVERITY_BY_LABEL.get(label, 2)
        matched_rules = [RULE_CODES.get(label, "UNMAPPED_ATTACK_FALLBACK_MEDIUM")]
        evidence = []
        missing = []
        critical_asset = any(any(marker.casefold() in component.casefold() for marker in CRITICAL_ASSET_MARKERS) for component in components)
        sensitive_write = _truthy_evidence(evidence_items, SENSITIVE_WRITE_KEYS)
        confirmed_impact = _truthy_evidence(evidence_items, IMPACT_KEYS)
        device_anomaly = _truthy_evidence(evidence_items, DEVICE_ANOMALY_KEYS)
        sustained = duration >= self.duration_seconds
        high_volume = sample_count >= self.sample_threshold
        multi_target = target_count >= self.target_threshold

        if critical_asset:
            matched_rules.append("CRITICAL_ASSET")
            evidence.append("目标包含关键控制资产")
        if sustained:
            matched_rules.append("SUSTAINED_ATTACK")
            evidence.append(f"攻击持续 {duration:.1f} 秒，达到持续攻击阈值")
        if high_volume:
            matched_rules.append("HIGH_SAMPLE_COUNT")
            evidence.append(f"有效攻击样本 {sample_count} 个，达到数量阈值")
        if multi_target:
            matched_rules.append("MULTI_TARGET")
            evidence.append(f"攻击覆盖 {target_count} 个目标")
        if sensitive_write:
            matched_rules.append("SENSITIVE_CONTROL_WRITE")
            evidence.append("检测证据表明存在敏感控制写入")
        if confirmed_impact:
            matched_rules.append("CONFIRMED_OPERATIONAL_IMPACT")
            evidence.append("检测证据表明设备或控制过程已经受到影响")

        final = base
        can_upgrade = critical_asset or sustained or high_volume or multi_target or sensitive_write or confirmed_impact
        if can_upgrade and not (not mapped and not evidence):
            final = max(0, base - 1)

        known_values = [_finite_number(item.get("knownConfidence")) for item in evidence_items]
        known_values = [value for value in known_values if value is not None]
        known_average = sum(known_values) / len(known_values) if known_values else None
        threshold = _finite_number(unknown_threshold)
        unknown_values = [_finite_number(item.get("unknownScore")) for item in evidence_items]
        unknown_values = [value for value in unknown_values if value is not None]
        unknown_max = max(unknown_values) if unknown_values else None
        weak_single = sample_count == 1 and known_average is not None and known_average < self.confidence_threshold
        weak_unknown = threshold is not None and unknown_max is not None and unknown_max <= threshold + 0.05
        corroborated = bool(evidence)
        if weak_single and not corroborated and label not in {"未知攻击", "MAC溢出"}:
            final = min(3, base + 1)
            matched_rules.append("WEAK_SINGLE_SAMPLE_DOWNGRADE")
            evidence.append(f"单样本平均置信度 {known_average:.3f}，低于 {self.confidence_threshold:.2f}")
        if label == "未知攻击" and weak_unknown:
            matched_rules.append("UNKNOWN_SCORE_NEAR_THRESHOLD")
            evidence.append("未知分数仅略高于判定阈值")

        critical_gate = confirmed_impact or (sensitive_write and critical_asset) or (sustained and high_volume and device_anomaly)
        if final == 0 and not critical_gate:
            final = 1
            matched_rules.append("CRITICAL_GATE_BLOCKED")
            missing.append("缺少关键控制写入、设备中断或物理影响证据")

        if label == "MAC溢出" and sample_count == 1:
            final = max(final, 2)
            matched_rules.append("MAC_SINGLE_SAMPLE_CAP_MEDIUM")
        if label == "未知攻击" and not critical_gate:
            final = max(final, 1)
            missing.append("未知分数只能证明异常特征，尚未确认严重物理影响")
        if not mapped:
            missing.append("攻击类型未被规则库覆盖")
        if not components:
            missing.append("未绑定可验证的资产类型")
        if not confirmed_impact:
            missing.append("未确认设备中断或物理影响")

        source = "rule" if mapped else "rule-fallback"
        status = "pending_confirmation" if label in {"未知攻击", "MAC溢出"} or not mapped else "assessed"
        if not mapped:
            reason = "无法映射攻击类型，按统一回退规则暂定为中危。"
        elif label == "未知攻击":
            reason = "存在未知攻击特征，但不足以证明已经造成严重物理影响。"
        elif label == "MAC溢出" and sample_count == 1:
            reason = "仅检测到单个 MAC 溢出样本，按证据规则暂定为中危。"
        else:
            reason = f"依据攻击行为和可验证证据，风险等级评定为{_severity_label(final)}。"

        return self._result(
            label, base, final, source, status, matched_rules, evidence, missing,
            reason, sample_count, duration, source_count, target_count,
        )

    def assess_event(self, event):
        details = event.get("detail") or []
        model = event.get("modelEvidence") or {}
        per_sample = [
            {
                "knownConfidence": item.get("knownConfidence"),
                "unknownScore": item.get("unknownScore"),
            }
            for item in details
        ]
        if not per_sample and model:
            per_sample = [{} for _ in range(max(1, int(model.get("sampleCount") or 1)))]
            known = (model.get("knownConfidence") or {}).get("average")
            unknown = (model.get("unknownScore") or {}).get("max")
            for item in per_sample:
                item.update({"knownConfidence": known, "unknownScore": unknown})
        historical_without_evidence = not model and not event.get("severityPolicyVersion")
        result = self.assess(
            event.get("attackLabel") or event.get("eventType"),
            [item.get("timestamp") for item in details],
            [item.get("component") for item in details],
            [item.get("source_ip") or item.get("source") for item in details],
            [item.get("destination_ip") or item.get("target") for item in details],
            per_sample,
            (model.get("unknownScore") or {}).get("threshold"),
            historical_without_evidence=historical_without_evidence,
        )
        return result

    @staticmethod
    def _result(label, base, final, source, status, matched, evidence, missing, reason, sample_count, duration, source_count, target_count):
        return {
            "eventSeverity": int(final),
            "severitySource": source,
            "severityPolicyVersion": SEVERITY_POLICY_VERSION,
            "severityStatus": status,
            "riskAssessment": {
                "attackLabel": label,
                "baseSeverity": int(base),
                "finalSeverity": int(final),
                "matchedRules": list(dict.fromkeys(matched)),
                "evidence": list(dict.fromkeys(evidence)),
                "missingEvidence": list(dict.fromkeys(missing)),
                "reason": reason,
                "sampleCount": int(sample_count),
                "durationSeconds": round(float(duration), 3),
                "sourceCount": int(source_count),
                "targetCount": int(target_count),
                "requiresHumanReview": status != "assessed",
                "assessedAt": datetime.now(timezone.utc).isoformat(),
            },
        }


DEFAULT_RISK_POLICY = RiskPolicy()

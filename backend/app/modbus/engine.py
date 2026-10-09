import hashlib
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

from .data_preprocessing import WINDOW_SIZE, WINDOW_STRIDE, extract_window_features, parse_pcap, parse_sample_records
from .fault_association import ATTACK_FAULT_RULES, FaultIndex, RecommendationEngine
from .prototype_classifier import FEATURE_COLS, load_prototypes, rule_based_classify, rule_explanation


class ModbusInferenceEngine:
    """In-process Modbus parser and classifier extracted from standalone."""

    def __init__(self, resource_dir, mode="fast"):
        self.resource_dir = Path(resource_dir)
        self.dataset_dir = self.resource_dir / "dataset"
        self.prototype_path = self.resource_dir / "model_output" / "prototypes.pkl"
        self.mode = mode if mode in {"fast", "hybrid"} else "fast"
        self.classifier = None
        self.prototype_error = None
        self.fault_index = None
        self.fault_index_error = None
        self._stream_lock = threading.Lock()
        self.reset_stream()
        try:
            self.classifier = load_prototypes(str(self.prototype_path))
        except Exception as error:
            self.prototype_error = str(error)
        try:
            self.fault_index = FaultIndex(cache_path=str(self.dataset_dir / "fault_index_cache.json"))
            self.association = RecommendationEngine(self.fault_index)
        except Exception as error:
            self.fault_index_error = str(error)
            self.association = None

    def status(self):
        return {
            "ready": True,
            "mode": self.mode,
            "prototypeAvailable": self.classifier is not None,
            "faultIndexAvailable": self.fault_index is not None,
            "degraded": self.classifier is None,
            "degradedReason": "原型资源不可用，已降级为快速规则模式" if self.classifier is None else None,
        }

    def detect_pcap(self, path, mode="fast"):
        records = parse_pcap(str(path))
        if not records:
            return self._empty_result("未检测到 Modbus/TCP 流量")
        windows = []
        records.sort(key=lambda item: item.get("timestamp", 0))
        for start in range(0, max(1, len(records) - WINDOW_SIZE + 1), WINDOW_STRIDE):
            window = records[start:start + WINDOW_SIZE]
            if len(window) < 5:
                continue
            features = extract_window_features(window)
            features.update({"window_index": len(windows), "packet_start": start, "packet_end": start + len(window)})
            windows.append(self._classify(features, mode))
        return self._build_result(windows, packet_count=len(records), source="pcap", mode=mode)

    def detect_features_csv(self, path, mode="fast"):
        frame = pd.read_csv(path)
        missing = [column for column in FEATURE_COLS if column not in frame.columns]
        if missing:
            raise ValueError(f"缺少 Modbus 特征列: {', '.join(missing[:6])}")
        windows = []
        for index, row in frame.iterrows():
            features = {}
            for key, value in row.to_dict().items():
                if pd.isna(value):
                    features[key] = None
                elif hasattr(value, "item"):
                    features[key] = value.item()
                else:
                    features[key] = value
            features.update({"window_index": int(index), "packet_start": None, "packet_end": None})
            windows.append(self._classify(features, mode))
        return self._build_result(windows, packet_count=None, source="features-csv", mode=mode)

    def reset_stream(self, source_key=None):
        with getattr(self, "_stream_lock", threading.Lock()):
            self._stream_source_key = source_key
            self._stream_records = []
            self._stream_base = 0
            self._stream_next_start = 0

    def detect_records(self, samples, source_fingerprint, source_type, mode="fast"):
        """Generate Modbus windows across SamplingService batch boundaries."""
        source_key = f"{source_type}:{source_fingerprint or 'unknown'}"
        parsed = parse_sample_records(samples)
        windows = []
        with self._stream_lock:
            if self._stream_source_key != source_key:
                self._stream_source_key = source_key
                self._stream_records = []
                self._stream_base = 0
                self._stream_next_start = 0
            self._stream_records.extend(parsed)
            while self._stream_next_start + WINDOW_SIZE <= self._stream_base + len(self._stream_records):
                relative = self._stream_next_start - self._stream_base
                window = self._stream_records[relative:relative + WINDOW_SIZE]
                features = extract_window_features(window)
                start = self._stream_next_start
                end = start + WINDOW_SIZE
                features.update({"window_index": start // WINDOW_STRIDE, "packet_start": start, "packet_end": end})
                classified = self._classify(features, mode)
                first_id = window[0].get("source_sample_id") or f"offset:{start}"
                last_id = window[-1].get("source_sample_id") or f"offset:{end - 1}"
                classified.update({
                    "windowKey": hashlib.sha256(f"{source_key}|{first_id}|{last_id}".encode()).hexdigest(),
                    "sourceFingerprint": source_fingerprint,
                    "sourceType": source_type,
                    "startTimestamp": window[0].get("timestamp"),
                    "endTimestamp": window[-1].get("timestamp"),
                })
                windows.append(classified)
                self._stream_next_start += WINDOW_STRIDE
            trim = self._stream_next_start - self._stream_base
            if trim > 0:
                self._stream_records = self._stream_records[trim:]
                self._stream_base += trim
        return self._build_result(windows, packet_count=len(parsed), source=source_type, mode=mode)

    def associate(self, result):
        label = result.get("predictedLabel") or result.get("predicted_label") or "unknown"
        features = result.get("features") or {}
        if self.association:
            analysis = self.association.analyze(label, features)
            attack_info = analysis.get("attack_info", {})
            consequence = analysis.get("physical_consequence", {})
            historical = analysis.get("historical_fault_match", {})
            recommendations = analysis.get("recommendations", [])
        else:
            rule = ATTACK_FAULT_RULES.get(label)
            if rule:
                attack_info = {"chinese_name": rule.get("chinese_name", label), "severity": rule.get("severity", "unknown"), "description": rule.get("description", "")}
                consequence = {"affected_subsystem": rule.get("affected_subsystem", ""), "description": rule.get("physical_consequence", "")}
                recommendations = [{"priority": "参考", "domain": "规则", "action": action, "source": "rule-based"} for action in rule.get("immediate_network_actions", []) + rule.get("immediate_physical_actions", [])]
            else:
                attack_info = {"chinese_name": f"未知攻击类型 ({label})", "severity": "unknown", "description": "模型输出的攻击类型未匹配已知规则，建议人工复核。"}
                consequence = {"affected_subsystem": "待确认", "description": "无法从现有规则确定物理后果，请结合流量特征和设备日志人工研判。"}
            historical = {"matched": False, "reason": "历史故障索引不可用", "total_matching_records": 0, "unique_fault_modes": 0, "top_faults": []}
            if not rule:
                recommendations = [{"priority": "最高", "domain": "人工研判", "action": "未知攻击类型，建议检查该源IP的全部通信记录和设备日志", "source": "rule-based"}]
        return {
            "ok": True,
            "label": label,
            "attackInfo": {
                "name": attack_info.get("chinese_name", label),
                "severity": attack_info.get("severity", "unknown"),
                "description": attack_info.get("description", ""),
            },
            "cause": attack_info.get("description", ""),
            "affectedSubsystem": consequence.get("affected_subsystem", ""),
            "physicalConsequence": consequence.get("description", ""),
            "historicalMatch": {
                "matched": bool(historical.get("matched")),
                "reason": historical.get("reason"),
                "totalMatchingRecords": historical.get("total_matching_records", 0),
                "uniqueFaultModes": historical.get("unique_fault_modes", 0),
                "topFaults": historical.get("top_faults", []),
            },
            "recommendations": recommendations,
        }

    def _classify(self, features, mode):
        started = time.perf_counter()
        if mode == "llm":
            raise ValueError("Modbus 引擎不支持 llm 模式")
        effective_mode = mode if mode in {"fast", "hybrid"} else self.mode
        if effective_mode == "hybrid" and self.classifier is not None:
            classified = self.classifier.classify(features)
            if classified.get("tier") != "llm":
                label = classified["label"]
                confidence = classified["confidence"]
                tier = classified["tier"]
                evidence = classified.get("evidence", "")
            else:
                label, confidence = rule_based_classify(features)
                tier, evidence = "rule-degraded", "原型匹配低于阈值，已回退快速规则：" + rule_explanation(features, label)
        else:
            label, confidence = rule_based_classify(features)
            tier, evidence = "rule", rule_explanation(features, label)
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        return {
            "windowIndex": features.get("window_index"),
            "packetStart": features.get("packet_start"),
            "packetEnd": features.get("packet_end"),
            "predictedLabel": label,
            "confidence": round(float(confidence), 4),
            "detectionTier": tier,
            "inferenceMs": elapsed,
            "evidence": evidence,
            "features": features,
            "sourceIp": features.get("src_ips"),
            "destinationIp": features.get("dst_ips"),
        }

    @staticmethod
    def _empty_result(reason):
        return {"windows": [], "labels": [], "confidences": [], "totalWindows": 0, "packetCount": 0, "reason": reason, "resultUnit": "window"}

    def _build_result(self, windows, packet_count, source, mode="fast"):
        labels = [item["predictedLabel"] for item in windows]
        return {
            "windows": windows,
            "labels": labels,
            "confidences": [item["confidence"] for item in windows],
            "attackCounts": dict(Counter(labels)),
            "totalWindows": len(windows),
            "packetCount": packet_count,
            "source": source,
            "resultUnit": "window",
            "engine": "modbus-hybrid" if mode == "hybrid" and self.classifier else "modbus-fast",
            "degraded": self.classifier is None,
            "degradedReason": "原型资源不可用，已降级为快速规则模式" if self.classifier is None else None,
        }

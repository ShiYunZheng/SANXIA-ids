from app.services.validation import ValidationService


def test_raw_byte_csv_uses_record_inference(tmp_path):
    target = tmp_path / "raw.csv"
    target.write_text("byte_0,byte_1,byte_2\n1,2,3\n4,5,6\n", encoding="utf-8")

    class Detection:
        @staticmethod
        def _read_upload(path, _suffix):
            import pandas as pd
            return pd.read_csv(path)

    class Modbus:
        def reset_stream(self):
            return None

        def detect_records(self, records, fingerprint, source):
            assert [item["raw_bytes"] for item in records] == [[1, 2, 3], [4, 5, 6]]
            assert fingerprint
            assert source == "raw-csv"
            return {"windows": [], "labels": [], "confidences": [], "resultUnit": "window"}

        def detect_features_csv(self, _path):
            raise AssertionError("raw-byte CSV must not use feature CSV inference")

    result = ValidationService(Detection(), Modbus(), tmp_path)._run_modbus(target, ".csv")
    assert result["ok"] is True
    assert result["result"]["windows"] == []


def test_normalize_standalone_window_preserves_reasoning_and_evidence():
    window = ValidationService._normalize_window(
        {
            "window_index": 7,
            "window_id": "flow-7",
            "packet_range": [120, 239],
            "predicted_label": "fuzzing",
            "confidence": 0.93,
            "detection_tier": "deep",
            "inference_time_ms": 18.4,
            "answer": "异常窗口",
            "thinking": "功能码和长度分布偏离基线",
            "features": {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "function_code": 16,
            },
            "timestamp": "2026-09-20T09:30:00Z",
        },
        0,
    )

    assert window["index"] == 7
    assert window["sampleId"] == "flow-7"
    assert window["packetStart"] == 120
    assert window["packetEnd"] == 239
    assert window["predictedLabel"] == "fuzzing"
    assert window["confidence"] == 0.93
    assert window["thinking"] == "功能码和长度分布偏离基线"
    assert window["features"]["function_code"] == 16
    assert window["sourceIp"] == "10.0.0.1"
    assert window["destinationIp"] == "10.0.0.2"


def test_normalize_standalone_window_keeps_missing_explanation_empty():
    window = ValidationService._normalize_window(
        {
            "predictedLabel": "normal",
            "score": 0.81,
            "windowRange": {"from": 1, "to": 100},
            "featureEvidence": "traffic baseline matched",
        },
        3,
    )

    assert window["index"] == 3
    assert window["sampleId"] == "window-3"
    assert window["packetStart"] == 1
    assert window["packetEnd"] == 100
    assert window["thinking"] is None
    assert window["answer"] is None
    assert window["features"] == {"value": "traffic baseline matched"}

def test_modbus_runtime_error_is_isolated(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    class BrokenModbus:
        def detect_pcap(self, path):
            raise TypeError("unexpected in-process response")

    service = ValidationService(None, BrokenModbus(), tmp_path)
    result = service._run_modbus(capture, ".pcap")

    assert result["ok"] is False
    assert "unexpected in-process response" in result["error"]
    assert result["elapsedMs"] >= 0


class FakeJudgementRepository:
    def __init__(self):
        self.items = {}

    def find(self, subject_type, subject_key):
        return self.items.get((subject_type, subject_key))

    def create_if_missing(self, subject_type, subject_key, content, engine):
        key = (subject_type, subject_key)
        self.items.setdefault(key, {
            "subject_type": subject_type,
            "subject_key": subject_key,
            "content": content,
            "engine": engine,
            "version": 1,
            "generated_at": "2026-09-23T00:00:00+00:00",
        })
        return self.items[key]

    def regenerate(self, subject_type, subject_key, content, engine):
        key = (subject_type, subject_key)
        version = int(self.items.get(key, {}).get("version", 0)) + 1
        self.items[key] = {
            "subject_type": subject_type,
            "subject_key": subject_key,
            "content": content,
            "engine": engine,
            "version": version,
            "generated_at": "2026-09-23T00:01:00+00:00",
        }
        return self.items[key]


class CountingModbus:
    def __init__(self):
        self.calls = 0

    def associate(self, window):
        self.calls += 1
        return {"ok": True, "cause": f"analysis-{self.calls}", "attackInfo": {"name": window["predictedLabel"]}}


def association_window(features=None):
    return {
        "predictedLabel": "fuzzing",
        "features": features or {"function_code": 16, "src_ip": "10.0.0.1"},
        "packetStart": 0,
        "packetEnd": 119,
        "thinking": "feature evidence",
    }


def test_association_is_persisted_and_reused(tmp_path):
    repository = FakeJudgementRepository()
    modbus = CountingModbus()
    service = ValidationService(None, modbus, tmp_path, repository)

    first = service.associate_window(association_window())
    second = service.associate_window(association_window())

    assert modbus.calls == 1
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["cause"] == first["cause"]
    assert second["version"] == 1


def test_association_fingerprint_is_stable_for_feature_order():
    left = association_window({"function_code": 16, "src_ip": "10.0.0.1"})
    right = association_window({"src_ip": "10.0.0.1", "function_code": 16})

    assert ValidationService.association_fingerprint(left) == ValidationService.association_fingerprint(right)


def test_association_fingerprint_changes_for_different_windows():
    left = association_window({"function_code": 16})
    right = association_window({"function_code": 3})

    assert ValidationService.association_fingerprint(left) != ValidationService.association_fingerprint(right)


def test_force_regenerates_and_increments_version(tmp_path):
    repository = FakeJudgementRepository()
    modbus = CountingModbus()
    service = ValidationService(None, modbus, tmp_path, repository)

    first = service.associate_window(association_window())
    regenerated = service.associate_window(association_window(), force=True)

    assert modbus.calls == 2
    assert first["version"] == 1
    assert regenerated["version"] == 2
    assert regenerated["cached"] is False
    assert regenerated["cause"] == "analysis-2"

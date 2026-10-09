import pytest
import numpy as np
import pandas as pd

from app.cascade import CascadeDetectionModel, RawBytePreprocessor
from app.constants import ATTACK_TYPES, UNKNOWN_ATTACK_LABEL
from app.services.detection import DetectionService


def _ethernet_ipv4(payload_byte=0):
    header = [0] * 12 + [0x08, 0x00]
    ip_packet = [0x45] + [payload_byte] * 39
    return header + ip_packet


def test_raw_byte_preprocessor_strips_ethernet_header_and_normalizes():
    batch = RawBytePreprocessor().prepare(pd.DataFrame({"raw_bytes": [_ethernet_ipv4(255)]}))

    assert batch["features"].shape == (1, 120)
    assert batch["features"][0, 0] == np.float32(0x45 / 255)
    assert batch["features"][0, 1] == np.float32(1.0)
    assert batch["ipv4_mask"].tolist() == [True]


def test_cascade_sends_only_known_normal_ipv4_packets_to_unknown_model(tmp_path):
    model = CascadeDetectionModel(tmp_path / "known", tmp_path / "unknown", tmp_path / "meta")
    model._known = object()
    model._unknown = object()
    known = np.zeros((2, 17), dtype=np.float32)
    known[0, 15] = 0.95
    known[1, 0] = 0.90
    model._predict_known = lambda features: known
    calls = []

    def unknown(features):
        calls.append(len(features))
        return np.asarray([0.8], dtype=np.float32), np.asarray([True])

    model._predict_unknown = unknown
    result = model.predict(pd.DataFrame({"raw_bytes": [_ethernet_ipv4(1), _ethernet_ipv4(2)]}))

    assert calls == [1]
    assert result["labels"].tolist() == [15, UNKNOWN_ATTACK_LABEL]


def test_feature_rows_without_raw_bytes_are_rejected(tmp_path):
    class Cascade:
        @staticmethod
        def supports(frame):
            return False

        @staticmethod
        def status():
            return {}

    service = DetectionService(Cascade(), tmp_path)
    with pytest.raises(Exception, match="原始字节"):
        service.detect_frame(pd.DataFrame({"timestamp": [1], "machine_name": ["设备"]}))
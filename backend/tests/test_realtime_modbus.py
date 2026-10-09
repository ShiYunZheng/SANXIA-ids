import threading

from scapy.all import Ether, IP, Raw, TCP

from app.modbus.engine import ModbusInferenceEngine
from app.services.realtime_inference import RealtimeInferenceService


def _engine():
    engine = ModbusInferenceEngine.__new__(ModbusInferenceEngine)
    engine.mode = "fast"
    engine.classifier = None
    engine.prototype_error = None
    engine.fault_index = None
    engine.fault_index_error = "test"
    engine.association = None
    engine._stream_lock = threading.Lock()
    engine.reset_stream()
    return engine


def _records(start, count):
    return [{
        "source_sample_id": f"replay:file:{index}",
        "src_ip": "192.168.101.99",
        "dst_ip": "192.168.101.11",
        "src_port": 12000,
        "dst_port": 502,
        "timestamp": float(index + 1),
        "transaction_id": index,
        "unit_id": 1,
        "function_code": 6,
        "register_address": 100,
        "register_value": index,
        "coil_address": None,
        "quantity": None,
        "sub_function": None,
        "payload_length": 6,
    } for index in range(start, start + count)]


def test_stream_windows_cross_batch(monkeypatch):
    engine = _engine()
    batches = iter([_records(0, 6), _records(6, 4), _records(10, 5)])
    monkeypatch.setattr("app.modbus.engine.parse_sample_records", lambda _samples: next(batches))

    assert engine.detect_records([{}] * 6, "file", "replay")["windows"] == []
    first = engine.detect_records([{}] * 4, "file", "replay")["windows"]
    second = engine.detect_records([{}] * 5, "file", "replay")["windows"]

    assert [item["packetStart"] for item in first + second] == [0, 5]
    assert [item["packetEnd"] for item in first + second] == [10, 15]
    assert first[0]["windowKey"] != second[0]["windowKey"]


def test_raw_sampling_records_are_parsed_without_temporary_pcap():
    engine = _engine()
    modbus_payload = bytes.fromhex("000100000006010600640001")
    packet = Ether() / IP(src="192.168.101.99", dst="192.168.101.11") / TCP(sport=12000, dport=502) / Raw(load=modbus_payload)
    samples = [{
        "raw_bytes": list(bytes(packet)),
        "timestamp": float(index + 1),
        "_source_sample_id": f"interface:{index}",
    } for index in range(10)]

    result = engine.detect_records(samples, "wlan-device", "interface")

    assert result["packetCount"] == 10
    assert result["totalWindows"] == 1
    assert result["windows"][0]["sourceIp"] == "192.168.101.99"
    assert result["windows"][0]["destinationIp"] == "192.168.101.11"


class FakeRepository:
    def __init__(self):
        self.items = {}

    def insert_if_new(self, document):
        if document["windowKey"] in self.items:
            return None
        document = {**document, "_id": str(len(self.items) + 1)}
        self.items[document["windowKey"]] = document
        return document

    def latest(self, limit):
        return list(reversed(list(self.items.values())))[:limit]


class FakeEvents:
    def __init__(self):
        self.items = []

    def create_modbus_event(self, document):
        self.items.append(document)


class FakeAssociationEngine:
    def associate(self, window):
        return {"attackInfo": {"name": window["predictedLabel"], "severity": "high"}, "recommendations": []}


def test_persist_windows_without_creating_event_archive_entries():
    repository = FakeRepository()
    events = FakeEvents()
    service = RealtimeInferenceService(repository, events, FakeAssociationEngine())
    inference = {"engine": "modbus-fast", "windows": [
        {"windowKey": "normal-1", "predictedLabel": "normal"},
        {"windowKey": "attack-1", "predictedLabel": "write_single_register"},
    ]}

    assert len(service.persist(inference)) == 2
    assert len(repository.items) == 2
    assert len(events.items) == 0
    assert repository.items["attack-1"]["association"]["attackInfo"]["severity"] == "high"
    assert service.persist(inference) == []
    assert len(events.items) == 0

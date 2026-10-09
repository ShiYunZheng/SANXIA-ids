from pathlib import Path

from types import SimpleNamespace

from app.services.analytics import DashboardService, EventService
from app.services.pipeline import PipelineWorker
from app.services.sampling import SamplingService


class MemoryDashboardRepository:
    def __init__(self):
        self.sample_ids = set()
        self.batch_hashes = set()

    def has_batch_marker(self, batch_hash):
        return batch_hash in self.batch_hashes

    def insert_unique(self, items):
        inserted = []
        for index, item in enumerate(items):
            sample_id = item["source_sample_id"]
            if sample_id not in self.sample_ids:
                self.sample_ids.add(sample_id)
                inserted.append(index)
        return inserted

    def insert_batch_marker(self, marker):
        self.batch_hashes.add(marker["batch_hash"])


class NoWaitStop:
    @staticmethod
    def is_set():
        return False

    @staticmethod
    def wait(_seconds):
        return False


def test_csv_source_ids_are_stable_and_file_is_read_once(tmp_path):
    csv_path = tmp_path / "samples.csv"
    csv_path.write_text("timestamp,machine_name,value\n1,设备A,10\n1,设备A,10\n", encoding="utf-8")
    service = SamplingService("csv", tmp_path / "none.pcap", csv_path, "默认设备")
    service._stop = NoWaitStop()

    service._run_csv()
    first = service.read_samples()
    assert len(first) == 2
    assert first[0]["_source_sample_id"] != first[1]["_source_sample_id"]

    service._run_csv()
    second = service.read_samples()
    assert [item["_source_sample_id"] for item in first] == [item["_source_sample_id"] for item in second]


def test_sample_ids_prevent_replay_across_different_batch_boundaries():
    repository = MemoryDashboardRepository()
    service = DashboardService(repository)

    first = service.insert_predictions([1, 2], ["设备A", "设备A"], [1, 1], ["file:0", "file:1"])
    replay_part = service.insert_predictions([1], ["设备A"], [1], ["file:0"])
    overlap = service.insert_predictions([2, 3], ["设备A", "设备B"], [1, 2], ["file:1", "file:2"])

    assert first == {"inserted_indices": [0, 1], "inserted_count": 2, "duplicate_count": 0}
    assert replay_part == {"inserted_indices": [], "inserted_count": 0, "duplicate_count": 1}
    assert overlap == {"inserted_indices": [1], "inserted_count": 1, "duplicate_count": 1}


def test_same_timestamp_is_not_treated_as_duplicate_when_row_ids_differ():
    repository = MemoryDashboardRepository()
    service = DashboardService(repository)
    outcome = service.insert_predictions(
        [1, 1], ["设备A", "设备A"], [123.0, 123.0], ["file:10", "file:11"]
    )
    assert outcome["inserted_count"] == 2
    assert outcome["duplicate_count"] == 0


def test_event_metadata_preserves_replay_source_and_packet_ips():
    class EventRepository:
        def __init__(self):
            self.events = []

        def insert(self, event):
            self.events.append(event)
            return SimpleNamespace(inserted_id="event-1")

    repository = EventRepository()
    service = EventService(repository)
    first_subscriber = service.subscribe()
    second_subscriber = service.subscribe()
    created = service.analyze(
        [1], [123.0], ["设备A"], ["10.10.0.1"], ["10.10.0.2"], "replay",
        pipeline_run_id="run-1",
    )

    event = repository.events[0]
    assert event["dataSource"] == "PCAP回放"
    assert event["pipelineRunId"] == "run-1"
    assert event["detail"][0]["source"] == "10.10.0.1"
    assert event["detail"][0]["target"] == "10.10.0.2"
    assert created[0]["_id"] == "event-1"
    assert first_subscriber.get_nowait()["_id"] == "event-1"
    assert second_subscriber.get_nowait()["_id"] == "event-1"


def test_event_recovery_is_idempotent_and_marks_restored_archive():
    class EventRepository:
        def __init__(self):
            self.events = []

        def find_matching_archive(self, archive_key, *_args):
            return next((item for item in self.events if item.get("archiveKey") == archive_key), None)

        def insert(self, event):
            self.events.append(event)
            return SimpleNamespace(inserted_id=f"event-{len(self.events)}")

    repository = EventRepository()
    service = EventService(repository)
    arguments = dict(
        labels=[1, 1], timestamps=[123.0, 124.0], machine_components=["设备A", "设备A"],
        source_ips=["10.10.0.1", "10.10.0.1"],
        destination_ips=["10.10.0.2", "10.10.0.2"], source_type="replay",
        pipeline_run_id="run-recovery", archive_key="sanxia-group:stable",
        source_fingerprint="same-pcap",
    )

    first = service.restore_missing(**arguments)
    second = service.restore_missing(**arguments)

    assert first["created"] is True
    assert second["created"] is False
    assert first["event"]["_id"] == second["event"]["_id"] == "event-1"
    assert len(repository.events) == 1
    assert repository.events[0]["restoredFromDuplicate"] is True
    assert repository.events[0]["archiveKey"] == "sanxia-group:stable"
    assert repository.events[0]["sourceFingerprint"] == "same-pcap"


def test_pipeline_creates_records_and_events_only_for_new_samples():
    class Sampling:
        @staticmethod
        def source_fingerprint():
            return "source"

    class Detection:
        @staticmethod
        def detect_records(_samples):
            return {
                "labels": [1, 2],
                "timestamps": [10, 20],
                "machine_components": ["设备A", "设备B"],
                "source_indices": [0, 1],
            }

    class Dashboard:
        @staticmethod
        def insert_predictions(*_args):
            return {"inserted_indices": [1], "inserted_count": 1, "duplicate_count": 1}

    class Records:
        inserted = None

        def insert_detection(self, labels):
            self.inserted = labels

    class Events:
        inserted = None

        def analyze(self, labels, timestamps, components):
            self.inserted = (labels, timestamps, components)

    records = Records()
    events = Events()
    worker = PipelineWorker(Sampling(), Detection(), Dashboard(), records, events)
    outcome = worker._process_samples([
        {"_source_sample_id": "source:0"},
        {"_source_sample_id": "source:1"},
    ])

    assert outcome["inserted_count"] == 1
    assert records.inserted == [2]
    assert events.inserted == ([2], [20], ["设备B"])
    assert worker.status()["insertedSamples"] == 1
    assert worker.status()["duplicateSamples"] == 1
    assert worker.status()["processedSamples"] == 2
    assert worker.status()["attackSamples"] == 2
    assert worker.status()["alertsDetected"] == 2
    assert worker.status()["attackPredictions"] == 2
    assert worker.status()["candidateAlerts"] == 2
    assert worker.status()["labelDistribution"] == {
        "Modbus模糊测试": 1,
        "功能码读取攻击": 1,
    }
    assert worker.status()["persistedLabelDistribution"] == {"功能码读取攻击": 1}


def test_duplicate_replay_restores_deleted_event_without_reinserting_samples():
    class Sampling:
        source = "replay"

        @staticmethod
        def source_fingerprint():
            return "same-pcap"

    class Detection:
        @staticmethod
        def detect_records(_samples):
            return {
                "labels": [1, 1],
                "timestamps": [10, 11],
                "machine_components": ["设备A", "设备A"],
                "source_indices": [0, 1],
            }

    class Dashboard:
        @staticmethod
        def insert_predictions(*_args):
            return {"inserted_indices": [], "inserted_count": 0, "duplicate_count": 2}

    class Records:
        def insert_detection(self, _labels):
            raise AssertionError("duplicate replay must not create a record")

    class Events:
        accepts_recovery_metadata = True

        def __init__(self):
            self.restored = None

        def analyze(self, *_args):
            raise AssertionError("duplicate replay must not use the normal insert path")

        def restore_missing(self, labels, timestamps, components, sources, destinations, source_type, **metadata):
            self.restored = (labels, timestamps, components, sources, destinations, source_type, metadata)
            return {
                "created": True,
                "event": {
                    "_id": "restored-event-1",
                    "attackLabel": "Modbus模糊测试",
                    "eventSeverity": 1,
                    "detail": [{"source": "10.0.0.1", "target": "10.0.0.2"}],
                },
            }

    events = Events()
    worker = PipelineWorker(Sampling(), Detection(), Dashboard(), Records(), events)
    worker._run_id = "run-duplicate"
    samples = [
        {"_source_sample_id": "same:0", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
        {"_source_sample_id": "same:1", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
    ]

    worker._process_samples(samples)
    worker._process_samples(samples)

    alerts = worker.alerts("run-duplicate", 10)
    assert len(alerts) == 1
    assert alerts[0]["archiveStatus"] == "archived"
    assert alerts[0]["eventId"] == "restored-event-1"
    assert alerts[0]["sampleCount"] == 2
    assert alerts[0]["source"] == "10.0.0.1"
    assert worker.status()["runtimeAlerts"] == 1
    assert worker.status()["duplicateAlerts"] == 0
    assert worker.status()["eventsCreated"] == 1
    assert worker.status()["eventsRecovered"] == 1
    assert worker.status()["attackPredictions"] == 4
    assert worker.status()["candidateAlerts"] == 1
    assert worker.status()["labelDistribution"] == {"Modbus模糊测试": 4}
    assert worker.status()["persistedLabelDistribution"] == {}
    assert events.restored[0] == [1, 1]
    assert events.restored[5] == "replay"
    assert events.restored[6]["archive_key"].startswith("sanxia-group:")
    assert events.restored[6]["source_fingerprint"] == "same-pcap"


def test_finite_replay_drains_buffer_and_completes():
    class Sampling:
        source = "replay"

        def __init__(self):
            self.samples = [{"_source_sample_id": "replay:0"}]

        def start(self):
            return None

        def stop(self):
            return None

        def read_samples(self):
            samples, self.samples = self.samples, []
            return samples

        def status(self):
            return {"running": False}

        def source_fingerprint(self):
            return "source"

    class Detection:
        def detect_records(self, _samples):
            return {"labels": [1], "timestamps": [10], "machine_components": ["设备A"], "source_indices": [0]}

    class Dashboard:
        def insert_predictions(self, *_args):
            return {"inserted_indices": [0], "inserted_count": 1, "duplicate_count": 0}

    class Records:
        def insert_detection(self, _labels):
            return None

    class Events:
        def analyze(self, *_args):
            return [{"_id": "event-1"}]

    worker = PipelineWorker(Sampling(), Detection(), Dashboard(), Records(), Events(), interval_seconds=0.01)
    worker.start()
    worker._thread.join(timeout=1)

    status = worker.status()
    assert status["runStatus"] == "completed"
    assert status["running"] is False
    assert status["processedSamples"] == 1
    assert status["eventsCreated"] == 1


def test_shadow_pipeline_produces_results_without_repository_writes():
    class Sampling:
        source = "replay"

        def __init__(self):
            self.samples = [{"_source_sample_id": "shadow:0", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}]

        def start(self):
            return None

        def stop(self):
            return None

        def read_samples(self):
            samples, self.samples = self.samples, []
            return samples

        def status(self):
            return {"running": False}

        def source_fingerprint(self):
            return "shadow-source"

    class Detection:
        def detect_records(self, _samples):
            return {
                "labels": [1], "timestamps": [10], "machine_components": ["以太网交换机"],
                "source_indices": [0], "known_confidences": [0.9], "unknown_scores": [0.1],
            }

    class NoWrites:
        def __getattr__(self, name):
            raise AssertionError(f"shadow mode attempted repository write through {name}")

    class Events(NoWrites):
        accepts_recovery_metadata = True
        risk_policy = None

    worker = PipelineWorker(Sampling(), Detection(), NoWrites(), NoWrites(), Events(), interval_seconds=0.01)
    worker.start(persist=False)
    worker._thread.join(timeout=1)

    status = worker.status()
    alerts = worker.alerts(status["runId"], 10)
    assert status["shadowMode"] is True
    assert status["persistenceMode"] == "shadow"
    assert status["processedSamples"] == 1
    assert status["attackSamples"] == 1
    assert status["insertedSamples"] == 0
    assert status["eventsCreated"] == 0
    assert alerts[0]["archiveStatus"] == "shadow"
    assert alerts[0]["eventId"] is None

import hashlib
import json
import logging
import queue
import threading
import time
import uuid
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

from ..constants import ATTACK_TYPES
from ..risk import DEFAULT_RISK_POLICY


class RuntimeAlertFeed:
    def __init__(self, capacity=500):
        self._items = deque(maxlen=capacity)
        self._subscribers = set()
        self._lock = threading.Lock()

    def publish(self, alert):
        with self._lock:
            self._items.appendleft(alert)
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(alert)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(alert)
                except queue.Empty:
                    pass

    def list(self, run_id=None, limit=100):
        with self._lock:
            items = list(self._items)
        if run_id:
            items = [item for item in items if item.get("runId") == run_id]
        return items[:limit]

    def count(self, run_id=None):
        with self._lock:
            if not run_id:
                return len(self._items)
            return sum(1 for item in self._items if item.get("runId") == run_id)

    def subscribe(self):
        subscriber = queue.Queue(maxsize=200)
        with self._lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber):
        with self._lock:
            self._subscribers.discard(subscriber)


class PipelineWorker:
    def __init__(self, sampling, detection, dashboard, records, events, interval_seconds=10, modbus=None, realtime_inference=None, alert_cooldown_seconds=60):
        self.sampling = sampling
        self.detection = detection
        self.dashboard = dashboard
        self.records = records
        self.events = events
        self.modbus = modbus
        self.realtime_inference = realtime_inference
        self.interval_seconds = interval_seconds
        self.alert_cooldown_seconds = max(float(alert_cooldown_seconds), 1.0)
        self._alert_feed = RuntimeAlertFeed()
        self._alert_seen = {}
        self._stop = threading.Event()
        self._thread = None
        self._last_error = None
        self._batches_processed = 0
        self._inserted_samples = 0
        self._duplicate_samples = 0
        self._last_batch = None
        self._run_id = None
        self._source_context_id = uuid.uuid4().hex
        self._source_changed_at = datetime.now(timezone.utc).isoformat()
        self._run_status = "idle"
        self._started_at = None
        self._completed_at = None
        self._processed_samples = 0
        self._attack_samples = 0
        self._alerts_detected = 0
        self._events_created = 0
        self._events_recovered = 0
        self._modbus_parsed_packets = 0
        self._modbus_windows = 0
        self._modbus_attack_windows = 0
        self._modbus_last_window_at = None
        self._modbus_last_error = None
        self._normal_predictions = 0
        self._attack_predictions = 0
        self._candidate_alerts = 0
        self._label_distribution = Counter()
        self._persisted_label_distribution = Counter()
        self._runtime_alerts = 0
        self._duplicate_alerts = 0
        self._shadow_mode = False

    def start(self, persist=True):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._shadow_mode = not bool(persist)
        self._run_id = uuid.uuid4().hex
        self._run_status = "running"
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._completed_at = None
        self._batches_processed = 0
        self._inserted_samples = 0
        self._duplicate_samples = 0
        self._processed_samples = 0
        self._attack_samples = 0
        self._alerts_detected = 0
        self._events_created = 0
        self._events_recovered = 0
        self._last_batch = None
        self._modbus_parsed_packets = 0
        self._modbus_windows = 0
        self._modbus_attack_windows = 0
        self._modbus_last_window_at = None
        self._modbus_last_error = None
        self._normal_predictions = 0
        self._attack_predictions = 0
        self._candidate_alerts = 0
        self._label_distribution.clear()
        self._persisted_label_distribution.clear()
        self._runtime_alerts = 0
        self._duplicate_alerts = 0
        self._alert_seen.clear()
        if self.realtime_inference:
            self.realtime_inference.begin_run(self._shadow_mode)
        if self.modbus:
            self.modbus.reset_stream()
        self.sampling.start()
        self._thread = threading.Thread(target=self._run, name="detection-pipeline", daemon=True)
        self._thread.start()

    def stop(self):
        self._run_status = "stopping"
        self.sampling.stop()
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(3, min(30, self.interval_seconds + 5)))

    def status(self):
        modbus_status = self.modbus.status() if self.modbus else {"ready": False, "degraded": True}
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "runId": self._run_id,
            "sourceContextId": self._source_context_id,
            "sourceChangedAt": self._source_changed_at,
            "runStatus": self._run_status,
            "startedAt": self._started_at,
            "completedAt": self._completed_at,
            "processedSamples": self._processed_samples,
            "attackSamples": self._attack_samples,
            "alertsDetected": self._alerts_detected,
            "eventsCreated": self._events_created,
            "eventsRecovered": self._events_recovered,
            "normalPredictions": self._normal_predictions,
            "attackPredictions": self._attack_predictions,
            "candidateAlerts": self._candidate_alerts,
            "runtimeAlerts": self._runtime_alerts,
            "duplicateAlerts": self._duplicate_alerts,
            "labelDistribution": dict(self._label_distribution),
            "persistedLabelDistribution": dict(self._persisted_label_distribution),
            "shadowMode": self._shadow_mode,
            "persistenceMode": "shadow" if self._shadow_mode else "formal",
            "duplicates": self._duplicate_samples,
            "batchesProcessed": self._batches_processed,
            "insertedSamples": self._inserted_samples,
            "duplicateSamples": self._duplicate_samples,
            "lastBatch": self._last_batch,
            "sourceFingerprint": self.sampling.source_fingerprint(),
            "lastError": self._last_error,
            "modbus": {
                **modbus_status,
                "engine": "modbus-hybrid" if modbus_status.get("mode") == "hybrid" and modbus_status.get("prototypeAvailable") else "modbus-fast",
                "parsedPackets": self._modbus_parsed_packets,
                "windowsProcessed": self._modbus_windows,
                "attackWindows": self._modbus_attack_windows,
                "lastWindowAt": self._modbus_last_window_at,
                "lastError": self._modbus_last_error,
            },
        }

    def alerts(self, run_id=None, limit=100):
        return self._alert_feed.list(run_id, limit)

    def alert_total(self, run_id=None):
        if run_id and run_id == self._run_id:
            return self._runtime_alerts
        return self._alert_feed.count(run_id)

    def subscribe_alerts(self):
        return self._alert_feed.subscribe()

    def unsubscribe_alerts(self, subscriber):
        self._alert_feed.unsubscribe(subscriber)

    def switch_source(self, source, **options):
        was_running = bool(self._thread and self._thread.is_alive())
        was_shadow = self._shadow_mode
        previous = self.sampling.configuration()
        if was_running:
            self.stop()
        try:
            self.sampling.set_source(source, **options)
            if self.modbus:
                self.modbus.reset_stream()
            self._reset_for_new_source()
            if was_running:
                self.start(persist=not was_shadow)
        except Exception:
            self.sampling.restore_configuration(previous)
            if was_running:
                self.start(persist=not was_shadow)
            raise

    def _reset_for_new_source(self):
        """Prepare an empty live view without deleting archived alerts or events."""
        self._source_context_id = uuid.uuid4().hex
        self._source_changed_at = datetime.now(timezone.utc).isoformat()
        self._run_id = None
        self._run_status = "idle"
        self._started_at = None
        self._completed_at = None
        self._last_error = None
        self._batches_processed = 0
        self._inserted_samples = 0
        self._duplicate_samples = 0
        self._last_batch = None
        self._processed_samples = 0
        self._attack_samples = 0
        self._alerts_detected = 0
        self._events_created = 0
        self._events_recovered = 0
        self._normal_predictions = 0
        self._attack_predictions = 0
        self._candidate_alerts = 0
        self._runtime_alerts = 0
        self._duplicate_alerts = 0
        self._shadow_mode = False
        self._label_distribution.clear()
        self._persisted_label_distribution.clear()
        self._alert_seen.clear()
        self._modbus_parsed_packets = 0
        self._modbus_windows = 0
        self._modbus_attack_windows = 0
        self._modbus_last_window_at = None
        self._modbus_last_error = None
        if self.realtime_inference:
            self.realtime_inference.begin_run(False)

    def _run(self):
        try:
            while True:
                stop_requested = self._stop.wait(self.interval_seconds)
                self._drain_buffer()
                if stop_requested:
                    break
                sampling_status = self.sampling.status()
                if self.sampling.source in {"csv", "pcap", "replay"} and not sampling_status.get("running"):
                    self._drain_buffer()
                    break
        finally:
            self._completed_at = datetime.now(timezone.utc).isoformat()
            self._run_status = "stopped" if self._stop.is_set() else "completed"

    def _drain_buffer(self):
        samples = self.sampling.read_samples()
        if not samples:
            return
        try:
            self._process_samples(samples)
            self._batches_processed += 1
            self._last_error = None
        except Exception as error:
            self._last_error = str(error)
            logging.getLogger(__name__).exception("Detection pipeline batch failed")

    def _process_samples(self, samples):
        sanxia_error = None
        modbus_error = None
        outcome = None
        try:
            outcome = self._process_sanxia(samples)
        except Exception as error:
            sanxia_error = error
            logging.getLogger(__name__).exception("SANXIA detection failed; Modbus inference will continue")
        if self.modbus and self.realtime_inference:
            try:
                inferred = self.modbus.detect_records(
                    samples,
                    self.sampling.source_fingerprint(),
                    self.sampling.source,
                    mode=self.modbus.mode,
                )
                created = self.realtime_inference.process(inferred, persist=not self._shadow_mode)
                self._modbus_parsed_packets += int(inferred.get("packetCount") or 0)
                self._modbus_windows += len(created)
                self._modbus_attack_windows += sum(1 for item in created if item.get("predictedLabel") != "normal")
                if created:
                    self._modbus_last_window_at = created[-1].get("createdAt")
                self._modbus_last_error = None
            except Exception as error:
                modbus_error = error
                self._modbus_last_error = str(error)
                logging.getLogger(__name__).exception("Modbus inference failed; SANXIA result is preserved")
        if sanxia_error and (not self.modbus or modbus_error):
            raise sanxia_error
        return outcome or {"inserted_indices": [], "inserted_count": 0, "duplicate_count": 0}

    def _process_sanxia(self, samples):
        started_at = datetime.now(timezone.utc)
        result = self.detection.detect_records(samples)
        labels = result["labels"]
        timestamps = result["timestamps"]
        components = result["machine_components"]
        source_indices = list(result.get("source_indices", range(len(labels))))
        sources = [samples[int(source_indices[index])].get("src_ip") for index in range(len(labels))]
        destinations = [samples[int(source_indices[index])].get("dst_ip") for index in range(len(labels))]
        source_ids = [
            _sample_id(samples[int(index)])
            for index in source_indices
        ]
        if self._shadow_mode:
            outcome = {"inserted_indices": [], "inserted_count": 0, "duplicate_count": 0}
            inserted_indices = []
        else:
            outcome = self.dashboard.insert_predictions(labels, components, timestamps, source_ids)
            inserted_indices = outcome["inserted_indices"]
        attack_count = sum(1 for label in labels if int(label) != 0)
        for label in labels:
            index = int(label)
            name = ATTACK_TYPES[index] if 0 <= index < len(ATTACK_TYPES) else str(index)
            self._label_distribution[name] += 1
        self._processed_samples += len(labels)
        self._attack_samples += attack_count
        self._normal_predictions += len(labels) - attack_count
        self._attack_predictions += attack_count
        self._inserted_samples += outcome["inserted_count"]
        self._duplicate_samples += outcome["duplicate_count"]
        created = []
        if inserted_indices:
            inserted_labels = [labels[index] for index in inserted_indices]
            for label in inserted_labels:
                index = int(label)
                name = ATTACK_TYPES[index] if 0 <= index < len(ATTACK_TYPES) else str(index)
                self._persisted_label_distribution[name] += 1
            inserted_timestamps = [timestamps[index] for index in inserted_indices]
            inserted_components = [components[index] for index in inserted_indices]
            inserted_sources = [samples[int(source_indices[index])].get("src_ip") for index in inserted_indices]
            inserted_destinations = [samples[int(source_indices[index])].get("dst_ip") for index in inserted_indices]
            known_confidences = result.get("known_confidences") or []
            unknown_scores = result.get("unknown_scores") or []
            inserted_model_evidence = [
                {
                    "knownConfidence": known_confidences[index] if index < len(known_confidences) else None,
                    "unknownScore": unknown_scores[index] if index < len(unknown_scores) else None,
                }
                for index in inserted_indices
            ]
            if getattr(self.records, "accepts_run_metadata", False):
                self.records.insert_detection(inserted_labels, pipeline_run_id=self._run_id)
            else:
                self.records.insert_detection(inserted_labels)
            if getattr(self.events, "accepts_run_metadata", False):
                created = self.events.analyze(
                    inserted_labels, inserted_timestamps, inserted_components,
                    inserted_sources, inserted_destinations, self.sampling.source,
                    pipeline_run_id=self._run_id,
                    model_evidence=inserted_model_evidence,
                    unknown_threshold=result.get("unknown_threshold"),
                    skipped_packets=result.get("skipped_packets", 0),
                )
            elif getattr(self.events, "accepts_source_metadata", False):
                created = self.events.analyze(
                    inserted_labels, inserted_timestamps, inserted_components,
                    inserted_sources, inserted_destinations, self.sampling.source,
                )
            elif getattr(self.events, "accepts_network_metadata", False):
                created = self.events.analyze(inserted_labels, inserted_timestamps, inserted_components, inserted_sources, inserted_destinations)
            else:
                created = self.events.analyze(inserted_labels, inserted_timestamps, inserted_components)
            self._events_created += len(created or [])
        inserted_set = set(inserted_indices)
        duplicate_indices = set() if self._shadow_mode else {index for index in range(len(labels)) if index not in inserted_set}
        self._publish_runtime_alerts(
            labels, timestamps, components, sources, destinations, created or [],
            duplicate_indices=duplicate_indices, result=result,
        )
        self._last_batch = {
            "sampleCount": len(labels),
            "normalCount": sum(1 for label in labels if int(label) == 0),
            "attackCount": attack_count,
            "insertedCount": outcome["inserted_count"],
            "duplicateCount": outcome["duplicate_count"],
            "startedAt": started_at.isoformat(),
            "completedAt": datetime.now(timezone.utc).isoformat(),
        }
        return outcome

    def _publish_runtime_alerts(
        self, labels, timestamps, components, sources, destinations, created_events,
        duplicate_indices=None, result=None,
    ):
        duplicate_indices = set(duplicate_indices or [])
        result = result or {}
        groups = defaultdict(list)
        for index, value in enumerate(labels):
            label = int(value)
            if label == 0 or not 0 <= label < len(ATTACK_TYPES):
                continue
            source = sources[index] if index < len(sources) else None
            destination = destinations[index] if index < len(destinations) else None
            groups[(label, source, destination)].append(index)

        archived = {}
        archived_by_label = {}
        for event in created_events:
            attack_label = event.get("attackLabel")
            if attack_label:
                archived_by_label.setdefault(attack_label, event)
            for detail in event.get("detail") or [{}]:
                key = (
                    attack_label,
                    detail.get("source") or detail.get("source_ip"),
                    detail.get("target") or detail.get("destination_ip"),
                )
                archived[key] = event
        if len(created_events) == 1 and len({key[0] for key in groups}) == 1 and not archived:
            only_label = ATTACK_TYPES[next(iter(groups))[0]]
            archived[(only_label, None, None)] = created_events[0]

        now_monotonic = time.monotonic()
        emitted_at = datetime.now(timezone.utc).isoformat()
        for (label, source, destination), indices in groups.items():
            cooldown_key = (label, source, destination)
            previous = self._alert_seen.get(cooldown_key)
            if previous is not None and now_monotonic - previous < self.alert_cooldown_seconds:
                continue
            self._alert_seen[cooldown_key] = now_monotonic
            attack_label = ATTACK_TYPES[label]
            event = archived.get((attack_label, source, destination)) or archived.get((attack_label, None, None)) or archived_by_label.get(attack_label)
            if (
                not self._shadow_mode
                and event is None
                and indices
                and all(index in duplicate_indices for index in indices)
                and getattr(self.sampling, "source", None) in {"pcap", "replay"}
                and getattr(self.events, "accepts_recovery_metadata", False)
            ):
                event, recovered = self._restore_missing_event(
                    label, source, destination, indices,
                    labels, timestamps, components, sources, destinations, result,
                )
                if recovered:
                    self._events_created += 1
                    self._events_recovered += 1
            archive_status = "shadow" if self._shadow_mode else "archived" if event else "deduplicated"
            event_id = str(event.get("_id")) if event and event.get("_id") is not None else None
            values = [float(timestamps[index]) for index in indices if index < len(timestamps)]
            affected = sorted({str(components[index]) for index in indices if index < len(components) and components[index]})
            known_confidences = result.get("known_confidences") or []
            unknown_scores = result.get("unknown_scores") or []
            runtime_risk = (getattr(self.events, "risk_policy", None) or DEFAULT_RISK_POLICY).assess(
                attack_label,
                values,
                [components[index] for index in indices if index < len(components)],
                [sources[index] for index in indices if index < len(sources)],
                [destinations[index] for index in indices if index < len(destinations)],
                [{
                    "knownConfidence": known_confidences[index] if index < len(known_confidences) else None,
                    "unknownScore": unknown_scores[index] if index < len(unknown_scores) else None,
                } for index in indices],
                result.get("unknown_threshold"),
            )
            selected_risk = {
                key: event.get(key)
                for key in ("eventSeverity", "severitySource", "severityPolicyVersion", "severityStatus", "riskAssessment")
                if event and event.get(key) is not None
            } or runtime_risk
            alert_key = f"{self._run_id}|{label}|{source}|{destination}|{int(now_monotonic // self.alert_cooldown_seconds)}"
            alert = {
                "alertId": hashlib.sha256(alert_key.encode("utf-8")).hexdigest()[:24],
                "runId": self._run_id,
                "sourceContextId": self._source_context_id,
                "attackLabel": attack_label,
                "eventType": f"{' '.join(affected) or '未知设备'} {attack_label}",
                **selected_risk,
                "source": source,
                "target": destination,
                "startAt": _iso_time(min(values)) if values else None,
                "endAt": _iso_time(max(values)) if values else None,
                "emittedAt": emitted_at,
                "sampleCount": len(indices),
                "dataSource": {"replay": "PCAP回放", "interface": "WLAN实时", "pcap": "PCAP文件", "csv": "CSV文件"}.get(getattr(self.sampling, "source", None), "实时推理"),
                "archiveStatus": archive_status,
                "eventId": event_id,
                "engine": "sanxia-runtime",
            }
            self._alert_feed.publish(alert)
            self._runtime_alerts += 1
            self._alerts_detected += 1
            self._candidate_alerts += 1
            if archive_status == "deduplicated":
                self._duplicate_alerts += 1

    def _restore_missing_event(
        self, label, source, destination, indices,
        labels, timestamps, components, sources, destinations, result,
    ):
        source_fingerprint = self.sampling.source_fingerprint()
        archive_payload = json.dumps({
            "sourceFingerprint": source_fingerprint,
            "attackLabel": ATTACK_TYPES[label],
            "source": source,
            "destination": destination,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        archive_key = "sanxia-group:" + hashlib.sha256(archive_payload.encode("utf-8")).hexdigest()
        known_confidences = result.get("known_confidences") or []
        unknown_scores = result.get("unknown_scores") or []
        model_evidence = [
            {
                "knownConfidence": known_confidences[index] if index < len(known_confidences) else None,
                "unknownScore": unknown_scores[index] if index < len(unknown_scores) else None,
            }
            for index in indices
        ]
        outcome = self.events.restore_missing(
            [labels[index] for index in indices],
            [timestamps[index] for index in indices],
            [components[index] for index in indices],
            [sources[index] for index in indices],
            [destinations[index] for index in indices],
            self.sampling.source,
            pipeline_run_id=self._run_id,
            model_evidence=model_evidence,
            unknown_threshold=result.get("unknown_threshold"),
            skipped_packets=result.get("skipped_packets", 0),
            archive_key=archive_key,
            source_fingerprint=source_fingerprint,
        ) or {}
        return outcome.get("event"), bool(outcome.get("created"))


def _sample_id(sample):
    existing = sample.get("_source_sample_id")
    if existing:
        return str(existing)
    payload = json.dumps(sample, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return f"record:{hashlib.sha256(payload).hexdigest()}"


def _iso_time(value):
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


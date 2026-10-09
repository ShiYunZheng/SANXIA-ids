from concurrent.futures import ThreadPoolExecutor
import ast
from datetime import datetime, timezone
import hashlib
import json
import time
import uuid
from pathlib import Path

from ..errors import ApiError


class ValidationService:
    def __init__(self, detection, modbus, upload_dir, judgement_repository=None):
        self.detection = detection
        self.modbus = modbus
        self.upload_dir = Path(upload_dir)
        self.judgements = judgement_repository

    @staticmethod
    def association_fingerprint(window):
        features = window.get("features") if isinstance(window.get("features"), dict) else {}
        canonical = {
            "predictedLabel": window.get("predictedLabel") or window.get("predicted_label"),
            "features": features,
            "sourceIp": window.get("sourceIp") or window.get("source_ip") or features.get("sourceIp") or features.get("source_ip") or features.get("src_ip"),
            "destinationIp": window.get("destinationIp") or window.get("destination_ip") or features.get("destinationIp") or features.get("destination_ip") or features.get("dst_ip"),
            "packetStart": window.get("packetStart") if window.get("packetStart") is not None else window.get("packet_start"),
            "packetEnd": window.get("packetEnd") if window.get("packetEnd") is not None else window.get("packet_end"),
        }
        payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _association_response(document, cached):
        content = dict(document.get("content") or {})
        generated_at = document.get("generated_at")
        if isinstance(generated_at, datetime):
            generated_at = generated_at.astimezone(timezone.utc).isoformat()
        content.update({
            "cached": cached,
            "generatedAt": generated_at,
            "version": int(document.get("version", 1)),
            "engine": document.get("engine", "standalone"),
            "fingerprint": document.get("subject_key"),
        })
        return content

    def associate_window(self, window, force=False):
        fingerprint = self.association_fingerprint(window)
        if self.judgements is not None and not force:
            existing = self.judgements.find("standalone_window", fingerprint)
            if existing is not None:
                return self._association_response(existing, True)

        result = self.modbus.associate(window)
        if not result.get("ok"):
            raise ApiError("ASSOCIATION_UNAVAILABLE", result.get("error", "故障关联不可用"), 503)
        result = dict(result)
        result["evidence"] = window.get("evidence") or window.get("thinking") or ""

        if self.judgements is None:
            return {
                **result,
                "cached": False,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "version": 1,
                "engine": "standalone",
                "fingerprint": fingerprint,
            }

        document = (
            self.judgements.regenerate("standalone_window", fingerprint, result, "standalone")
            if force
            else self.judgements.create_if_missing("standalone_window", fingerprint, result, "standalone")
        )
        return self._association_response(document, False)
    def compare_upload(self, uploaded_file):
        filename = Path(uploaded_file.filename or "").name
        suffix = Path(filename).suffix.lower()
        if not filename or suffix not in {".csv", ".pcap", ".pcapng"}:
            raise ApiError("INVALID_FILE", "仅支持 CSV、PCAP 或 PCAPNG 文件", 400)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        target = self.upload_dir / f"compare-{uuid.uuid4().hex}-{filename}"
        uploaded_file.save(target)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = {
                    "sanxia": pool.submit(self._run_sanxia, target, suffix),
                    "standalone": pool.submit(self._run_modbus, target, suffix),
                }
                systems = {name: future.result() for name, future in futures.items()}
            return self._build_report(filename, systems)
        finally:
            target.unlink(missing_ok=True)

    def _run_sanxia(self, target, suffix):
        started = time.perf_counter()
        try:
            frame = self.detection._read_upload(target, suffix)
            result = self.detection.detect_frame(frame)
            return {"ok": True, "elapsedMs": round((time.perf_counter() - started) * 1000, 2), "result": result}
        except Exception as error:
            return {"ok": False, "elapsedMs": round((time.perf_counter() - started) * 1000, 2), "error": str(error)}

    def _run_modbus(self, target, suffix):
        started = time.perf_counter()
        try:
            if suffix == ".csv":
                frame = self.detection._read_upload(target, suffix)
                byte_columns = sorted(
                    (column for column in frame.columns if str(column).startswith("byte_") and str(column).rsplit("_", 1)[-1].isdigit()),
                    key=lambda column: int(str(column).rsplit("_", 1)[-1]),
                )
                if "raw_bytes" in frame.columns or byte_columns:
                    records = []
                    for index, row in frame.iterrows():
                        raw = row.get("raw_bytes") if "raw_bytes" in frame.columns else [row[column] for column in byte_columns]
                        if isinstance(raw, str):
                            try:
                                raw = ast.literal_eval(raw)
                            except (ValueError, SyntaxError):
                                raw = []
                        raw = [int(value) for value in list(raw or []) if value == value]
                        records.append({
                            **row.to_dict(),
                            "raw_bytes": raw,
                            "_source_sample_id": f"raw-csv:{index}",
                        })
                    self.modbus.reset_stream()
                    fingerprint = hashlib.sha256(Path(target).read_bytes()).hexdigest()
                    result = self.modbus.detect_records(records, fingerprint, "raw-csv")
                else:
                    result = self.modbus.detect_features_csv(target)
            else:
                result = self.modbus.detect_pcap(target)
            normalized_windows = [self._normalize_window(item, index) for index, item in enumerate(result.get("windows", []))]
            normalized = {
                **result,
                "windows": normalized_windows,
                "labels": [item["predictedLabel"] for item in normalized_windows],
                "confidences": [item["confidence"] for item in normalized_windows],
                "resultUnit": "window",
            }
            return {"ok": True, "status": 200, "engine": normalized.get("engine", "modbus-fast"), "transport": "in-process", "degraded": normalized.get("degraded", False), "degradedReason": normalized.get("degradedReason"), "resultUnit": "window", "elapsedMs": round((time.perf_counter() - started) * 1000, 2), "result": normalized}
        except Exception as error:
            return {"ok": False, "status": getattr(error, "code", None), "transport": "in-process", "elapsedMs": round((time.perf_counter() - started) * 1000, 2), "error": str(error)}
    @staticmethod
    def _first(mapping, *keys):
        if not isinstance(mapping, dict):
            return None
        for key in keys:
            if key in mapping and mapping[key] is not None:
                return mapping[key]
        return None

    @classmethod
    def _normalize_window(cls, item, index):
        item = item if isinstance(item, dict) else {}
        packet_range = cls._first(item, "packet_range", "packetRange", "window_range", "windowRange")
        packet_start = cls._first(item, "packet_start", "packetStart", "start_packet", "startPacket", "window_start", "windowStart")
        packet_end = cls._first(item, "packet_end", "packetEnd", "end_packet", "endPacket", "window_end", "windowEnd")
        if isinstance(packet_range, (list, tuple)) and len(packet_range) >= 2:
            packet_start = packet_start if packet_start is not None else packet_range[0]
            packet_end = packet_end if packet_end is not None else packet_range[1]
        elif isinstance(packet_range, dict):
            packet_start = packet_start if packet_start is not None else cls._first(packet_range, "start", "from", "first")
            packet_end = packet_end if packet_end is not None else cls._first(packet_range, "end", "to", "last")

        features = cls._first(item, "features", "feature_evidence", "featureEvidence")
        features = features if isinstance(features, (dict, list)) else ({} if features is None else {"value": features})
        feature_map = features if isinstance(features, dict) else {}
        source_ip = cls._first(item, "source_ip", "sourceIp", "src_ip", "srcIp") or cls._first(feature_map, "source_ip", "sourceIp", "src_ip", "srcIp")
        destination_ip = cls._first(item, "destination_ip", "destinationIp", "dst_ip", "dstIp") or cls._first(feature_map, "destination_ip", "destinationIp", "dst_ip", "dstIp")
        explicit_index = cls._first(item, "window_index", "windowIndex", "index")

        return {
            "index": explicit_index if explicit_index is not None else index,
            "sampleId": cls._first(item, "sample_id", "sampleId", "window_id", "windowId", "id") or f"window-{index}",
            "packetStart": packet_start,
            "packetEnd": packet_end,
            "packetRange": packet_range if isinstance(packet_range, str) else None,
            "predictedLabel": cls._first(item, "predicted_label", "predictedLabel", "label"),
            "confidence": cls._first(item, "confidence", "score", "probability"),
            "detectionTier": cls._first(item, "detection_tier", "detectionTier", "tier"),
            "inferenceMs": cls._first(item, "inference_time_ms", "inferenceTimeMs", "inference_ms", "latency_ms", "latencyMs"),
            "answer": cls._first(item, "answer", "final_answer", "finalAnswer", "conclusion"),
            "thinking": cls._first(item, "thinking", "reasoning", "explanation"),
            "features": features,
            "sourceIp": source_ip,
            "destinationIp": destination_ip,
            "timestamp": cls._first(item, "timestamp", "time", "detected_at", "detectedAt"),
        }

    @staticmethod
    def _labels(system):
        result = system.get("result") or {}
        return result.get("labels", []) if isinstance(result, dict) else []

    def _build_report(self, filename, systems):
        sanxia_labels = self._labels(systems["sanxia"])
        standalone_labels = self._labels(systems["standalone"])
        sanxia_result = systems["sanxia"].get("result") or {}
        comparable = bool(sanxia_result.get("sample_ids")) and bool((systems["standalone"].get("result") or {}).get("sample_ids"))
        differences = []
        for index in range(max(len(sanxia_labels), len(standalone_labels))) if comparable else []:
            left = sanxia_labels[index] if index < len(sanxia_labels) else None
            right = standalone_labels[index] if index < len(standalone_labels) else None
            if left != right:
                differences.append({"index": index, "sampleId": (sanxia_result.get("source_indices") or [None] * (index + 1))[index] if index < len(sanxia_result.get("source_indices") or []) else None, "sanxia": left, "standalone": right, "sanxiaConfidence": (sanxia_result.get("known_confidences") or [None] * (index + 1))[index] if index < len(sanxia_result.get("known_confidences") or []) else None, "unknownScore": (sanxia_result.get("unknown_scores") or [None] * (index + 1))[index] if index < len(sanxia_result.get("unknown_scores") or []) else None, "timestamp": (sanxia_result.get("timestamps") or [None] * (index + 1))[index] if index < len(sanxia_result.get("timestamps") or []) else None, "type": "missing" if left is None or right is None else "label_mismatch"})
        return {
            "input": {"filename": filename, "packetCount": max(len(sanxia_labels), len(standalone_labels))},
            "systems": systems,
            "summary": {"sanxiaCount": len(sanxia_labels), "standaloneCount": len(standalone_labels), "sameCount": (max(len(sanxia_labels), len(standalone_labels)) - len(differences)) if comparable else None, "differentCount": len(differences) if comparable else None, "comparisonMode": "sample" if comparable else "independent"},
            "differences": differences,
        }

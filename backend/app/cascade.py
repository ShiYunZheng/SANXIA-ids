import json
import threading
import time
from pathlib import Path

import numpy as np

from .constants import KNOWN_MODEL_ATTACK_TYPES, UNKNOWN_ATTACK_LABEL
from .errors import ApiError


class RawBytePreprocessor:
    """Build the byte representations used by both supplied models."""

    max_len = 120

    @staticmethod
    def byte_columns(frame):
        columns = []
        for column in frame.columns:
            name = str(column)
            if not name.startswith("byte_"):
                continue
            try:
                order = int(name.rsplit("_", 1)[1])
            except (TypeError, ValueError):
                continue
            columns.append((order, column))
        return [column for _, column in sorted(columns)]

    def supports(self, frame):
        return "raw_bytes" in frame.columns or bool(self.byte_columns(frame))

    def prepare(self, frame):
        byte_columns = self.byte_columns(frame)
        if "raw_bytes" in frame.columns:
            rows = frame["raw_bytes"].tolist()
        elif byte_columns:
            rows = frame[byte_columns].to_numpy(dtype=object).tolist()
        else:
            raise ApiError(
                "RAW_BYTES_REQUIRED",
                "级联模型需要 raw_bytes 或 byte_1...byte_n 原始字节列",
                400,
            )

        features = []
        ipv4_mask = []
        source_indices = []
        for index, row in enumerate(rows):
            prepared = self._prepare_row(row)
            if prepared is None:
                continue
            vector, is_ipv4 = prepared
            features.append(vector)
            ipv4_mask.append(is_ipv4)
            source_indices.append(index)

        if not features:
            raise ApiError("INVALID_PACKET_BYTES", "输入中没有可用于检测的数据包字节", 400)

        return {
            "features": np.stack(features).astype(np.float32),
            "ipv4_mask": np.asarray(ipv4_mask, dtype=bool),
            "source_indices": np.asarray(source_indices, dtype=np.int64),
            "skipped": len(rows) - len(features),
        }

    def _prepare_row(self, row):
        if row is None:
            return None
        try:
            values = np.asarray(list(row), dtype=np.float64).reshape(-1)
        except (TypeError, ValueError):
            return None
        values = values[~np.isnan(values)]
        if values.size == 0 or not np.isfinite(values).all():
            return None

        normalized = float(values.max(initial=0)) <= 1.0 and float(values.min(initial=0)) >= 0.0
        if normalized:
            packet = np.rint(values * 255.0).astype(np.uint8)
            payload, is_ipv4 = self._network_payload(packet)
        else:
            if float(values.min()) < 0 or float(values.max()) > 255:
                return None
            packet = np.rint(values).astype(np.uint8)
            payload, is_ipv4 = self._network_payload(packet)

        if payload.size == 0:
            return None
        vector = np.zeros(self.max_len, dtype=np.float32)
        length = min(payload.size, self.max_len)
        vector[:length] = payload[:length].astype(np.float32) / 255.0
        return vector, is_ipv4

    @staticmethod
    def _network_payload(packet):
        if packet.size >= 14:
            ether_type = (int(packet[12]) << 8) | int(packet[13])
            if ether_type in {0x0800, 0x0806, 0x86DD}:
                return packet[14:], ether_type == 0x0800
            if ether_type in {0x8100, 0x88A8} and packet.size >= 18:
                inner_type = (int(packet[16]) << 8) | int(packet[17])
                return packet[18:], inner_type == 0x0800
        return packet, packet.size > 0 and int(packet[0]) >> 4 == 4


class CascadeDetectionModel:
    def __init__(self, known_path, unknown_path, metadata_path, device="cpu", batch_size=1024):
        self.known_path = Path(known_path)
        self.unknown_path = Path(unknown_path)
        self.metadata_path = Path(metadata_path)
        self.requested_device = device
        self.batch_size = batch_size
        self.preprocessor = RawBytePreprocessor()
        self._known = None
        self._unknown = None
        self._torch = None
        self._device = "cpu"
        self._metadata = None
        self._load_lock = threading.Lock()
        self._predict_lock = threading.Lock()
        self.load_error = None
        self.load_elapsed_ms = None

    @property
    def ready(self):
        return self._known is not None and self._unknown is not None

    def resources_available(self):
        return self.known_path.is_file() and self.unknown_path.is_file() and self.metadata_path.is_file()

    def supports(self, frame):
        return self.preprocessor.supports(frame)

    def status(self):
        return {
            "ready": self.ready,
            "resourcesAvailable": self.resources_available(),
            "device": self._device,
            "knownClasses": len(KNOWN_MODEL_ATTACK_TYPES),
            "unknownThreshold": float(self._metadata["validation_attack_threshold"]) if self._metadata else None,
            "loadError": self.load_error,
            "loadElapsedMs": self.load_elapsed_ms,
        }

    def load(self):
        if self.ready:
            return
        with self._load_lock:
            if self.ready:
                return
            if not self.resources_available():
                raise ApiError("MODEL_UNAVAILABLE", "已知或未知攻击模型文件不存在", 503)
            started = time.perf_counter()
            try:
                import tensorflow as tf
                import torch

                metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
                if int(metadata.get("input_dim", 0)) != self.preprocessor.max_len:
                    raise ValueError("未知攻击模型输入维度不是 120")
                known = tf.keras.models.load_model(self.known_path, compile=False)
                if tuple(known.input_shape[1:]) != (self.preprocessor.max_len, 1):
                    raise ValueError("已知攻击模型输入形状不匹配")
                if int(known.output_shape[-1]) != len(KNOWN_MODEL_ATTACK_TYPES):
                    raise ValueError("已知攻击模型类别数量不匹配")
                device = "cuda" if self.requested_device == "cuda" and torch.cuda.is_available() else "cpu"
                unknown = torch.jit.load(str(self.unknown_path), map_location=device)
                unknown.eval()
                self._known = known
                self._unknown = unknown
                self._torch = torch
                self._device = device
                self._metadata = metadata
                self.load_error = None
                self.load_elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            except ApiError:
                raise
            except Exception as error:
                self.load_error = str(error)
                self.load_elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                raise ApiError("MODEL_UNAVAILABLE", "两阶段检测模型加载失败", 503) from error

    def predict(self, frame):
        self.load()
        prepared = self.preprocessor.prepare(frame)
        features = prepared["features"]
        with self._predict_lock:
            known_probabilities = self._predict_known(features)
            known_labels = known_probabilities.argmax(axis=1).astype(np.int64)
            known_confidences = known_probabilities.max(axis=1).astype(np.float32)
            final_labels = known_labels.copy()
            unknown_scores = np.full(len(final_labels), np.nan, dtype=np.float32)
            candidates = np.flatnonzero((known_labels == 0) & prepared["ipv4_mask"])
            if candidates.size:
                scores, predictions = self._predict_unknown(features[candidates])
                unknown_scores[candidates] = scores
                final_labels[candidates[predictions]] = UNKNOWN_ATTACK_LABEL

        return {
            "labels": final_labels,
            "known_labels": known_labels,
            "known_confidences": known_confidences,
            "unknown_scores": unknown_scores,
            "source_indices": prepared["source_indices"],
            "skipped": prepared["skipped"],
            "unknown_threshold": float(self._metadata["validation_attack_threshold"]) if self._metadata else None,
        }

    def _predict_known(self, features):
        outputs = []
        for start in range(0, len(features), self.batch_size):
            batch = np.expand_dims(features[start:start + self.batch_size], axis=-1)
            outputs.append(np.asarray(self._known.predict(batch, verbose=0), dtype=np.float32))
        return np.concatenate(outputs, axis=0)

    def _predict_unknown(self, features):
        score_outputs = []
        prediction_outputs = []
        torch = self._torch
        with torch.no_grad():
            for start in range(0, len(features), self.batch_size):
                batch = torch.as_tensor(features[start:start + self.batch_size], dtype=torch.float32, device=self._device)
                _, attack_score, pred_attack = self._unknown(batch)
                score_outputs.append(attack_score.detach().cpu().numpy().astype(np.float32))
                prediction_outputs.append(pred_attack.detach().cpu().numpy().astype(bool))
        return np.concatenate(score_outputs), np.concatenate(prediction_outputs)

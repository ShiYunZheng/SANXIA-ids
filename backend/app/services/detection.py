from pathlib import Path

import numpy as np
import pandas as pd
from werkzeug.utils import secure_filename

from ..constants import ATTACK_TYPES, KNOWN_MODEL_ATTACK_TYPES
from ..errors import ApiError
from ..ml import metrics


class DetectionService:
    def __init__(self, cascade_model, upload_dir, default_machine_name="未知设备"):
        self.cascade_model = cascade_model
        self.upload_dir = Path(upload_dir)
        self.default_machine_name = default_machine_name
        self._metrics = {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0}

    def detect_upload(self, uploaded_file):
        filename = secure_filename(uploaded_file.filename or "")
        suffix = Path(filename).suffix.lower()
        if not filename or suffix not in {".csv", ".pcap", ".pcapng"}:
            raise ApiError("INVALID_FILE", "仅支持 CSV、PCAP 或 PCAPNG 文件", 400)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        target = self.upload_dir / filename
        uploaded_file.save(target)
        try:
            frame = self._read_upload(target, suffix)
            result = self.detect_frame(frame)
            self._update_metrics(frame, result)
            return result
        finally:
            target.unlink(missing_ok=True)

    def detect_records(self, records):
        if not records:
            return self._empty_result()
        frame = pd.DataFrame(records)
        return self.detect_frame(frame)

    def detect_frame(self, frame):
        if self.cascade_model.supports(frame):
            prediction = self.cascade_model.predict(frame)
            indices = prediction["source_indices"]
            labels = prediction["labels"].astype(int).tolist()
            timestamps = self._values_at(frame, "timestamp", indices, numeric=True)
            components = self._values_at(frame, "machine_name", indices, default=self.default_machine_name)
            return {
                "labels": labels,
                "timestamps": timestamps,
                "machine_components": components,
                "attack_types": ATTACK_TYPES,
                "known_attack_types": KNOWN_MODEL_ATTACK_TYPES,
                "engine": "cascade",
                "known_labels": prediction["known_labels"].astype(int).tolist(),
                "known_confidences": prediction["known_confidences"].astype(float).tolist(),
                "unknown_scores": [None if np.isnan(value) else float(value) for value in prediction["unknown_scores"]],
                "source_indices": indices.astype(int).tolist(),
                "unknown_threshold": prediction["unknown_threshold"],
                "skipped_packets": int(prediction["skipped"]),
            }

        raise ApiError("RAW_BYTES_REQUIRED", "当前 SANXIA 仅支持 Keras/TorchScript 级联模型，输入必须包含原始字节列", 400)

    def get_metrics(self):
        return [{"name": name, "value": float(value)} for name, value in self._metrics.items()]

    def model_status(self):
        return {"cascade": self.cascade_model.status()}


    def _read_upload(self, target, suffix):
        if suffix == ".csv":
            try:
                return pd.read_csv(target)
            except Exception as error:
                raise ApiError("INVALID_CSV", "CSV 文件无法解析", 400) from error
        try:
            from scapy.utils import PcapReader

            records = []
            with PcapReader(str(target)) as reader:
                for packet in reader:
                    records.append({
                        "raw_bytes": list(bytes(packet)),
                        "timestamp": float(packet.time),
                        "machine_name": self.default_machine_name,
                    })
            if not records:
                raise ApiError("INVALID_PCAP", "抓包文件中没有数据包", 400)
            return pd.DataFrame(records)
        except ApiError:
            raise
        except Exception as error:
            raise ApiError("INVALID_PCAP", "PCAP/PCAPNG 文件无法解析", 400) from error

    def _update_metrics(self, frame, result):
        if "label" not in frame.columns or not result["labels"]:
            return
        values = frame["label"].iloc[result["source_indices"]].tolist()
        try:
            if all(isinstance(value, str) and value in ATTACK_TYPES for value in values):
                mapping = {name: index for index, name in enumerate(ATTACK_TYPES)}
                truth = [mapping[value] for value in values]
                predicted = result["labels"]
            else:
                truth = [1 if int(float(value)) > 0 else 0 for value in values]
                predicted = [1 if int(value) > 0 else 0 for value in result["labels"]]
            self._metrics = metrics(truth, predicted)
        except (ValueError, TypeError):
            return

    def _values_at(self, frame, column, indices, numeric=False, default=None):
        if column not in frame.columns:
            values = [default if default is not None else float(index) for index in indices]
        else:
            series = frame[column].iloc[indices]
            if numeric:
                converted = pd.to_numeric(series, errors="coerce")
                values = [float(value) if pd.notna(value) else float(index) for index, value in zip(indices, converted)]
            else:
                values = series.fillna(default).astype(str).tolist()
        return values

    @staticmethod
    def _empty_result():
        return {
            "labels": [], "timestamps": [], "machine_components": [], "attack_types": ATTACK_TYPES,
            "known_attack_types": [],
            "engine": "none", "known_labels": [], "known_confidences": [], "unknown_scores": [],
            "source_indices": [], "unknown_threshold": None, "skipped_packets": 0,
        }

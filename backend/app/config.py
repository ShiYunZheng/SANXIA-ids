import os
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
RESOURCE_ROOT = Path(__file__).resolve().parent / "resources"


def _boolean(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _path(name, default):
    value = os.getenv(name)
    return str(Path(value).expanduser().resolve()) if value else str(Path(default).resolve())


class Config:
    APP_ENV = os.getenv("APP_ENV", "development").lower()
    APP_PORT = int(os.getenv("APP_PORT", "5000"))
    API_PREFIX = "/api/v1"
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/spiderfort-db")
    JWT_SECRET = os.getenv("JWT_SECRET", "development-only-change-me")
    JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "1440"))
    UPLOAD_DIR = _path("UPLOAD_DIR", BACKEND_ROOT / "uploads")
    PIPELINE_PCAP_DIR = _path("PIPELINE_PCAP_DIR", Path(UPLOAD_DIR) / "pipeline_sources")
    KNOWN_ATTACK_MODEL_PATH = _path("KNOWN_ATTACK_MODEL_PATH", RESOURCE_ROOT / "cascade" / "known_attack.keras")
    UNKNOWN_ATTACK_MODEL_PATH = _path("UNKNOWN_ATTACK_MODEL_PATH", RESOURCE_ROOT / "cascade" / "unknown_attack.pt")
    UNKNOWN_ATTACK_METADATA_PATH = _path("UNKNOWN_ATTACK_METADATA_PATH", RESOURCE_ROOT / "cascade" / "unknown_metadata.json")
    MODBUS_RESOURCE_DIR = _path("MODBUS_RESOURCE_DIR", RESOURCE_ROOT / "modbus")
    MODEL_DEVICE = os.getenv("MODEL_DEVICE", "cpu").lower()
    MODEL_BATCH_SIZE = max(int(os.getenv("MODEL_BATCH_SIZE", "1024")), 1)
    PIPELINE_ENABLED = _boolean("PIPELINE_ENABLED", False)
    PIPELINE_INTERVAL_SECONDS = max(float(os.getenv("PIPELINE_INTERVAL_SECONDS", "10")), 0.1)
    PIPELINE_REPLAY_INTERVAL_SECONDS = max(float(os.getenv("PIPELINE_REPLAY_INTERVAL_SECONDS", "0.02")), 0.001)
    SAMPLE_SOURCE = os.getenv("SAMPLE_SOURCE", "csv").lower()
    INPUT_PCAP_PATH = _path("INPUT_PCAP_PATH", RESOURCE_ROOT / "input.pcap")
    INPUT_TRAFFIC_PATH = _path("INPUT_TRAFFIC_PATH", RESOURCE_ROOT / "input_traffic.csv")
    SAMPLE_MACHINE_NAME = os.getenv("SAMPLE_MACHINE_NAME", "test")
    SAMPLE_IP_ADDRESS = os.getenv("SAMPLE_IP_ADDRESS", "") or None
    SAMPLE_INTERFACE = os.getenv("SAMPLE_INTERFACE", "")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
    MONGO_CONNECT_TIMEOUT_MS = int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", "3000"))
    RISK_DURATION_SECONDS = max(float(os.getenv("RISK_DURATION_SECONDS", "30")), 0.0)
    RISK_SAMPLE_THRESHOLD = max(int(os.getenv("RISK_SAMPLE_THRESHOLD", "10")), 1)
    RISK_TARGET_THRESHOLD = max(int(os.getenv("RISK_TARGET_THRESHOLD", "3")), 1)
    RISK_CONFIDENCE_THRESHOLD = min(max(float(os.getenv("RISK_CONFIDENCE_THRESHOLD", "0.60")), 0.0), 1.0)
    JSON_AS_ASCII = False

    @classmethod
    def validate(cls):
        if cls.APP_ENV == "production" and cls.JWT_SECRET == "development-only-change-me":
            raise RuntimeError("JWT_SECRET must be set when APP_ENV=production")
        if cls.SAMPLE_SOURCE not in {"pcap", "replay", "interface", "csv"}:
            raise RuntimeError("SAMPLE_SOURCE must be one of: pcap, replay, interface, csv")
        if cls.MODEL_DEVICE not in {"cpu", "cuda"}:
            raise RuntimeError("MODEL_DEVICE must be cpu or cuda")


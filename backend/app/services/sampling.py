import gc
import hashlib
import ipaddress
import random
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ..constants import MACHINE_COMPONENTS
from ..errors import ApiError


class SampleBuffer:
    def __init__(self, max_size=100000):
        self._items = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def add(self, item):
        with self._lock:
            self._items.append(item)

    def drain(self):
        with self._lock:
            items = list(self._items)
            self._items.clear()
        return items

    def __len__(self):
        with self._lock:
            return len(self._items)


class SamplingService:
    def __init__(self, source, pcap_path, csv_path, machine_name, ip_address=None, interface="", upload_dir=None, max_upload_bytes=50 * 1024 * 1024, replay_interval_seconds=0.02):
        self.source = source
        self.pcap_path = Path(pcap_path)
        self.pcap_name = self.pcap_path.name if self.pcap_path.is_file() else None
        self.csv_path = Path(csv_path)
        self.machine_name = machine_name
        self.ip_address = ip_address
        self.interface = interface
        self.interface_name = None
        self.upload_dir = Path(upload_dir or self.pcap_path.parent / "pipeline_sources")
        self.max_upload_bytes = max_upload_bytes
        self.replay_interval_seconds = max(float(replay_interval_seconds), 0.001)
        self.buffer = SampleBuffer()
        self._stop = threading.Event()
        self._thread = None
        self._last_error = None
        self._captured_samples = 0
        self._last_capture_at = None

    def source_available(self):
        if self.source in {"pcap", "replay"}:
            return self.pcap_path.is_file()
        if self.source == "csv":
            return self.csv_path.is_file()
        return any(item["deviceId"] == self.interface and item["available"] for item in self.interface_catalog())

    def configuration(self):
        return {
            "source": self.source,
            "pcap_path": self.pcap_path,
            "pcap_name": self.pcap_name,
            "interface": self.interface,
            "interface_name": self.interface_name,
            "machine_name": self.machine_name,
        }

    def restore_configuration(self, configuration):
        self.source = configuration["source"]
        self.pcap_path = Path(configuration["pcap_path"])
        self.pcap_name = configuration["pcap_name"]
        self.interface = configuration["interface"]
        self.interface_name = configuration["interface_name"]
        self.machine_name = configuration["machine_name"]

    def set_source(self, source, pcap_path=None, pcap_name=None, interface=None, machine_name=None):
        if source not in {"csv", "pcap", "replay", "interface"}:
            raise ApiError("INVALID_SAMPLE_SOURCE", "采样源必须是 csv、pcap、replay 或 interface", 400)
        previous = self.configuration()
        self.source = source
        if machine_name is not None:
            if machine_name not in MACHINE_COMPONENTS:
                self.restore_configuration(previous)
                raise ApiError("INVALID_MACHINE_COMPONENT", "资产名称不在受支持的工控组件列表中", 400)
            self.machine_name = machine_name
        if source in {"pcap", "replay"} and pcap_path:
            self.pcap_path = Path(pcap_path)
            self.pcap_name = pcap_name or self.pcap_path.name
        if source == "interface":
            if not interface:
                self.restore_configuration(previous)
                raise ApiError("INTERFACE_REQUIRED", "请选择要采样的实时网卡", 400)
            selected = next((item for item in self.interface_catalog() if item["deviceId"] == interface), None)
            if not selected or not selected["available"]:
                self.restore_configuration(previous)
                reason = selected["reason"] if selected else "所选网卡不存在或当前已断开"
                raise ApiError("SAMPLING_UNAVAILABLE", reason, 503)
            self.interface = interface
            self.interface_name = selected["name"]
        if not self.source_available():
            self.restore_configuration(previous)
            raise ApiError("SAMPLING_UNAVAILABLE", self.availability_reason(source), 503)
        self._last_error = None

    def store_pcap(self, uploaded_file):
        filename = uploaded_file.filename or ""
        suffix = Path(filename).suffix.lower()
        if suffix not in {".pcap", ".pcapng"}:
            raise ApiError("INVALID_PCAP_TYPE", "仅支持 .pcap 或 .pcapng 文件", 400)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.upload_dir / f".upload-{uuid.uuid4().hex}.tmp"
        try:
            uploaded_file.save(temporary)
            size = temporary.stat().st_size
            if size == 0:
                raise ApiError("INVALID_PCAP", "PCAP 文件为空", 400)
            if size > self.max_upload_bytes:
                raise ApiError("FILE_TOO_LARGE", "PCAP 文件不能超过 50 MB", 413)
            _validate_pcap(temporary)
            digest = _file_hash(temporary)
            destination = self.upload_dir / f"{digest}{suffix}"
            if destination.exists():
                _safe_unlink(temporary)
            else:
                temporary.replace(destination)
            return {"path": destination, "name": filename, "fingerprint": digest, "size": size}
        finally:
            if temporary.exists():
                _safe_unlink(temporary)

    def availability_reason(self, source=None):
        selected = source or self.source
        if selected == "csv":
            return None if self.csv_path.is_file() else "内置 CSV 文件不存在"
        if selected in {"pcap", "replay"}:
            return None if self.pcap_path.is_file() else "尚未上传有效的 PCAP 文件"
        if not _npcap_available():
            return "Npcap 未安装或服务未运行，暂时无法实时抓包"
        if not self.interface:
            return "尚未选择实时网卡"
        return "所选网卡不存在、已断开或不可用"

    def interface_catalog(self):
        try:
            from scapy.arch.windows import get_windows_if_list
            adapters = get_windows_if_list()
        except Exception:
            return []
        npcap_available = _npcap_available()
        result = []
        for adapter in adapters:
            name = str(adapter.get("name") or "")
            description = str(adapter.get("description") or "")
            guid = str(adapter.get("guid") or "")
            ips = [str(value) for value in adapter.get("ips", []) if _usable_ip(value)]
            searchable = f"{name} {description}".lower()
            if not guid or not ips or "bluetooth" in searchable or "wi-fi direct" in searchable or "loopback" in searchable or name.endswith("-0000"):
                continue
            device_id = f"\\Device\\NPF_{guid}"
            available = npcap_available
            result.append({
                "name": name or description,
                "description": description,
                "deviceId": device_id,
                "ip": next((value for value in ips if ":" not in value), ips[0]),
                "available": available,
                "recommended": name.casefold() == "wlan",
                "reason": None if available else "Npcap 未安装或服务未运行",
            })
        return sorted(result, key=lambda item: (not item["recommended"], "wsl" not in item["name"].lower(), item["name"].lower()))

    def sources(self):
        interfaces = self.interface_catalog()
        return {
            "sources": [
                {"source": "csv", "label": "内置 CSV", "available": self.csv_path.is_file(), "reason": self.availability_reason("csv")},
                {"source": "pcap", "label": "外部 PCAP", "available": self.pcap_path.is_file(), "reason": self.availability_reason("pcap"), "fileName": self.pcap_name},
                {"source": "replay", "label": "模拟 WLAN", "available": self.pcap_path.is_file(), "reason": self.availability_reason("replay"), "fileName": self.pcap_name, "simulated": True},
                {"source": "interface", "label": "实时网卡", "available": any(item["available"] for item in interfaces), "reason": None if any(item["available"] for item in interfaces) else self.availability_reason("interface")},
            ],
            "interfaces": interfaces,
            "selectedSource": self.source,
            "selectedInterface": self.interface or None,
        }

    def status(self):
        return {
            "source": self.source,
            "sourceFingerprint": self.source_fingerprint(),
            "sourceFileName": self.pcap_name if self.source in {"pcap", "replay"} else None,
            "interfaceName": self.interface_name if self.source == "interface" else None,
            "machineName": self.machine_name,
            "simulated": self.source == "replay",
            "available": self.source_available(),
            "availabilityReason": self.availability_reason() if not self.source_available() else None,
            "running": bool(self._thread and self._thread.is_alive()),
            "capturedSamples": self._captured_samples,
            "bufferedSamples": len(self.buffer),
            "lastCaptureAt": self._last_capture_at,
            "lastError": self._last_error,
        }

    def source_fingerprint(self):
        if self.source == "csv" and self.csv_path.is_file():
            return _file_hash(self.csv_path)
        if self.source in {"pcap", "replay"} and self.pcap_path.is_file():
            return _file_hash(self.pcap_path)
        if self.source == "interface" and self.interface:
            return hashlib.sha256(self.interface.encode("utf-8")).hexdigest()
        return None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        if not self.source_available():
            raise ApiError("SAMPLING_UNAVAILABLE", "采样源配置无效或文件不存在", 503)
        self._stop.clear()
        self._captured_samples = 0
        self._last_capture_at = None
        self._last_error = None
        self._thread = threading.Thread(target=self._run, name="traffic-sampler", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def read_samples(self):
        return self.buffer.drain()

    def _run(self):
        try:
            if self.source == "csv":
                self._run_csv()
            elif self.source in {"pcap", "replay"}:
                self._run_pcap(replay=self.source == "replay")
            else:
                self._run_interface()
        except Exception as error:
            self._last_error = str(error)

    def _run_csv(self):
        source_hash = _file_hash(self.csv_path)
        frame = pd.read_csv(self.csv_path)
        for index, item in enumerate(frame.to_dict(orient="records")):
            if self._stop.is_set():
                return
            item.setdefault("machine_name", self.machine_name)
            item["_source_sample_id"] = f"csv:{source_hash}:{index}"
            self._add_sample(item)
            self._stop.wait(0.02)

    def _run_pcap(self, replay=False):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader

        source_hash = _file_hash(self.pcap_path)
        with PcapReader(str(self.pcap_path)) as reader:
            for index, packet in enumerate(reader):
                if self._stop.is_set():
                    return
                item = _packet_to_record(packet, IP, TCP, self.machine_name, self.ip_address, IPv6)
                item["_source_sample_id"] = f"{'replay' if replay else 'pcap'}:{source_hash}:{index}"
                self._add_sample(item)
                self._stop.wait(self.replay_interval_seconds if replay else 0.02)

    def _run_interface(self):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.sendrecv import sniff

        while not self._stop.is_set():
            packets = sniff(iface=self.interface, store=True, timeout=1)
            for packet in packets:
                item = _packet_to_record(packet, IP, TCP, self.machine_name, self.ip_address, IPv6)
                digest = hashlib.sha256(
                    f"{self.interface}|{item['timestamp']}|".encode("utf-8") + bytes(item["raw_bytes"])
                ).hexdigest()
                item["_source_sample_id"] = f"interface:{digest}"
                self._add_sample(item)

    def _add_sample(self, item):
        self.buffer.add(item)
        self._captured_samples += 1
        self._last_capture_at = datetime.now(timezone.utc).isoformat()


class AttackService:
    def __init__(self, csv_path):
        self.csv_path = Path(csv_path)

    def samples(self):
        if not self.csv_path.is_file():
            raise ApiError("ATTACK_SOURCE_UNAVAILABLE", "攻击样本 CSV 不存在", 503)
        frame = pd.read_csv(self.csv_path)
        if frame.empty:
            return []
        count = min(random.randint(100, 200), len(frame))
        start = random.randint(0, max(len(frame) - count, 0))
        return frame.iloc[start:start + count].to_dict(orient="records")


def _packet_to_record(packet, ip_layer, tcp_layer, machine_name, ip_address, ipv6_layer=None):
    record = {
        "raw_bytes": list(bytes(packet)),
        "timestamp": float(getattr(packet, "time", time.time())),
        "frame_length": len(packet),
        "captured_length": len(packet),
        "ip_version": 0,
        "ip_header_length": 0,
        "ip_tos": 0,
        "ip_ttl": 0,
        "ip_protocol": 0,
        "ip_length": 0,
        "src_port": 0,
        "dst_port": 0,
        "tcp_seq": 0,
        "tcp_ack": 0,
        "tcp_flags": "",
        "tcp_window": 0,
        "tcp_header_length": 0,
        "protocol_name": "Unknown",
        "machine_name": machine_name,
        "ip_address": ip_address,
        "src_ip": None,
        "dst_ip": None,
    }
    if ip_layer in packet:
        ip = packet[ip_layer]
        record.update({
            "ip_version": ip.version,
            "ip_header_length": (ip.ihl or 0) * 4,
            "ip_tos": ip.tos,
            "ip_ttl": ip.ttl,
            "ip_protocol": ip.proto,
            "ip_length": ip.len,
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
        })
    elif ipv6_layer is not None and ipv6_layer in packet:
        ip = packet[ipv6_layer]
        record.update({
            "ip_version": 6,
            "ip_ttl": int(getattr(ip, "hlim", 0) or 0),
            "ip_protocol": int(getattr(ip, "nh", 0) or 0),
            "ip_length": int(getattr(ip, "plen", 0) or 0),
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
        })
    if tcp_layer in packet:
        tcp = packet[tcp_layer]
        record.update({
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_seq": tcp.seq,
            "tcp_ack": tcp.ack,
            "tcp_flags": str(tcp.flags),
            "tcp_window": tcp.window,
            "tcp_header_length": (tcp.dataofs or 0) * 4,
            "protocol_name": _protocol_name(tcp.sport, tcp.dport),
        })
    return record


def _protocol_name(source_port, destination_port):
    known = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 502: "ModBus", 3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP"}
    return known.get(source_port) or known.get(destination_port) or ("TCP_WellKnown" if source_port < 1024 or destination_port < 1024 else "TCP")


def _file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_pcap(path):
    try:
        from scapy.utils import PcapReader
        with PcapReader(str(path)) as reader:
            if reader.read_packet() is None:
                raise ValueError("no packets")
    except Exception as error:
        raise ApiError("INVALID_PCAP", "文件不是可解析且包含数据包的 PCAP/PCAPNG", 400) from error


def _npcap_available():
    try:
        from scapy.config import conf
        return bool(conf.use_pcap)
    except Exception:
        return False


def _usable_ip(value):
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
        return not address.is_loopback and not address.is_link_local and not (address.version == 4 and address.is_private and str(address).startswith("169.254."))
    except ValueError:
        return False


def _safe_unlink(path):
    for _attempt in range(4):
        try:
            Path(path).unlink(missing_ok=True)
            return
        except PermissionError:
            gc.collect()
            time.sleep(0.05)


"""
Modbus pcapng 数据预处理脚本
解析 sainxia_data_260414/ 下的 pcapng 文件，提取 Modbus 协议字段，
按会话窗口聚合，生成结构化的特征 CSV 文件。
"""
import os
import struct
from collections import defaultdict
from datetime import datetime
from typing import Optional

from scapy.all import rdpcap, IP, TCP, Raw
import pandas as pd
import numpy as np
from tqdm import tqdm

# ── 配置 ──────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__), "sainxia_data_260414")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "dataset")
WINDOW_SIZE = 10          # 每个窗口包含的数据包数（缩小以增加样本密度）
WINDOW_STRIDE = 5          # 窗口滑动步长（缩小以增加重叠）

# 正常运维设备 IP（假设）
TRUSTED_IPS = {"192.168.101.1", "192.168.101.10"}

# 已知攻击者 IP（源 IP 为此集合的流量标记为攻击）
ATTACKER_IPS = {"192.168.101.99", "192.168.101.199"}

# 敏感寄存器地址范围（调速器控制相关）
SENSITIVE_REGISTERS = {
    (0xC488, 0xC48F),   # 油泵出口压力区域
    (0x0064, 0x00C7),   # 通用控制寄存器
}

# 文件→标签映射
FILE_LABEL = {
    "writeSingleRegister_3300.pcapng": "write_single_register",
    "readHoldingRegister_200.pcapng": "read_holding_register",
    "readCoils_3000.pcapng": "read_coils",
    "getfunc_3000_3times.pcapng": "getfunc_scan",
    "uid_700.pcapng": "uid_scan",
    "fuzzing_2700.pcapng": "fuzzing",
}

# ── Modbus/TCP 解析 ───────────────────────────────────


def parse_modbus_tcp(payload: bytes) -> Optional[dict]:
    """手动解析 Modbus/TCP 协议，返回字段字典或 None"""
    if len(payload) < 8:
        return None

    # Modbus/TCP 头: TransactionID(2) + ProtocolID(2) + Length(2) + UnitID(1)
    trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
    if proto_id != 0:  # Modbus 协议标识固定为 0
        return None

    function_code = payload[7]
    result = {
        "transaction_id": trans_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "register_address": None,
        "register_value": None,
        "coil_address": None,
        "quantity": None,
        "sub_function": None,
        "payload_length": length,
    }

    pdu = payload[7 : 7 + length]
    pdu_len = len(pdu)

    # 按功能码解析 PDU（防御性编程，检查长度）
    if function_code == 0x01:  # Read Coils
        if pdu_len >= 5:
            result["coil_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["quantity"] = struct.unpack(">H", pdu[3:5])[0]

    elif function_code == 0x03:  # Read Holding Registers
        if pdu_len >= 5:
            result["register_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["quantity"] = struct.unpack(">H", pdu[3:5])[0]

    elif function_code == 0x06:  # Write Single Register
        if pdu_len >= 5:
            result["register_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["register_value"] = struct.unpack(">H", pdu[3:5])[0]

    elif function_code == 0x10:  # Write Multiple Registers
        if pdu_len >= 5:
            result["register_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["quantity"] = struct.unpack(">H", pdu[3:5])[0]
            # 后续字节为写入的具体值（可变长）

    elif function_code == 0x08:  # Diagnostics (含 UID 探测子功能)
        if pdu_len >= 4:
            result["sub_function"] = struct.unpack(">H", pdu[1:3])[0]

    elif function_code == 0x2B:  # MEI / Get Function (功能码探测)
        if pdu_len >= 3:
            result["sub_function"] = pdu[1]  # MEI Type

    return result


def parse_pcap(filepath: str) -> list[dict]:
    """解析单个 pcapng 文件，返回所有 Modbus 记录列表"""
    packets = rdpcap(str(filepath))
    records = []
    fname = os.path.basename(filepath)

    for pkt in tqdm(packets, desc=f"解析 {fname}", leave=False):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        if not pkt.haslayer(Raw):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        payload = bytes(pkt[Raw].load)

        # Modbus/TCP 默认端口 502
        if dst_port != 502 and src_port != 502:
            continue

        modbus_info = parse_modbus_tcp(payload)
        if modbus_info is None:
            continue

        modbus_info.update({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "timestamp": float(pkt.time),
        })
        records.append(modbus_info)

    return records


# ── 特征工程 ──────────────────────────────────────────


def is_sensitive_address(addr: Optional[int]) -> bool:
    """判断寄存器地址是否属于敏感区域"""
    if addr is None:
        return False
    for low, high in SENSITIVE_REGISTERS:
        if low <= addr <= high:
            return True
    return False


def extract_window_features(window: list[dict]) -> dict:
    """从数据包窗口中提取统计特征"""
    if not window:
        return {}

    func_codes = [r["function_code"] for r in window]
    reg_addrs = [r["register_address"] for r in window if r["register_address"] is not None]
    reg_vals = [r["register_value"] for r in window if r["register_value"] is not None]
    timestamps = [r["timestamp"] for r in window]
    src_ips = list(set(r["src_ip"] for r in window))
    dst_ips = list(set(r["dst_ip"] for r in window))

    # 时间特征
    if len(timestamps) > 1:
        intervals = np.diff(sorted(timestamps))
        mean_interval = float(np.mean(intervals))
        std_interval = float(np.std(intervals))
    else:
        mean_interval = std_interval = 0.0

    # 功能码分布
    func_code_counts = defaultdict(int)
    for fc in func_codes:
        func_code_counts[int(fc)] += 1
    unique_func_codes = len(func_code_counts)

    # 请求频率 (包/秒)
    duration = max(timestamps) - min(timestamps)
    request_rate = len(window) / duration if duration > 0 else 0

    features = {
        "packet_count": len(window),
        "unique_func_codes": unique_func_codes,
        "most_common_func": max(func_code_counts, key=func_code_counts.get),
        "func_0x01_count": func_code_counts.get(0x01, 0),
        "func_0x03_count": func_code_counts.get(0x03, 0),
        "func_0x06_count": func_code_counts.get(0x06, 0),
        "func_0x08_count": func_code_counts.get(0x08, 0),
        "func_0x10_count": func_code_counts.get(0x10, 0),
        "func_0x2b_count": func_code_counts.get(0x2B, 0),
        "unique_reg_addr": len(set(reg_addrs)),
        "has_sensitive_addr": any(is_sensitive_address(a) for a in reg_addrs),
        "register_addr_min": min(reg_addrs) if reg_addrs else 0,
        "register_addr_max": max(reg_addrs) if reg_addrs else 0,
        "register_value_mean": float(np.mean(reg_vals)) if reg_vals else 0,
        "register_value_std": float(np.std(reg_vals)) if reg_vals else 0,
        "src_is_trusted": all(ip in TRUSTED_IPS for ip in src_ips),
        "src_is_attacker": any(ip in ATTACKER_IPS for ip in src_ips),
        "mean_interval_ms": round(mean_interval * 1000, 3),
        "std_interval_ms": round(std_interval * 1000, 3),
        "request_rate": round(request_rate, 2),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "src_ips": ",".join(sorted(src_ips)),
        "dst_ips": ",".join(sorted(dst_ips)),
    }
    return features


# ── 生成正常流量样本 ──────────────────────────────────
def generate_normal_samples(count: int = 800) -> list[dict]:
    """模拟正常 Modbus 通信，补充 normal 类别样本"""
    np.random.seed(42)
    records = []
    normal_ips = list(TRUSTED_IPS)

    for i in range(count):
        t = 1000 + i * np.random.uniform(0.5, 2.0)
        src = np.random.choice(normal_ips)
        dst = np.random.choice(["192.168.101.11", "192.168.101.41", "192.168.101.71"])
        # 正常操作：读寄存器 (0x03)、读线圈 (0x01)
        fc = np.random.choice([0x03, 0x01], p=[0.7, 0.3])
        reg_addr = np.random.randint(0x0000, 0x0100)
        records.append({
            "src_ip": src,
            "dst_ip": dst,
            "function_code": fc,
            "register_address": reg_addr,
            "register_value": None if fc != 0x06 else np.random.randint(0x0000, 0x1000),
            "coil_address": reg_addr if fc == 0x01 else None,
            "quantity": np.random.randint(1, 10),
            "timestamp": t,
            "is_normal": True,
        })
    return records


# ── 主流程 ────────────────────────────────────────────


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    all_records = []
    label_counts = defaultdict(int)

    print("=" * 60)
    print("1. 解析 pcapng 文件...")
    print("=" * 60)

    for fname, label in FILE_LABEL.items():
        fpath = os.path.join(DATA_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  [WARN] 文件不存在: {fpath}")
            continue

        print(f"  解析 {fname} ...")
        records = parse_pcap(fpath)
        for r in records:
            # 按源 IP 判断：攻击 IP → 保留攻击子类型，其余 → 正常
            if r["src_ip"] in ATTACKER_IPS:
                r["label"] = label
            else:
                r["label"] = "normal"
        all_records.extend(records)
        print(f"    提取 {len(records)} 条 Modbus 记录 -> 标签: {label}")
        label_counts[label] += len(records)

    # 不再生成模拟正常流量 — 非攻击 IP 的包已自动标为 normal
    # print(f"\n  生成正常流量样本...")
    # normal_records = generate_normal_samples(800)
    # for r in normal_records:
    #     r["label"] = "normal"
    # all_records.extend(normal_records)
    # label_counts["normal"] = len(normal_records)
    # print(f"    生成 {len(normal_records)} 条正常记录")

    # 按文件+会话分组后滑动窗口
    print(f"\n2. 滑动窗口特征提取 (窗口={WINDOW_SIZE}, 步长={WINDOW_STRIDE})...")
    print("=" * 60)

    # 按 (src_ip, dst_ip) 分组模拟会话
    sessions = defaultdict(list)
    for r in all_records:
        key = (r["src_ip"], r["dst_ip"])
        sessions[key].append(r)

    # 每个会话内按时序排序后滑动窗口
    features_list = []
    for key, pkts in tqdm(sessions.items(), desc="滑动窗口特征提取"):
        pkts.sort(key=lambda x: x["timestamp"])
        # 确定该窗口的主标签（取窗口内多数标签）
        for i in range(0, max(1, len(pkts) - WINDOW_SIZE + 1), WINDOW_STRIDE):
            window = pkts[i : i + WINDOW_SIZE]
            if len(window) < 5:  # 忽略太小的窗口
                continue
            feat = extract_window_features(window)
            # 确定标签：取窗口内出现最多的攻击标签，避免正常标签主导
            window_labels = [p["label"] for p in window]
            label_votes = defaultdict(int)
            for lbl in window_labels:
                label_votes[lbl] += 1
            # 如果任何攻击标签总数 > 正常标签，则用攻击标签
            attack_votes = sum(v for k, v in label_votes.items() if k != "normal")
            normal_votes = label_votes.get("normal", 0)
            if attack_votes > normal_votes:
                # 选最多的攻击标签
                top_attack = max(
                    ((k, v) for k, v in label_votes.items() if k != "normal"),
                    key=lambda x: x[1],
                )[0]
                feat["label"] = top_attack
            else:
                feat["label"] = "normal"
            features_list.append(feat)

    df = pd.DataFrame(features_list)
    print(f"  共生成 {len(df)} 条窗口样本")

    # 标签分布
    print(f"\n3. 标签分布:")
    print("=" * 60)
    for lbl in sorted(df["label"].unique()):
        cnt = (df["label"] == lbl).sum()
        print(f"  {lbl:30s}: {cnt:5d}")

    # 保存
    output_path = os.path.join(OUTPUT_DIR, "features.csv")
    df.to_csv(output_path, index=False)
    print(f"\n  特征数据已保存至: {output_path}")
    print(f"  列: {list(df.columns)}")
    print("=" * 60)
    print("数据预处理完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()

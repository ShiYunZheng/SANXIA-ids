ATTACK_TYPES = [
    "Normal",
    "Modbus模糊测试",
    "功能码读取攻击",
    "线圈读取攻击",
    "寄存器读取攻击",
    "UID枚举攻击",
    "寄存器写入攻击",
    "msf-detect",
    "功能码爆破",
    "nmap扫描",
    "ARP投毒",
    "DDoS",
    "DNS劫持",
    "ICMP泛洪",
    "MAC溢出",
    "MITM",
    "SYN泛洪",
    "电机开关故障",
    "未知攻击",
]

KNOWN_MODEL_ATTACK_TYPES = ATTACK_TYPES[:17]
LEGACY_ATTACK_TYPES = ["Normal", "MITM", "nmap扫描", "SYN泛洪", "msf-detect", "电机开关故障", "未知攻击"]
LEGACY_TO_PLATFORM_LABEL = [ATTACK_TYPES.index(name) for name in LEGACY_ATTACK_TYPES]
UNKNOWN_ATTACK_LABEL = ATTACK_TYPES.index("未知攻击")

# Kept as a public compatibility mapping. New event grading is performed by
# RiskPolicy and every unmapped attack falls back to medium instead of density.
ATTACK_SEVERITY_BY_LABEL = {
    "寄存器写入攻击": 1,
    "Modbus模糊测试": 1,
    "未知攻击": 1,
    "寄存器读取攻击": 2,
    "线圈读取攻击": 2,
    "MAC溢出": 2,
    "功能码读取攻击": 3,
    "UID枚举攻击": 3,
}
SEVERITY_NAMES = ("critical", "high", "medium", "low")
SEVERITY_POLICY_VERSION = "attack-rule-v2"


def attack_severity(label, fallback=2):
    return int(ATTACK_SEVERITY_BY_LABEL.get(str(label), 2))

MACHINE_COMPONENTS = ["监控主机", "以太网交换机", "数据服务器", "左阀门", "右阀门"]

ROLE_ADMIN = 0
ROLE_USER_REGISTER = 1
ROLE_USER = 2

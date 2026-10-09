"""
故障关联分析模块
将 Modbus 攻击检测结果与历史故障清单关联，生成规则化处置建议。

核心流程: 攻击类型 → 物理后果 → 历史故障匹配 → 处置建议
"""
import os
import re
import json
import hashlib
from collections import Counter, defaultdict
from typing import Optional

# ── 项目路径 ──────────────────────────────────────────────
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DOCX_PATH = os.path.join(PROJECT_DIR, "附件3历史故障清单.docx")
CACHE_DIR = os.path.join(PROJECT_DIR, "dataset")
CACHE_PATH = os.path.join(CACHE_DIR, "fault_index_cache.json")


# ══════════════════════════════════════════════════════════
# FaultIndex — 故障索引
# ══════════════════════════════════════════════════════════

class FaultIndex:
    """解析 docx 故障清单并构建可搜索的关键词倒排索引"""

    def __init__(self, docx_path: str = DOCX_PATH, cache_path: str = CACHE_PATH):
        self.faults: list[dict] = []
        self._keyword_index: dict[str, set[str]] = defaultdict(set)  # keyword → fault_ids
        self._load(docx_path, cache_path)

    # ── 加载与缓存 ───────────────────────────────────

    def _load(self, docx_path: str, cache_path: str):
        os.makedirs(CACHE_DIR, exist_ok=True)

        docx_mtime = os.path.getmtime(docx_path) if os.path.exists(docx_path) else 0
        cache_valid = os.path.exists(cache_path) and os.path.getmtime(cache_path) >= docx_mtime

        if cache_valid:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            self.faults = cached["faults"]
            self._keyword_index = defaultdict(set, {
                k: set(v) for k, v in cached.get("keyword_index", {}).items()
            })
            return

        # 解析 docx
        self._parse_docx(docx_path)
        # 构建关键词索引
        self._build_keyword_index()
        # 写缓存
        cache_data = {
            "faults": self.faults,
            "keyword_index": {k: list(v) for k, v in self._keyword_index.items()},
            "count": len(self.faults),
        }
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)

    def _parse_docx(self, docx_path: str):
        """解析 docx 文件中的故障表格"""
        from docx import Document

        doc = Document(docx_path)
        if not doc.tables:
            raise ValueError(f"docx 文件中未找到表格: {docx_path}")

        table = doc.tables[0]
        rows = list(table.rows)

        # 验证表头
        if len(rows) < 2:
            raise ValueError("故障清单表格为空")

        header = [cell.text.strip() for cell in rows[0].cells]
        expected = ["序号", "闸别", "故障发生时间", "故障模式", "运行方向",
                     "故障发生时相关传感器的状态", "故障发生时的应对措施"]
        if len(header) < len(expected):
            raise ValueError(f"表格列数不足: 期望 {len(expected)}, 实际 {len(header)}")

        self.faults = []
        for row in rows[1:]:
            cells = [cell.text.strip() for cell in row.cells]
            if len(cells) < 7:
                continue
            seq = cells[0].strip()
            if not seq:  # 跳过空序号行
                continue

            fault_mode = cells[3]
            sensor_state = cells[5]
            response = cells[6]

            # 提取关键词
            keywords = self._extract_keywords(fault_mode, sensor_state)

            self.faults.append({
                "id": seq,
                "gate": cells[1],
                "time": cells[2],
                "fault_mode": fault_mode,
                "direction": cells[4],
                "sensor_state": sensor_state,
                "response": response,
                "_keywords": keywords,
            })

    def _build_keyword_index(self):
        """构建关键词倒排索引"""
        self._keyword_index = defaultdict(set)
        for fault in self.faults:
            fid = fault["id"]
            for kw in fault["_keywords"]:
                self._keyword_index[kw].add(fid)

    @staticmethod
    def _extract_keywords(fault_mode: str, sensor_state: str) -> list[str]:
        """从故障模式和传感器状态中提取关键词"""
        combined = fault_mode + " " + sensor_state
        # 提取所有连续中文字符作为候选关键词
        chinese_words = re.findall(r"[一-鿿]{2,}", combined)
        # 过滤常见停用词
        stop_words = {"信号", "无异常", "是否", "是否涉及", "异常", "正常",
                       "发生时间", "发生时的", "时的", "故障", "发生时"}
        keywords = [w for w in chinese_words if w not in stop_words]
        # 添加原始故障模式作为整体关键词
        keywords.append(fault_mode)
        return list(set(keywords))

    # ── 查询接口 ─────────────────────────────────────

    def search_by_keyword(self, keyword: str) -> list[dict]:
        """按关键词搜索匹配的故障记录"""
        matched_ids = set()
        for idx_kw, fids in self._keyword_index.items():
            if keyword in idx_kw:
                matched_ids.update(fids)
        return [f for f in self.faults if f["id"] in matched_ids]

    def search_by_keywords(self, keywords: list[str]) -> list[dict]:
        """按多个关键词搜索（OR逻辑），去重返回"""
        matched_ids = set()
        for kw in keywords:
            for idx_kw, fids in self._keyword_index.items():
                if kw in idx_kw:
                    matched_ids.update(fids)
        return [f for f in self.faults if f["id"] in matched_ids]

    def get_mode_summary(self) -> Counter:
        """返回故障模式分布"""
        return Counter(f["fault_mode"] for f in self.faults)

    def get_response_summary(self) -> Counter:
        """返回应对措施分布"""
        return Counter(f["response"] for f in self.faults)

    def __len__(self):
        return len(self.faults)


# ══════════════════════════════════════════════════════════
# 攻击-故障映射规则
# ══════════════════════════════════════════════════════════

ATTACK_FAULT_RULES: dict = {
    "write_single_register": {
        "severity": "critical",
        "chinese_name": "写寄存器攻击 (0x06)",
        "description": "攻击者向敏感控制寄存器写入异常值，试图篡改工业控制参数",
        "physical_consequence": (
            "攻击者利用Modbus 0x06功能码向调速器、油泵、阀门或变频器的控制寄存器写入"
            "异常值。在三峡船闸系统中，可能导致：\n"
            "  (1) 调速器控制参数被篡改 → 闸门运动速度/位置失控 → 机械过载\n"
            "  (2) 油泵/液压系统控制寄存器被篡改 → 油压异常 → 动力回路故障\n"
            "  (3) 变频器运行参数被篡改 → 电机驱动异常 → 变频器故障"
        ),
        "affected_subsystem": "调速器 / 油泵 / 阀门 / 变频器控制系统",
        "immediate_network_actions": [
            "立即在交换机/防火墙上阻断攻击源IP的Modbus 502端口通信",
            "检查PLC程序完整性，确认是否有未授权的寄存器写入操作",
            "在SCADA网络上启用Modbus深度包检测，拦截0x06写操作到敏感地址",
        ],
        "immediate_physical_actions": [
            "检查调速器当前设定值是否与运行基线一致",
            "检查油泵出口压力是否在正常范围（寄存器0xC488-0xC48F）",
            "检查变频器运行参数是否被篡改",
            "如发现异常参数，立即将受影响设备切换至手动/本地控制模式",
        ],
        "fault_search_keywords": [
            "机械过载", "变频器故障", "动力回路故障", "开闸", "关闸",
            "压力故障", "过载",
        ],
    },

    "fuzzing": {
        "severity": "high",
        "chinese_name": "模糊测试攻击 (Fuzzing)",
        "description": "发送大量异常/畸形的Modbus数据包，试图造成设备拒绝服务",
        "physical_consequence": (
            "攻击者发送大量畸形Modbus数据包冲击PLC/RTU，造成通信模块处理异常、"
            "缓冲区溢出或控制器进程崩溃。在三峡船闸系统中，可能导致：\n"
            "  (1) PLC通信中断 → 合拢信号无法正常收发 → 合拢超时故障\n"
            "  (2) 控制器死机/重启 → 水平信号丢失\n"
            "  (3) 阀门/闸门控制指令丢失或延迟 → 开闸/关闸超时\n"
            "  (4) 变频器通信模块异常 → 变频器故障报警"
        ),
        "affected_subsystem": "PLC控制器 / Modbus通信网络 / 变频器",
        "immediate_network_actions": [
            "立即在接入交换机上对攻击源IP实施流量限速（Rate Limiting）或完全阻断",
            "启用工业IDS/IPS规则拦截异常功能码和畸形Modbus报文",
            "检查PLC通信模块的CPU利用率和错误计数，确认是否受到冲击",
        ],
        "immediate_physical_actions": [
            "检查各闸门合拢信号是否正常，必要时切换至本地手动操作模式",
            "检查水平信号传感器的数据连续性，确认是否有丢失",
            "检查变频器运行状态和报警记录",
            "如控制器疑似重启，检查程序加载状态和时间戳",
        ],
        "fault_search_keywords": [
            "合拢超时", "水平信号丢失", "开闸", "关闸", "超时", "变频器故障",
            "信号丢失", "离开关终位", "离开开关终位",
        ],
    },

    "read_holding_register": {
        "severity": "medium",
        "chinese_name": "读保持寄存器攻击 (0x03)",
        "description": "大量读取保持寄存器，属于信息侦察行为",
        "physical_consequence": (
            "攻击者通过Modbus 0x03功能码大量读取保持寄存器，获取设备运行参数"
            "（油压、闸门开度、水位等），属于侦察行为。\n"
            "当前阶段不直接引发物理故障，但暴露系统运行状态，为后续精准攻击"
            "（如写寄存器攻击）提供情报支撑。"
        ),
        "affected_subsystem": "全系统（信息侦察——无直接物理影响）",
        "immediate_network_actions": [
            "加强该源IP的Modbus通信监控与审计日志记录",
            "评估是否需要对Modbus通信启用访问控制白名单",
            "检查是否有同一源IP的其他异常行为（如后续的写操作尝试）",
        ],
        "immediate_physical_actions": [
            "无需直接物理干预，但建议对关键控制参数进行人工复核",
        ],
        "fault_search_keywords": [],  # 侦察行为无直接物理故障匹配
    },

    "read_coils": {
        "severity": "medium",
        "chinese_name": "读线圈攻击 (0x01)",
        "description": "批量读取线圈状态，探测开关量信息",
        "physical_consequence": (
            "攻击者通过Modbus 0x01功能码批量读取线圈状态，获取开关量信息"
            "（阀门位置、闸门限位、合拢/水平信号等）。同属侦察行为，"
            "不直接引发物理故障。"
        ),
        "affected_subsystem": "全系统（侦察——无直接物理影响）",
        "immediate_network_actions": [
            "加强该源IP的监控与审计日志记录",
            "评估是否需要在Modbus报文层面检测异常的线圈读取模式",
        ],
        "immediate_physical_actions": [],
        "fault_search_keywords": [],
    },

    "getfunc_scan": {
        "severity": "low",
        "chinese_name": "功能码探测攻击 (0x2B)",
        "description": "探测PLC支持的功能码列表，属于攻击链早期侦察",
        "physical_consequence": (
            "攻击者使用0x2B(MEI)等功能码探测目标PLC/RTU支持的功能列表，"
            "属于攻击链早期侦察阶段，不直接引发物理故障。"
        ),
        "affected_subsystem": "PLC/RTU通信接口（侦察）",
        "immediate_network_actions": [
            "记录该源IP的行为特征，纳入威胁情报库",
            "检查是否存在其他IP同时进行功能码探测（协同侦察），评估攻击面",
        ],
        "immediate_physical_actions": [],
        "fault_search_keywords": [],
    },

    "uid_scan": {
        "severity": "low",
        "chinese_name": "从站地址扫描 (0x08)",
        "description": "扫描Modbus从站地址，枚举网络中的在线设备",
        "physical_consequence": (
            "攻击者使用0x08诊断功能码扫描Modbus从站地址，枚举网络中所有在线"
            "设备，属于攻击链早期侦察行为，不直接引发物理故障。"
        ),
        "affected_subsystem": "Modbus网络从站设备（侦察）",
        "immediate_network_actions": [
            "记录扫描来源，评估是否需要调整Modbus从站地址映射以增加探测难度",
            "考虑在网络边界部署工业防火墙，过滤异常诊断功能码",
        ],
        "immediate_physical_actions": [],
        "fault_search_keywords": [],
    },

    "normal": {
        "severity": "none",
        "chinese_name": "正常通信",
        "description": "流量特征符合正常Modbus通信模式",
        "physical_consequence": "无。流量特征符合正常Modbus通信模式，不对物理系统构成威胁。",
        "affected_subsystem": "无",
        "immediate_network_actions": [],
        "immediate_physical_actions": [],
        "fault_search_keywords": [],
    },
}

# ── 严重度排序 ──────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


# ══════════════════════════════════════════════════════════
# RecommendationEngine — 推荐引擎
# ══════════════════════════════════════════════════════════

class RecommendationEngine:
    """三阶段关联引擎：攻击→物理后果→历史故障匹配→处置建议"""

    def __init__(self, fault_index: FaultIndex, rules: dict = None):
        self.fault_index = fault_index
        self.rules = rules or ATTACK_FAULT_RULES

    def analyze(self, predicted_label: str,
                input_features: dict = None) -> dict:
        """
        主入口：分析预测结果并返回完整关联报告。

        Args:
            predicted_label: 预测的攻击类型标签
            input_features: 可选的输入特征字典（用于补充上下文）

        Returns:
            完整分析结果字典
        """
        rule = self.rules.get(predicted_label)
        if not rule:
            return self._unknown_label_result(predicted_label, input_features)

        # Stage 1: 物理后果
        consequence = {
            "description": rule["physical_consequence"],
            "affected_subsystem": rule["affected_subsystem"],
        }

        # Stage 2: 历史故障匹配
        historical_match = self._find_matching_faults(
            rule.get("fault_search_keywords", [])
        )

        # Stage 3: 处置建议
        recommendations = self._generate_recommendations(
            rule, historical_match, input_features
        )

        return {
            "attack_info": {
                "predicted_label": predicted_label,
                "chinese_name": rule["chinese_name"],
                "severity": rule["severity"],
                "description": rule["description"],
            },
            "physical_consequence": consequence,
            "historical_fault_match": historical_match,
            "recommendations": recommendations,
        }

    def _find_matching_faults(self, keywords: list[str]) -> dict:
        """搜索历史故障清单，聚合匹配结果"""
        if not keywords:
            return {
                "matched": False,
                "reason": "该攻击类型为信息侦察行为，无直接对应的物理故障模式",
                "total_matching_records": 0,
                "unique_fault_modes": 0,
                "top_faults": [],
            }

        matching = self.fault_index.search_by_keywords(keywords)
        if not matching:
            return {
                "matched": False,
                "reason": f"未在历史故障清单中找到匹配模式 (搜索关键词: {', '.join(keywords[:5])}...)",
                "total_matching_records": 0,
                "unique_fault_modes": 0,
                "top_faults": [],
            }

        # 按故障模式聚合
        mode_groups: dict[str, list[dict]] = defaultdict(list)
        for f in matching:
            mode_groups[f["fault_mode"]].append(f)

        # 按频次降序排列
        sorted_modes = sorted(mode_groups.items(), key=lambda x: -len(x[1]))

        top_faults = []
        for mode, faults in sorted_modes[:10]:
            # 该模式最常用的应对措施
            response_counter = Counter(f["response"] for f in faults)
            top_response = response_counter.most_common(1)[0]

            # 示例故障
            example = faults[0]
            top_faults.append({
                "fault_mode": mode,
                "occurrences": len(faults),
                "typical_response": top_response[0],
                "response_frequency": f"{top_response[1]}/{len(faults)}",
                "example": {
                    "id": example["id"],
                    "gate": example["gate"],
                    "time": example["time"],
                    "direction": example["direction"],
                },
            })

        return {
            "matched": True,
            "total_matching_records": len(matching),
            "unique_fault_modes": len(mode_groups),
            "top_faults": top_faults,
        }

    def _generate_recommendations(self, rule: dict, historical_match: dict,
                                   features: dict = None) -> list[dict]:
        """合并规则即时动作与历史应对措施"""
        recs = []

        # 严重度为 critical/high 时，最高优先级建议
        if rule["severity"] in ("critical", "high"):
            recs.append({
                "priority": "最高",
                "domain": "overall",
                "action": "建议立即将受影响控制系统切换至离线/手动模式，阻断所有非授权Modbus通信",
                "source": "rule-based",
            })

        # 网络层即时动作
        for action in rule.get("immediate_network_actions", []):
            recs.append({
                "priority": "立即",
                "domain": "网络层",
                "action": action,
                "source": "rule-based",
            })

        # 物理层即时动作
        for action in rule.get("immediate_physical_actions", []):
            recs.append({
                "priority": "立即",
                "domain": "物理层",
                "action": action,
                "source": "rule-based",
            })

        # 历史故障的应对措施（去重）
        if historical_match.get("matched"):
            seen_actions = set()
            for ft in historical_match.get("top_faults", []):
                resp = ft.get("typical_response", "")
                if resp and resp not in seen_actions:
                    seen_actions.add(resp)
                    recs.append({
                        "priority": "参考历史",
                        "domain": "物理层",
                        "action": resp,
                        "source": "historical",
                        "basis": (
                            f"历史{ft['occurrences']}起'{ft['fault_mode']}'故障"
                            f"均采用此措施 ({ft['response_frequency']})"
                        ),
                    })

        return recs

    def _unknown_label_result(self, label: str, features: dict = None) -> dict:
        """处理未识别的预测标签"""
        return {
            "attack_info": {
                "predicted_label": label,
                "chinese_name": f"未知攻击类型 ({label})",
                "severity": "unknown",
                "description": "模型输出的攻击类型不在已知分类中，建议人工研判",
            },
            "physical_consequence": {
                "description": "无法评估——攻击类型未识别，建议由安全专家人工分析流量特征",
                "affected_subsystem": "待确认",
            },
            "historical_fault_match": {
                "matched": False,
                "reason": "无法匹配——攻击类型未识别",
                "total_matching_records": 0,
                "unique_fault_modes": 0,
                "top_faults": [],
            },
            "recommendations": [{
                "priority": "最高",
                "domain": "overall",
                "action": "未知攻击类型，建议立即人工介入分析，并检查该源IP的所有通信记录",
                "source": "rule-based",
            }],
        }


# ══════════════════════════════════════════════════════════
# 报告格式化
# ══════════════════════════════════════════════════════════

def format_analysis_console(analysis: dict, sample_idx: int = 0) -> str:
    """将单条分析结果格式化为控制台可读文本"""
    ai = analysis.get("attack_info", {})
    pc = analysis.get("physical_consequence", {})
    hm = analysis.get("historical_fault_match", {})
    recs = analysis.get("recommendations", [])

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                       "low": "🟢", "none": "⚪", "unknown": "❓"}

    lines = []
    lines.append("─" * 65)
    lines.append(f"样本 #{sample_idx} | {ai.get('chinese_name', '')} | "
                 f"严重度: {severity_emoji.get(ai.get('severity', ''), '')} "
                 f"{ai.get('severity', '').upper()}")

    # 思考过程
    thinking = analysis.get("thinking", "")
    if thinking:
        lines.append(f"\n  💭 思考过程:")
        for think_line in thinking.split("\n"):
            lines.append(f"     {think_line.strip()}")

    answer = analysis.get("answer", "")
    if answer:
        lines.append(f"\n  💬 模型答案: {answer}")

    # 物理后果
    lines.append(f"\n  📋 物理后果评估:")
    lines.append(f"     影响子系统: {pc.get('affected_subsystem', 'N/A')}")
    for desc_line in pc.get("description", "").split("\n"):
        lines.append(f"     {desc_line.strip()}")

    # 历史故障匹配
    lines.append(f"\n  📊 历史故障匹配:")
    if hm.get("matched"):
        lines.append(f"     ✓ 匹配到 {hm['total_matching_records']} 条历史故障记录 "
                     f"({hm['unique_fault_modes']} 种模式)")
        for ft in hm.get("top_faults", [])[:5]:
            lines.append(f"       • {ft['fault_mode']} ({ft['occurrences']}次)"
                         f" → 典型措施: {ft['typical_response']}")
    else:
        lines.append(f"     ✗ {hm.get('reason', '无匹配')}")

    # 处置建议
    lines.append(f"\n  🛡️  处置建议:")
    for r in recs[:8]:
        tag = f"[{r['priority']}-{r['domain']}]"
        lines.append(f"       {tag:22s} {r['action']}")
        if r.get("basis"):
            lines.append(f"       {'':22s} (依据: {r['basis']})")

    return "\n".join(lines)


def generate_summary(analyses: list[dict]) -> dict:
    """生成批量分析的汇总统计"""
    total = len(analyses)
    if total == 0:
        return {"total_samples": 0}

    # 攻击类型分布
    attack_dist = Counter(
        a.get("attack_info", {}).get("predicted_label", "unknown")
        for a in analyses
    )

    # 严重度分布
    severity_dist = Counter(
        a.get("attack_info", {}).get("severity", "unknown")
        for a in analyses
    )

    # 故障匹配统计
    fault_matched = sum(
        1 for a in analyses
        if a.get("historical_fault_match", {}).get("matched")
    )
    total_matching_records = sum(
        a.get("historical_fault_match", {}).get("total_matching_records", 0)
        for a in analyses
    )

    # 最常见建议（提取 action 文本）
    all_actions = []
    for a in analyses:
        for r in a.get("recommendations", []):
            all_actions.append(r["action"])
    top_actions = Counter(all_actions).most_common(5)

    return {
        "total_samples": total,
        "attack_type_distribution": dict(attack_dist.most_common()),
        "severity_distribution": dict(severity_dist.most_common()),
        "samples_with_fault_match": fault_matched,
        "total_matching_historical_records": total_matching_records,
        "most_common_recommendations": [
            {"action": action, "count": cnt} for action, cnt in top_actions
        ],
    }

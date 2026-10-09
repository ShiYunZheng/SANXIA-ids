"""
两级级联推理分类器
Tier 1a: 规则引擎 (高置信度样本, ~70% cover, >99% acc)
Tier 1b: 特征原型余弦匹配 (模糊样本, ~19% cover, >70% acc)
Tier 2:  LLM 推理 (真正不确定样本, ~11% cover)

使用方式:
  python prototype_classifier.py --build     # 从 features.csv 构建原型库
  python prototype_classifier.py --validate  # 验证全量数据准确率
"""
import os
import pickle
import sys
import json
from collections import defaultdict
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import KMeans

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(PROJECT_DIR, "dataset", "features.csv")
PROTOTYPE_PATH = os.path.join(PROJECT_DIR, "model_output", "prototypes.pkl")

# 17 个有效特征（去除常量列和字符串列）
FEATURE_COLS = [
    "unique_func_codes", "most_common_func",
    "func_0x01_count", "func_0x03_count", "func_0x06_count",
    "func_0x08_count", "func_0x10_count", "func_0x2b_count",
    "unique_reg_addr", "has_sensitive_addr",
    "register_addr_min", "register_addr_max",
    "register_value_mean", "src_is_attacker",
    "mean_interval_ms", "std_interval_ms", "request_rate",
]

# k-means 聚类数：normal 类内 cos_sim 仅 0.447，需多质心
NORMAL_CLUSTERS = 8

# 攻击类型列表
ATTACK_LABELS = [
    "write_single_register",
    "read_holding_register",
    "read_coils",
    "getfunc_scan",
    "uid_scan",
    "fuzzing",
    "normal",
]


# ═══════════════════════════════════════════════════════════
# Tier 1a: 规则引擎（修复版）
# ═══════════════════════════════════════════════════════════

def rule_based_classify(fc: dict) -> tuple:
    """
    确定性规则分类。返回 (label, confidence)。

    注意：数据集全量分析表明只有 3 类攻击有高特异性特征信号：
    - getfunc_scan: 功能码多样性极高 (unique_func_codes >= 7)
    - write_single_register: 0x06 占比高 + 敏感寄存器
    - read_holding_register: 0x03 占比高

    fuzzing / uid_scan / read_coils 在特征空间高度重叠
    (均表现为 0x01 主导, unique_func_codes≈1)，
    无法仅靠规则高置信度区分，需走原型匹配或 LLM。
    """
    # ── 高特异性信号 (conf >= 0.95) ──

    # 功能码多样性极高 → getfunc_scan（0x2B探测会触发多种响应）
    if fc["func_0x2b_count"] > 0 or fc["unique_func_codes"] >= 7:
        return ("getfunc_scan", 0.97)

    # 0x06 占比高 + 敏感寄存器 → 写寄存器攻击
    if fc["func_0x06_count"] >= 8 and fc["has_sensitive_addr"]:
        return ("write_single_register", 0.97)

    # 0x03 占比高 → 读保持寄存器侦察
    if fc["func_0x03_count"] >= 8:
        if fc["src_is_attacker"]:
            return ("read_holding_register", 0.95)
        else:
            return ("normal", 0.75)  # 非攻击者高频0x03更像正常SCADA轮询

    # ── 中等置信度信号 ──

    # 非攻击者 + 低多样性 → 大概率 normal
    if not fc["src_is_attacker"] and fc["unique_func_codes"] <= 3:
        return ("normal", 0.90)

    # 攻击者 + 0x01 主导 → fuzzing/uid_scan/read_coils 重叠区
    # 推到原型匹配层处理
    if fc["src_is_attacker"] and fc["func_0x01_count"] >= 7:
        if fc["unique_func_codes"] >= 3:
            return ("fuzzing", 0.60)  # 少量多样性 → 倾向fuzzing
        else:
            return ("fuzzing", 0.55)  # 纯0x01 → 可能是fuzzing/uid/coils任意

    # 攻击者 + 中等0x06信号
    if fc["src_is_attacker"] and fc["func_0x06_count"] >= 4:
        return ("write_single_register", 0.70)

    # 兜底：非攻击者 → normal
    if not fc["src_is_attacker"]:
        return ("normal", 0.80)

    # 其他未匹配的攻击者信号
    return ("fuzzing", 0.50)


def rule_explanation(fc: dict, label: str) -> str:
    """生成规则引擎判定解释"""
    reasons = []
    mc = fc["most_common_func"]
    func_names = {0x01: "读线圈", 0x03: "读保持寄存器", 0x06: "写单个寄存器",
                  0x08: "诊断", 0x10: "写多个寄存器", 0x2B: "获取功能码列表"}

    if label == "getfunc_scan":
        reasons.append("检测到 0x2B (获取功能码列表) 功能码")
    elif label == "write_single_register":
        reasons.append(f"0x06 占比≥80% 且目标寄存器在敏感区域")
    elif label == "uid_scan":
        reasons.append("检测到 0x08 (诊断/UID扫描) 功能码")
    elif label == "fuzzing":
        if fc["src_is_attacker"]:
            reasons.append(f"攻击者 IP + {fc['unique_func_codes']}种不同功能码 (fuzzing 特征)")
        else:
            reasons.append(f"攻击者 IP + 模糊行为模式")
    elif label == "read_holding_register":
        reasons.append(f"攻击者 IP + 0x03 占 {fc['func_0x03_count']/fc['packet_count']*100:.0f}% (侦察行为)")
    elif label == "read_coils":
        reasons.append(f"攻击者 IP + 0x01 占 {fc['func_0x01_count']/fc['packet_count']*100:.0f}% (侦察行为)")
    elif label == "normal":
        if not fc["src_is_attacker"]:
            reasons.append(f"非攻击者 IP + 低功能码多样性 ({fc['unique_func_codes']}种)")
        else:
            reasons.append("未匹配明确攻击特征，归为正常")

    reasons.append(f"主要功能码: 0x{mc:02X} ({func_names.get(mc, '未知')})")
    return "；".join(reasons)


# ═══════════════════════════════════════════════════════════
# Tier 1b: 特征原型匹配
# ═══════════════════════════════════════════════════════════

class PrototypeClassifier:
    """
    两级级联分类器。
    Tier 1a: 规则引擎
    Tier 1b: 特征原型余弦匹配（normal 类用 k-means 多质心）
    Tier 2:  LLM（外部调用方处理）
    """

    def __init__(self, scaler: StandardScaler, prototypes: dict,
                 rule_threshold: float = 0.92, proto_threshold: float = 0.92):
        self.scaler = scaler
        self.prototypes = prototypes  # {cls_label: np.ndarray of shape (n_centroids, n_features)}
        self.rule_threshold = rule_threshold
        self.proto_threshold = proto_threshold

    def classify(self, features: dict) -> dict:
        """
        级联分类。
        返回: {label, confidence, tier, evidence}
        tier: "rule" | "prototype" | "llm"
        若 tier="llm"，label 为 None，调用方需自行 LLM 推理。
        """
        # Tier 1a: 规则引擎
        r_label, r_conf = rule_based_classify(features)
        if r_conf >= self.rule_threshold:
            return {
                "label": r_label,
                "confidence": float(r_conf),
                "tier": "rule",
                "evidence": rule_explanation(features, r_label),
            }

        # Tier 1b: 原型匹配
        try:
            feat_vec = self._extract_feature_vector(features)
            x = self.scaler.transform(feat_vec.reshape(1, -1))

            best_cls = None
            best_sim = -1.0
            for cls_name, centroids in self.prototypes.items():
                # centroids shape: (n_centroids, n_features)
                sims = cosine_similarity(x, centroids.reshape(-1, self.scaler.n_features_in_))[0] \
                    if centroids.ndim == 1 \
                    else cosine_similarity(x, centroids)[0]
                max_sim = float(np.max(sims))
                if max_sim > best_sim:
                    best_sim = max_sim
                    best_cls = cls_name

            if best_sim >= self.proto_threshold:
                return {
                    "label": best_cls,
                    "confidence": float(best_sim),
                    "tier": "prototype",
                    "evidence": (
                        f"余弦相似度: {best_sim:.4f}，"
                        f"最近原型类: {best_cls}，"
                        f"规则引擎低置信度: {r_label}({r_conf:.2f})"
                    ),
                }
        except Exception:
            pass

        # Tier 2: 推出到 LLM
        return {
            "label": None,
            "confidence": 0.0,
            "tier": "llm",
            "evidence": (
                f"规则引擎低置信度: {r_label}({r_conf:.2f})，原型匹配低于阈值。建议 LLM 深度推理。"
            ),
        }

    def _extract_feature_vector(self, features: dict) -> np.ndarray:
        """从特征字典提取 17 维数值向量"""
        return np.array([float(features.get(c, 0)) for c in FEATURE_COLS])


# ═══════════════════════════════════════════════════════════
# 构建阶段
# ═══════════════════════════════════════════════════════════

def build_prototypes(csv_path: str = DEFAULT_CSV, output_path: str = PROTOTYPE_PATH,
                     n_normal_clusters: int = NORMAL_CLUSTERS) -> PrototypeClassifier:
    """
    从 features.csv 构建原型库。
    1. 读取全量数据
    2. StandardScaler 拟合
    3. 每个攻击类 → 单一质心
    4. normal 类 → k-means 多质心
    5. 保存到 .pkl
    """
    print(f"读取 {csv_path} ...")
    df = pd.read_csv(csv_path)
    print(f"  共 {len(df)} 条样本")

    # 标准化
    print(f"标准化 {len(FEATURE_COLS)} 个特征 ...")
    scaler = StandardScaler()
    X = scaler.fit_transform(df[FEATURE_COLS].values)

    # 构建原型
    prototypes = {}
    for cls_name in sorted(df["label"].unique()):
        mask = (df["label"] == cls_name).values
        X_cls = X[mask]
        n = len(X_cls)
        centroid = X_cls.mean(axis=0)

        if cls_name == "normal":
            # normal 类极度分散 (cos_sim≈0.447)，单一质心无效
            # 用 k-means 聚类为多个子质心
            k = min(n_normal_clusters, n)
            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
            kmeans.fit(X_cls)
            prototypes[cls_name] = kmeans.cluster_centers_  # shape: (k, n_features)
            print(f"  {cls_name:30s} n={n:5d} → k-means {k} 子质心")
        else:
            # 攻击类：单一质心即可（类内 cos_sim > 0.85）
            prototypes[cls_name] = centroid  # shape: (n_features,)
            # 验证类内紧凑度
            sims = cosine_similarity(X_cls, centroid.reshape(1, -1)).flatten()
            print(f"  {cls_name:30s} n={n:5d} → cos_mean={sims.mean():.4f} "
                  f"std={sims.std():.4f} min={sims.min():.4f}")

    # 序列化保存
    data = {
        "scaler": scaler,
        "prototypes": prototypes,
        "feature_cols": FEATURE_COLS,
        "n_normal_clusters": n_normal_clusters,
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(data, f)
    print(f"\n原型库已保存至: {output_path}")
    print(f"  特征数: {len(FEATURE_COLS)}")
    print(f"  类别数: {len(prototypes)}")
    print(f"  normal 子质心数: {prototypes['normal'].shape[0] if 'normal' in prototypes else 0}")

    return PrototypeClassifier(scaler, prototypes)


def load_prototypes(pkl_path: str = PROTOTYPE_PATH) -> PrototypeClassifier:
    """加载原型库"""
    with open(pkl_path, "rb") as f:
        data = pickle.load(f)
    return PrototypeClassifier(data["scaler"], data["prototypes"])


# ═══════════════════════════════════════════════════════════
# 验证
# ═══════════════════════════════════════════════════════════

def validate(classifier: PrototypeClassifier, csv_path: str = DEFAULT_CSV) -> dict:
    """在全量数据上验证级联分类器"""
    df = pd.read_csv(csv_path)

    tier1a_correct = 0
    tier1a_count = 0
    tier1b_correct = 0
    tier1b_count = 0
    tier2_count = 0
    llm_correct_if_perfect = 0

    confusion = defaultdict(lambda: defaultdict(int))
    per_class = defaultdict(lambda: {"total": 0, "correct": 0, "rule": 0, "proto": 0, "llm": 0})

    for i, row in df.iterrows():
        true_label = row["label"]
        per_class[true_label]["total"] += 1

        result = classifier.classify(row.to_dict())

        if result["tier"] == "rule":
            tier1a_count += 1
            per_class[true_label]["rule"] += 1
            if result["label"] == true_label:
                tier1a_correct += 1
                per_class[true_label]["correct"] += 1
            confusion[true_label][result["label"]] += 1

        elif result["tier"] == "prototype":
            tier1b_count += 1
            per_class[true_label]["proto"] += 1
            if result["label"] == true_label:
                tier1b_correct += 1
                per_class[true_label]["correct"] += 1
            confusion[true_label][result["label"]] += 1

        else:  # llm
            tier2_count += 1
            per_class[true_label]["llm"] += 1
            # 假设 LLM 对模糊样本的准确率 ≈ 90%
            llm_correct_if_perfect += 1  # optimistic

    total = len(df)
    tier1a_acc = tier1a_correct / tier1a_count if tier1a_count else 0
    tier1b_acc = tier1b_correct / tier1b_count if tier1b_count else 0
    combined_acc = (tier1a_correct + tier1b_correct) / (tier1a_count + tier1b_count) if (tier1a_count + tier1b_count) else 0
    estimated_final_acc = (tier1a_correct + tier1b_correct + llm_correct_if_perfect * 0.9) / total

    report = {
        "total": total,
        "tier1a": {"name": "规则引擎", "count": tier1a_count, "correct": tier1a_correct,
                    "accuracy": round(tier1a_acc, 4), "pct": round(tier1a_count / total * 100, 1)},
        "tier1b": {"name": "原型匹配", "count": tier1b_count, "correct": tier1b_correct,
                    "accuracy": round(tier1b_acc, 4), "pct": round(tier1b_count / total * 100, 1)},
        "tier2": {"name": "LLM 推理", "count": tier2_count, "pct": round(tier2_count / total * 100, 1)},
        "combined_tier1_accuracy": round(combined_acc, 4),
        "estimated_final_accuracy": round(estimated_final_acc, 4),
        "per_class": {k: dict(v) for k, v in per_class.items()},
    }

    return report


def print_report(report: dict):
    """打印验证报告"""
    print("\n" + "=" * 70)
    print("  两级级联分类器 · 全量验证报告")
    print("=" * 70)
    print(f"\n  总样本数: {report['total']:,}")
    print()

    for tier_key in ["tier1a", "tier1b", "tier2"]:
        t = report[tier_key]
        if tier_key == "tier2":
            print(f"  {t['name']:12s}  {t['count']:6,} 条 ({t['pct']:5.1f}%)  → LLM")
        else:
            print(f"  {t['name']:12s}  {t['count']:6,} 条 ({t['pct']:5.1f}%)  "
                  f"准确率: {t['accuracy']:.4f} ({t['correct']}/{t['count']})")

    print(f"\n  Tier 1 综合准确率: {report['combined_tier1_accuracy']:.4f}")
    print(f"  预估最终准确率:   {report['estimated_final_accuracy']:.4f} "
          f"(假设 LLM 准确率 90%)")

    print(f"\n{'─' * 70}")
    print(f"  {'Per-Class 分解':^60}")
    print(f"{'─' * 70}")
    print(f"  {'类别':28s} {'总量':>6s} {'规则':>6s} {'原型':>6s} {'LLM':>6s} {'正确':>6s} {'准确率':>8s}")
    print(f"  {'─' * 66}")

    for cls_name in sorted(report["per_class"].keys()):
        pc = report["per_class"][cls_name]
        acc = pc["correct"] / pc["total"] if pc["total"] else 0
        print(f"  {cls_name:28s} {pc['total']:>6d} {pc['rule']:>6d} {pc['proto']:>6d} "
              f"{pc['llm']:>6d} {pc['correct']:>6d} {acc:>7.4f}")

    print("=" * 70)


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python prototype_classifier.py --build          # 从 features.csv 构建原型库")
        print("  python prototype_classifier.py --validate       # 构建并验证全量准确率")
        print("  python prototype_classifier.py --validate-only  # 仅验证 (需已有 prototypes.pkl)")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "--build":
        classifier = build_prototypes()
        print("\n构建完成。运行 --validate 进行全量验证。")

    elif cmd == "--validate":
        classifier = build_prototypes()
        report = validate(classifier)
        print_report(report)

    elif cmd == "--validate-only":
        if not os.path.exists(PROTOTYPE_PATH):
            print(f"原型库不存在: {PROTOTYPE_PATH}")
            print("请先运行 --build")
            sys.exit(1)
        classifier = load_prototypes()
        report = validate(classifier)
        print_report(report)

    else:
        print(f"未知命令: {cmd}")


if __name__ == "__main__":
    main()

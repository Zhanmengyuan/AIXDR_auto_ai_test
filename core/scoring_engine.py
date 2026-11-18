"""
评分引擎 (Scoring Engine)

将各智能体的原始指标值，通过归一化公式转为 0~100 标准分，
再按维度归并、按类型加权，最终得到综合分和评级。

四层计算：
  第一层：指标归一化（原始值 → 0~100 标准分）
  第二层：维度归并（同维度内标准分取均值 → 维度分）
  第三层：智能体综合分（维度分按类型权重加权 → 综合分）
  第四层：整体综合分（类内均值 → 类间等权 → 整体分）
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ════════════════════════════════════════════════════════
# 第一层：归一化公式
# ════════════════════════════════════════════════════════

def normalize_higher_better(raw: float, best: float = 1.0, worst: float = 0.0) -> float:
    """越高越好：raw=best → 100分, raw=worst → 0分

    公式：score = raw ÷ best × 100
    超过best截断为100，低于worst截断为0

    适用：准确率、F1、合规率等

    >>> normalize_higher_better(0.977, 1.0, 0.0)
    97.7
    >>> normalize_higher_better(0.98, 1.0, 0.0)
    98.0
    """
    if best == worst:
        return 100.0 if raw >= best else 0.0
    score = raw / best * 100
    return max(0.0, min(100.0, score))


# 注：性能指标（响应时间）不算分，只展示原始值，不需要归一化


def normalize_pass_fail(pass_count: int, total: int) -> float:
    """通过率：pass_count / total × 100

    适用：稳定性成功率、执行成功率等

    >>> normalize_pass_fail(47, 50)
    94.0
    """
    if total == 0:
        return 0.0
    return pass_count / total * 100


def normalize_score_based(raw_score: float, max_score: float = 100.0) -> float:
    """已有评分制：raw_score / max_score × 100

    适用：LLM审查100分制、处置建议合理性100分制等

    >>> normalize_score_based(92, 100)
    92.0
    """
    if max_score == 0:
        return 0.0
    return max(0.0, min(100.0, raw_score / max_score * 100))


# ════════════════════════════════════════════════════════
# 检测研判类 F1 二分类计算（框架从黑白样本数量计算）
# ════════════════════════════════════════════════════════

def calculate_f1_from_samples(
    black_samples: int,
    black_correct: int,
    white_samples: int,
    white_correct: int,
) -> Dict[str, Any]:
    """从黑白样本数量计算二分类F1及黑白样本准确率

    Args:
        black_samples: 黑样本总数（正报样本）
        black_correct: 黑样本判定正确数
        white_samples: 白样本总数（误报样本）
        white_correct: 白样本判定正确数

    Returns:
        {
            "f1": F1值,
            "precision": 精确率,
            "recall": 召回率,
            "black_accuracy": 黑样本准确率,
            "white_accuracy": 白样本准确率,
            "tp": TP, "fn": FN, "fp": FP, "tn": TN,
        }

    示例（WAF降噪）:
        >>> result = calculate_f1_from_samples(300, 291, 300, 295)
        >>> result["f1"]
        0.9765
        >>> result["black_accuracy"]
        0.97
        >>> result["white_accuracy"]
        0.9833
    """
    tp = black_correct                          # 黑样本正确判定（正报正确）
    fn = black_samples - black_correct           # 黑样本漏判（正报判错）
    fp = white_samples - white_correct            # 白样本误判（误报复判为正报）
    tn = white_correct                           # 白样本正确判定（误报正确）

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    black_accuracy = black_correct / black_samples if black_samples > 0 else 0.0
    white_accuracy = white_correct / white_samples if white_samples > 0 else 0.0

    return {
        "f1_score": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "black_accuracy": round(black_accuracy, 4),
        "white_accuracy": round(white_accuracy, 4),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


# ════════════════════════════════════════════════════════
# 第二层：维度归并
# ════════════════════════════════════════════════════════

@dataclass
class MetricScore:
    """单个指标归一化后的标准分"""
    dimension: str
    key: str
    name_cn: str
    raw_value: Any
    standard_score: float
    detail: Dict[str, Any] = field(default_factory=dict)


def aggregate_dimension_scores(metric_scores: List[MetricScore]) -> Dict[str, float]:
    """同维度内标准分取均值，得到维度分

    返回 {dimension: score}

    >>> metrics = [
    ...     MetricScore("accuracy", "acc", "准确率", 0.98, 98.0),
    ...     MetricScore("accuracy", "f1", "F1", 0.97, 97.0),
    ...     MetricScore("performance", "time", "响应时间", 0.2, 96.0),
    ... ]
    >>> aggregate_dimension_scores(metrics)
    {'accuracy': 97.5, 'performance': 96.0}
    """
    dim_scores: Dict[str, List[float]] = {}
    for m in metric_scores:
        if m.dimension not in dim_scores:
            dim_scores[m.dimension] = []
        dim_scores[m.dimension].append(m.standard_score)

    result = {}
    for dim, scores in dim_scores.items():
        result[dim] = sum(scores) / len(scores)
    return result


# ════════════════════════════════════════════════════════
# 第三层：智能体综合分
# ════════════════════════════════════════════════════════

WEIGHT_PROFILES = {
    "detect":  {"accuracy": 90, "reliability": 5, "content_quality": 5},
    "generate": {"accuracy": 70, "reliability": 15, "content_quality": 15},
    "query":   {"accuracy": 80, "reliability": 10, "content_quality": 10},
    "qa":      {"accuracy": 90, "reliability": 5, "content_quality": 5},
}


def calculate_agent_score(
    dimension_scores: Dict[str, float],
    category: str,
) -> Tuple[float, Dict[str, float]]:
    """计算单智能体综合分（缺失维度排除，分母调整）

    performance维度不算分，只展示原始值。

    返回 (综合分, 各维度权重贡献明细)

    示例（告警解读，generate类）:
        dimension_scores = {"accuracy": 99, "reliability": 94, "content_quality": 94}
        weights = {"accuracy": 35, "reliability": 20, "content_quality": 35, "performance": 10}
        total_weight = 35+20+35+10 = 100
        score = (99*35 + 94*20 + 94*35 + 96*10) / 100 = 95.85

    示例（资产解读，generate类，无reliability）:
        dimension_scores = {"accuracy": 100, "content_quality": 88, "performance": 89}
        weights = {"accuracy": 35, "content_quality": 35, "performance": 10}
        total_weight = 35+35+10 = 80 (排除reliability的20)
        score = (100*35 + 88*35 + 89*10) / 80 = 92.625
    """
    weights = WEIGHT_PROFILES.get(category, WEIGHT_PROFILES["generate"])

    total_weight = 0
    weighted_sum = 0.0
    detail = {}

    for dim, score in dimension_scores.items():
        w = weights.get(dim, 0)
        if w > 0:
            total_weight += w
            weighted_sum += score * w
            detail[dim] = {"score": round(score, 1), "weight": w, "weighted": round(score * w, 1)}

    if total_weight == 0:
        return 0.0, detail

    final_score = weighted_sum / total_weight
    return round(final_score, 1), detail


# ════════════════════════════════════════════════════════
# 第四层：整体综合分（类内均值 → 类间等权）
# ════════════════════════════════════════════════════════

def calculate_overall_scores(
    agent_scores_by_category: Dict[str, List[float]],
) -> Dict[str, float]:
    """计算整体维度分和综合分（类间等权法）

    第一步：类内均值（同类内各智能体综合分取均值）
    第二步：类间等权均值（4类权重相等）

    返回:
        {
            "overall": 整体综合分,
            "category_scores": {category: 类内均值},
            "overall_dimensions": {dim: 维度分}  (如果传入维度数据)
        }

    示例:
        agent_scores_by_category = {
            "detect":  [97, 96, 91, 83, 95],      → mean = 92.4
            "generate": [96, 96, 93, 88, 89],     → mean = 92.4
            "query":   [89, 88],                  → mean = 88.5
            "qa":      [85],                      → mean = 85.0
        }
        overall = mean(92.4, 92.4, 88.5, 85.0) = 89.6
    """
    category_means = {}
    for cat, scores in agent_scores_by_category.items():
        if scores:
            category_means[cat] = sum(scores) / len(scores)

    if category_means:
        overall = sum(category_means.values()) / len(category_means)
    else:
        overall = 0.0

    return {
        "overall": round(overall, 1),
        "category_scores": {k: round(v, 1) for k, v in category_means.items()},
    }


def calculate_overall_dimension_scores(
    dimension_scores_by_category: Dict[str, Dict[str, List[float]]],
) -> Dict[str, float]:
    """计算各维度的整体分（类间等权法）

    输入: {category: {dimension: [agent1_score, agent2_score, ...]}}
    输出: {dimension: overall_score}

    示例:
        {
            "detect":  {"accuracy": [97, 97, 90, 83, 91], "reliability": [100, 98, 94, 89, 100], ...},
            "generate": {"accuracy": [99, 99, 100, None, 93], ...},
            "query":   {"accuracy": [91, 86], ...},
            "qa":      {"accuracy": [85], ...},
        }
        accuracy:
            detect mean = mean(97,97,90,83,91) = 91.6
            generate mean = mean(99,99,100,93) = 97.75  (排除None)
            query mean = mean(91,86) = 88.5
            qa mean = 85
            overall accuracy = mean(91.6, 97.75, 88.5, 85) = 90.7
    """
    all_dimensions = set()
    for cat_dims in dimension_scores_by_category.values():
        all_dimensions.update(cat_dims.keys())

    result = {}
    for dim in all_dimensions:
        category_means = []
        for cat, dims in dimension_scores_by_category.items():
            if dim in dims:
                valid_scores = [s for s in dims[dim] if s is not None]
                if valid_scores:
                    category_means.append(sum(valid_scores) / len(valid_scores))
        if category_means:
            result[dim] = round(sum(category_means) / len(category_means), 1)

    return result


# ════════════════════════════════════════════════════════
# 评级
# ════════════════════════════════════════════════════════

def calculate_rating(score: float, dimension_scores: Dict[str, float] = None) -> str:
    """计算评级（短板锁定 + 红线）

    规则:
        S: 综合分 ≥ 90 且 所有维度 ≥ 85
        A: 综合分 ≥ 80 且 所有维度 ≥ 70
        B: 综合分 ≥ 70 且 所有维度 ≥ 60
        C: 综合分 ≥ 60
        D: 综合分 < 60 或 任意维度 < 60
    """
    dimension_scores = dimension_scores or {}
    min_dim = min(dimension_scores.values()) if dimension_scores else 100

    if score < 60 or min_dim < 60:
        return "D"
    if score < 70:
        return "C"
    if score < 80 or min_dim < 70:
        return "B"
    if score < 90 or min_dim < 85:
        return "A"
    return "S"


# ════════════════════════════════════════════════════════
# 版本对比
# ════════════════════════════════════════════════════════

SIGNIFICANT_THRESHOLDS = {
    "accuracy_rate": 2.0,
    "f1": 0.02,
    "time_percent": 10.0,
    "llm_score": 3.0,
}


def compare_metric(old_value: float, new_value: float, metric_type: str = "accuracy_rate") -> Dict[str, Any]:
    """逐指标对比，返回变化方向和幅度

    返回: {"direction": "up/down/flat", "delta": delta_value, "significant": bool}
    """
    delta = new_value - old_value
    threshold = SIGNIFICANT_THRESHOLDS.get(metric_type, 2.0)

    if metric_type == "time_percent":
        old_base = old_value if old_value != 0 else 1
        delta_pct = abs(delta) / abs(old_base) * 100
        significant = delta_pct > threshold
    elif metric_type == "f1":
        significant = abs(delta) > threshold
    elif metric_type == "llm_score":
        significant = abs(delta) > threshold
    else:
        significant = abs(delta) > threshold

    if abs(delta) < 0.01:
        direction = "flat"
    elif delta > 0:
        direction = "up"
    else:
        direction = "down"

    return {
        "direction": direction,
        "delta": round(delta, 2),
        "significant": significant,
    }


def version_decision(
    metrics_comparison: List[Dict[str, Any]],
    guardrail_triggered: bool,
) -> str:
    """版本判定

    输入: 所有指标的对比结果 + 是否有门禁触发

    返回: "建议升级" / "谨慎升级" / "不建议升级"
    """
    up_count = sum(1 for m in metrics_comparison if m["direction"] == "up" and m["significant"])
    down_count = sum(1 for m in metrics_comparison if m["direction"] == "down" and m["significant"])

    if guardrail_triggered or down_count > up_count:
        return "不建议升级"
    if up_count >= 3 and down_count <= 2 and not guardrail_triggered:
        return "建议升级"
    return "谨慎升级"

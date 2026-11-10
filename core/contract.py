"""
标准结果契约层 (StandardResult Contract)

定义所有智能体测试结果的统一数据结构，是整个测试框架的地基。
无论 Pull 模式（框架主动调AI）还是 Push 模式（其他团队推结果），
最终都归一为 StandardResult，供调度内核聚合、报告门户展示。

维度标签体系：
    - accuracy    准确性（AI输出与基准真值是否一致）
    - performance 性能（响应时间、吞吐）
    - stability   稳定性（同输入多次执行结论一致性）
    - compliance  合规审查（LLM审查评分、格式规范、推荐问题质量）
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── 维度常量 ──────────────────────────────────────────────
DIMENSION_ACCURACY = "accuracy"
DIMENSION_PERFORMANCE = "performance"
DIMENSION_STABILITY = "stability"
DIMENSION_COMPLIANCE = "compliance"

ALL_DIMENSIONS = [
    DIMENSION_ACCURACY,
    DIMENSION_PERFORMANCE,
    DIMENSION_STABILITY,
    DIMENSION_COMPLIANCE,
]

# ── 样本状态常量 ──────────────────────────────────────────
STATUS_VALID = "valid"      # 有效样本，参与指标计算
STATUS_FAILED = "failed"    # AI调用失败，不参与指标计算
STATUS_INVALID = "invalid"  # API查不到业务数据，不参与指标计算


@dataclass
class Metric:
    """单个指标结果

    每个指标都带 dimension 标签，使调度内核能按维度裁剪执行。
    """
    dimension: str               # accuracy / performance / stability / compliance
    key: str                     # 指标标识，如 "threat_determination_accuracy"
    name_cn: str                 # 中文名，如 "威胁定性准确率"
    value: Any = None            # AI解读值
    expected: Any = None         # 基准真值
    accuracy: Optional[float] = None  # 0~1，None=提取失败（不计入均值）
    passed: bool = False         # 是否通过
    score: Optional[float] = None     # 得分（部分指标有）
    max_score: Optional[float] = None # 满分（部分指标有）
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "key": self.key,
            "name_cn": self.name_cn,
            "value": self.value,
            "expected": self.expected,
            "accuracy": self.accuracy,
            "passed": self.passed,
            "score": self.score,
            "max_score": self.max_score,
            "detail": self.detail,
        }


@dataclass
class StandardResult:
    """智能体测试标准结果

    所有智能体（无论接入模式）的测试结果都归一为此结构。
    这是框架内部流转和提供给其他团队的"规定返回结构"。
    """
    # ── 身份标识 ──
    agent_id: str                # 智能体唯一标识，如 "ai_interpret_alarm"
    case_id: str                 # 测试用例编号，如 "alarm_test_01"
    sample_id: str               # 业务样本ID，如 "7927904014451048448"
    run_id: str                  # 本次批次ID（时间戳），用于聚合归档

    # ── 样本分类 ──
    status: str = STATUS_VALID   # valid / failed / invalid

    # ── 响应性能（Pull模式有值，Push模式可选）──
    first_packet_time: float = 0.0
    total_response_time: float = 0.0

    # ── 维度化指标列表 ──
    metrics: List[Metric] = field(default_factory=list)

    # ── 溯源 ──
    raw_text: str = ""           # AI原始输出
    error: str = ""              # 失败/失效原因
    timestamp: str = ""          # 结果生成时间

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "case_id": self.case_id,
            "sample_id": self.sample_id,
            "run_id": self.run_id,
            "status": self.status,
            "first_packet_time": self.first_packet_time,
            "total_response_time": self.total_response_time,
            "metrics": [m.to_dict() if isinstance(m, Metric) else m for m in self.metrics],
            "raw_text": self.raw_text,
            "error": self.error,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StandardResult":
        """从字典构造（Push模式下接收JSON反序列化用）"""
        metrics_data = data.get("metrics", [])
        metrics = []
        for m in metrics_data:
            if isinstance(m, Metric):
                metrics.append(m)
            elif isinstance(m, dict):
                metrics.append(Metric(
                    dimension=m.get("dimension", ""),
                    key=m.get("key", ""),
                    name_cn=m.get("name_cn", ""),
                    value=m.get("value"),
                    expected=m.get("expected"),
                    accuracy=m.get("accuracy"),
                    passed=m.get("passed", False),
                    score=m.get("score"),
                    max_score=m.get("max_score"),
                    detail=m.get("detail", {}),
                ))
        return cls(
            agent_id=data.get("agent_id", ""),
            case_id=data.get("case_id", ""),
            sample_id=data.get("sample_id", ""),
            run_id=data.get("run_id", ""),
            status=data.get("status", STATUS_VALID),
            first_packet_time=data.get("first_packet_time", 0.0),
            total_response_time=data.get("total_response_time", 0.0),
            metrics=metrics,
            raw_text=data.get("raw_text", ""),
            error=data.get("error", ""),
            timestamp=data.get("timestamp", ""),
        )


def metric_from_calculator_result(
    metric_dict: Dict[str, Any],
    dimension: str,
) -> Metric:
    """从现有计算器产出的 dict 构造 Metric

    现有 MetricResult.to_dict() 产出的结构:
        {metric_name, metric_cn, score, max_score, accuracy, ai_value, api_value, detail, is_passed}
    以及额外的标记字段: is_extraction_failure

    Args:
        metric_dict: MetricResult.to_dict() 的输出，或 RecommendQuestionCalculator 的返回
        dimension: 该指标所属的维度

    Returns:
        Metric: 统一指标结构
    """
    return Metric(
        dimension=dimension,
        key=metric_dict.get("metric_name", metric_dict.get("key", "")),
        name_cn=metric_dict.get("metric_cn", metric_dict.get("name_cn", "")),
        value=metric_dict.get("ai_value", metric_dict.get("value")),
        expected=metric_dict.get("api_value", metric_dict.get("expected")),
        accuracy=metric_dict.get("accuracy"),
        passed=metric_dict.get("is_passed", metric_dict.get("passed", False)),
        score=metric_dict.get("score"),
        max_score=metric_dict.get("max_score"),
        detail=metric_dict.get("detail", {}),
    )

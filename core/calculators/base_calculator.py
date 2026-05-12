"""
计算器基类
定义指标计算的接口和通用方法
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class MetricResult:
    """指标计算结果"""
    metric_name: str
    metric_cn: str
    score: float
    max_score: float
    accuracy: float
    ai_value: Any
    api_value: Any
    detail: Dict[str, Any]
    is_passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "metric_cn": self.metric_cn,
            "score": self.score,
            "max_score": self.max_score,
            "accuracy": self.accuracy,
            "ai_value": self.ai_value,
            "api_value": self.api_value,
            "detail": self.detail,
            "is_passed": self.is_passed
        }


class BaseCalculator:
    """指标计算器基类"""

    METRIC_NAME = ""
    METRIC_CN = ""
    MAX_SCORE = 0

    def __init__(self, threshold: float = 1.0):
        self.threshold = threshold

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算指标

        Args:
            ai_data: AI解析的数据
            api_data: API获取的标准数据

        Returns:
            MetricResult: 指标计算结果
        """
        raise NotImplementedError

    def _create_result(
        self,
        ai_value: Any,
        api_value: Any,
        accuracy: float,
        detail: Dict[str, Any]
    ) -> MetricResult:
        """创建指标结果"""
        score = accuracy * self.MAX_SCORE
        is_passed = accuracy >= self.threshold

        return MetricResult(
            metric_name=self.METRIC_NAME,
            metric_cn=self.METRIC_CN,
            score=score,
            max_score=self.MAX_SCORE,
            accuracy=accuracy,
            ai_value=ai_value,
            api_value=api_value,
            detail=detail,
            is_passed=is_passed
        )

    def _normalize_value(self, value: Any) -> str:
        """标准化值用于比较"""
        if value is None:
            return ""
        return str(value).strip()

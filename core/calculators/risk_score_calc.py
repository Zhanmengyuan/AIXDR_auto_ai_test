"""
资产风险评分准确率计算器
计算AI识别的风险评分与API标准的误差
"""
from typing import Any, Dict
from .base_calculator import BaseCalculator, MetricResult


class RiskScoreCalculator(BaseCalculator):
    """资产风险评分准确率计算器"""

    METRIC_NAME = "risk_score_accuracy"
    METRIC_CN = "资产风险评分准确率"
    MAX_SCORE = 10
    THRESHOLD = 5

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算风险评分准确率

        逻辑：
        - |AI评分 - API评分| ≤ 5分 = 100%
        - 误差越大，准确率越低
        """
        ai_score = self._parse_score(ai_data.get('risk_score'))
        api_score = self._parse_score(api_data.get('risk_score'))

        if ai_score is None or api_score is None:
            accuracy = 0.0
            error = None
        else:
            error = abs(ai_score - api_score)
            if error == 0:
                accuracy = 1.0
            elif error <= self.THRESHOLD:
                accuracy = 1.0
            else:
                accuracy = max(0.0, 1.0 - (error - self.THRESHOLD) / 50)

        detail = {
            "ai_score": ai_score,
            "api_score": api_score,
            "error": error,
            "threshold": self.THRESHOLD
        }

        return self._create_result(
            ai_value=ai_score,
            api_value=api_score,
            accuracy=accuracy,
            detail=detail
        )

    def _parse_score(self, value: Any) -> int:
        """解析评分"""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            import re
            match = re.search(r'\d+', value)
            return int(match.group()) if match else None
        return None

"""
风险等级准确率计算器
计算AI识别的风险等级与API标准是否一致（多分类）
"""
from typing import Any, Dict
from .base_calculator import BaseCalculator, MetricResult


class RiskLevelCalculator(BaseCalculator):
    """风险等级准确率计算器"""

    METRIC_NAME = "risk_level_accuracy"
    METRIC_CN = "风险等级准确率"
    MAX_SCORE = 20

    RISK_LEVELS = ['严重', '高危', '中危', '低危', '一般']

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算风险等级准确率

        逻辑：
        - AI识别的风险等级与API标准完全一致 = 100%
        - 不一致 = 0%
        """
        ai_risk = ai_data.get('risk_level')
        api_risk = api_data.get('risk_level')

        ai_risk_normalized = self._normalize_risk(ai_risk)
        api_risk_normalized = self._normalize_risk(api_risk)

        is_match = ai_risk_normalized == api_risk_normalized if (ai_risk and api_risk) else False

        accuracy = 1.0 if is_match else 0.0

        detail = {
            "ai_risk": ai_risk,
            "api_risk": api_risk,
            "ai_risk_normalized": ai_risk_normalized,
            "api_risk_normalized": api_risk_normalized,
            "is_match": is_match
        }

        return self._create_result(
            ai_value=ai_risk,
            api_value=api_risk,
            accuracy=accuracy,
            detail=detail
        )

    def _normalize_risk(self, risk: str) -> str:
        """标准化风险等级"""
        if not risk:
            return ""
        risk = str(risk).strip()
        for level in self.RISK_LEVELS:
            if level in risk:
                return level
        return risk

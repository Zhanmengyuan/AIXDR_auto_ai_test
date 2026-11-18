"""
风险等级加权准确率计算器
计算AI识别的风险等级与API标准是否一致（多分类）
采用加权准确率（正确样本数/总样本数），适合真实业务不均衡分布
注：宏平均F1需各类别≥30个样本且分布均衡，不适用于真实业务数据
"""
from typing import Any, Dict, List, Tuple
from .base_calculator import BaseCalculator, MetricResult


class RiskLevelCalculator(BaseCalculator):
    """风险等级准确率计算器"""

    METRIC_NAME = "risk_level_accuracy"
    METRIC_CN = "风险等级准确率"
    MAX_SCORE = 20
    DIMENSION = "accuracy"
    EXPECTED_F1 = 0.95
    DEDUCTION_INTERVAL = 0.05
    DEDUCTION_AMOUNT = 5

    RISK_LEVELS = ['严重', '高危', '中危', '低危', '健康']

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算风险等级准确率（单次）

        逻辑：完全一致 = 1.0，不一致 = 0.0
        多样本时取均值即为加权准确率（正确样本数/总样本数）
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

    def calculate_batch(self, results: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> MetricResult:
        """批量计算风险等级宏平均F1

        Args:
            results: [(ai_data, api_data), ...] 列表

        Returns:
            宏平均F1 MetricResult
        """
        y_true = []
        y_pred = []

        for ai_data, api_data in results:
            ai_risk = ai_data.get('risk_level')
            api_risk = api_data.get('risk_level')

            ai_risk_normalized = self._normalize_risk(ai_risk)
            api_risk_normalized = self._normalize_risk(api_risk)

            y_pred.append(ai_risk_normalized)
            y_true.append(api_risk_normalized)

        macro_f1 = self._calculate_macro_f1(y_true, y_pred)

        score = self._calculate_score(macro_f1)

        ai_risks = [r[0].get('risk_level') for r in results]
        api_risks = [r[1].get('risk_level') for r in results]

        detail = {
            "macro_f1": macro_f1,
            "expected_f1": self.EXPECTED_F1,
            "total_samples": len(results),
            "ai_risks": ai_risks,
            "api_risks": api_risks,
            "y_true": y_true,
            "y_pred": y_pred
        }

        return MetricResult(
            metric_name=self.METRIC_NAME,
            metric_cn=self.METRIC_CN,
            score=score,
            max_score=self.MAX_SCORE,
            accuracy=macro_f1,
            ai_value=f"{macro_f1:.4f}",
            api_value=f">={self.EXPECTED_F1}",
            detail=detail,
            is_passed=macro_f1 >= self.EXPECTED_F1
        )

    def _calculate_macro_f1(self, y_true: List[str], y_pred: List[str]) -> float:
        """计算多分类宏平均F1

        Args:
            y_true: 真实标签列表
            y_pred: 预测标签列表

        Returns:
            宏平均F1分数
        """
        all_labels = set(y_true + y_pred)
        all_labels.discard("")
        labels = [l for l in self.RISK_LEVELS if l in all_labels]

        if not labels:
            return 0.0

        f1_scores = []

        for label in labels:
            tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
            fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
            fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            f1_scores.append(f1)

        macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0.0
        return macro_f1

    def _calculate_score(self, macro_f1: float) -> float:
        """根据宏平均F1计算得分

        评分规则：
        - F1 >= 0.95: 满分20分
        - 每低于期望值0.05扣5分
        - 最低0分

        Args:
            macro_f1: 宏平均F1

        Returns:
            得分
        """
        if macro_f1 >= self.EXPECTED_F1:
            return float(self.MAX_SCORE)

        deduction = ((self.EXPECTED_F1 - macro_f1) / self.DEDUCTION_INTERVAL) * self.DEDUCTION_AMOUNT
        score = self.MAX_SCORE - deduction

        return max(0.0, score)

    def _normalize_risk(self, risk: str) -> str:
        """标准化风险等级"""
        if not risk:
            return ""
        risk = str(risk).strip()
        for level in self.RISK_LEVELS:
            if level in risk:
                return level
        return risk

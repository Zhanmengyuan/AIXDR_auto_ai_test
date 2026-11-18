"""
CVSS 评分误差计算器
计算 AI 输出的 CVSS 评分与标准值的误差
"""
from typing import Any, Dict, List, Tuple
from .base_calculator import BaseCalculator, MetricResult


class CVSSCalculator(BaseCalculator):
    """CVSS 评分误差计算器"""

    METRIC_NAME = "cvss_score_error"
    METRIC_CN = "CVSS 评分误差"
    MAX_SCORE = 15
    DIMENSION = "accuracy"
    EXPECTED_ERROR = 0.3

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算单个 CVSS 评分误差"""
        ai_cvss = self._extract_cvss(ai_data)
        api_cvss = self._extract_cvss(api_data)

        if ai_cvss is None or api_cvss is None:
            return self._create_result(
                ai_value=ai_cvss,
                api_value=api_cvss,
                accuracy=0.0,
                detail={"error": "缺少 CVSS 评分数据"}
            )

        error = abs(ai_cvss - api_cvss)
        accuracy = max(0.0, 1.0 - error / 10.0)

        detail = {
            "ai_cvss": ai_cvss,
            "api_cvss": api_cvss,
            "error": error,
            "expected_error": self.EXPECTED_ERROR
        }

        return self._create_result(
            ai_value=ai_cvss,
            api_value=api_cvss,
            accuracy=accuracy,
            detail=detail
        )

    def calculate_batch(self, results: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> MetricResult:
        """批量计算 CVSS 评分平均误差"""
        errors = []
        pairs = []

        for ai_data, api_data in results:
            ai_cvss = self._extract_cvss(ai_data)
            api_cvss = self._extract_cvss(api_data)

            if ai_cvss is not None and api_cvss is not None:
                error = abs(ai_cvss - api_cvss)
                errors.append(error)
                pairs.append((ai_cvss, api_cvss))

        if not errors:
            return MetricResult(
                metric_name=self.METRIC_NAME,
                metric_cn=self.METRIC_CN,
                score=0.0,
                max_score=self.MAX_SCORE,
                accuracy=0.0,
                ai_value="N/A",
                api_value="N/A",
                detail={"error": "没有有效的 CVSS 评分数据"},
                is_passed=False
            )

        avg_error = sum(errors) / len(errors)
        accuracy = max(0.0, 1.0 - avg_error / 10.0)
        score = self._calculate_score(avg_error)

        detail = {
            "avg_error": avg_error,
            "expected_error": self.EXPECTED_ERROR,
            "total_samples": len(results),
            "valid_samples": len(errors),
            "pairs": pairs
        }

        return MetricResult(
            metric_name=self.METRIC_NAME,
            metric_cn=self.METRIC_CN,
            score=score,
            max_score=self.MAX_SCORE,
            accuracy=accuracy,
            ai_value=f"{avg_error:.2f}",
            api_value=f"≤{self.EXPECTED_ERROR}",
            detail=detail,
            is_passed=avg_error <= self.EXPECTED_ERROR
        )

    def _extract_cvss(self, data: Dict[str, Any]) -> float:
        """从数据中提取 CVSS 评分"""
        if not data:
            return None

        cvss_keys = ["cvss_score", "cvss", "CVSS评分", "CVSS"]
        for key in cvss_keys:
            if key in data and data[key] is not None:
                try:
                    return float(data[key])
                except (ValueError, TypeError):
                    continue

        return None

    def _calculate_score(self, avg_error: float) -> float:
        """根据平均误差计算得分"""
        if avg_error <= self.EXPECTED_ERROR:
            return float(self.MAX_SCORE)
        elif avg_error <= 1.0:
            return self.MAX_SCORE * (1.0 - (avg_error - self.EXPECTED_ERROR) / (1.0 - self.EXPECTED_ERROR))
        elif avg_error <= 2.0:
            return self.MAX_SCORE * 0.5 * (1.0 - (avg_error - 1.0))
        else:
            return 0.0

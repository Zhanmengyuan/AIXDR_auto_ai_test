"""
漏洞列表准确率计算器
计算AI识别的漏洞列表与API查询结果的匹配准确率
"""
from typing import Any, Dict, List, Set
from .base_calculator import BaseCalculator, MetricResult


class VulnAccuracyCalculator(BaseCalculator):
    """漏洞列表准确率计算器"""

    METRIC_NAME = "vuln_accuracy"
    METRIC_CN = "漏洞列表准确率"
    MAX_SCORE = 10
    DIMENSION = "accuracy"

    def __init__(self, threshold: float = 1.0):
        super().__init__(threshold)

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算漏洞列表准确率

        逻辑：
        - AI返回最多5个漏洞ID（最关键的）
        - 检查AI返回的漏洞ID是否在API列表中存在
        - 准确率 = 匹配数 / AI返回数

        评分：
        - 0个错误: 100%
        - 1个错误: 80%
        - 2个错误: 60%
        - 3个错误: 40%
        - 4个错误: 20%
        - 5个错误: 0%
        """
        ai_vulns = self._to_list(ai_data.get('vuln_list', []))
        api_vulns = self._to_list(api_data.get('vuln_list', []))

        if not api_vulns:
            api_vulns = api_data.get('vuln_ids', [])

        api_vuln_set = set(self._normalize(v) for v in api_vulns)

        matched = []
        extra = []

        for vuln in ai_vulns:
            norm_vuln = self._normalize(vuln)
            if norm_vuln in api_vuln_set:
                matched.append(vuln)
            else:
                extra.append(vuln)

        ai_count = len(ai_vulns)
        error_count = len(extra)

        if ai_count == 0:
            accuracy = 0.0
        else:
            if error_count == 0:
                accuracy = 1.0
            elif error_count == 1:
                accuracy = 0.8
            elif error_count == 2:
                accuracy = 0.6
            elif error_count == 3:
                accuracy = 0.4
            elif error_count == 4:
                accuracy = 0.2
            else:
                accuracy = 0.0

        detail = {
            "ai_count": ai_count,
            "api_count": len(api_vulns),
            "matched": len(matched),
            "error": error_count,
            "matched_vulns": matched,
            "extra_vulns": extra,
            "ai_vulns": ai_vulns,
            "api_vulns": list(api_vuln_set)
        }

        return self._create_result(
            ai_value=ai_vulns,
            api_value=list(api_vuln_set),
            accuracy=accuracy,
            detail=detail
        )

    def _to_list(self, value: Any) -> List[str]:
        """转换为列表"""
        if isinstance(value, list):
            return value
        elif isinstance(value, str):
            return [value] if value else []
        return []

    def _normalize(self, value: str) -> str:
        """标准化漏洞ID"""
        if not value:
            return ""
        v = str(value).strip().upper()
        if not v.startswith("AVE-"):
            v = f"AVE-{v}"
        return v

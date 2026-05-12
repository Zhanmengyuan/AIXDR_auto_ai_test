"""
字段完整率计算器
计算AI识别的资产关键字段完整率
"""
from typing import Any, Dict, List
from .base_calculator import BaseCalculator, MetricResult


class FieldCompletenessCalculator(BaseCalculator):
    """资产关键字段完整率计算器"""

    METRIC_NAME = "field_completeness"
    METRIC_CN = "资产关键字段完整率"
    MAX_SCORE = 10

    # 资产关键字段（10个）
    KEY_FIELDS = [
        'asset_id', 'ip_address', 'mac_address', 'hostname',
        'asset_type', 'asset_level', 'os_name', 'organization',
        'is_exposed', 'last_online_time'
    ]

    def __init__(self, threshold: float = 1.0):
        super().__init__(threshold)
        self.fields = self.KEY_FIELDS

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        """计算字段完整率

        完整率 = 识别的字段数 / 总字段数(10)
        """
        identified_fields = []
        missing_fields = []

        for field in self.fields:
            value = ai_data.get(field)
            if value is not None and str(value).strip() != "":
                identified_fields.append(field)
            else:
                missing_fields.append(field)

        completeness = len(identified_fields) / len(self.fields)

        detail = {
            "total_fields": len(self.fields),
            "identified": len(identified_fields),
            "missing": len(missing_fields),
            "identified_fields": identified_fields,
            "missing_fields": missing_fields
        }

        return self._create_result(
            ai_value=f"{len(identified_fields)}/{len(self.fields)}",
            api_value=None,
            accuracy=completeness,
            detail=detail
        )

    def calculate_with_comparison(
        self,
        ai_data: Dict[str, Any],
        api_data: Dict[str, Any]
    ) -> MetricResult:
        """计算字段完整率（带API对比）"""
        identified_fields = []
        missing_fields = []
        correct_fields = []

        for field in self.fields:
            ai_value = ai_data.get(field)
            api_value = api_data.get(field) if api_data else None

            if ai_value is not None and str(ai_value).strip() != "":
                identified_fields.append(field)
                if api_value and self._normalize_value(ai_value) == self._normalize_value(api_value):
                    correct_fields.append(field)
            else:
                missing_fields.append(field)

        completeness = len(identified_fields) / len(self.fields)

        detail = {
            "total_fields": len(self.fields),
            "identified": len(identified_fields),
            "correct": len(correct_fields),
            "missing": len(missing_fields),
            "identified_fields": identified_fields,
            "correct_fields": correct_fields,
            "missing_fields": missing_fields
        }

        return self._create_result(
            ai_value=f"{len(identified_fields)}/{len(self.fields)}",
            api_value=f"{len(correct_fields)}/{len(self.fields)}",
            accuracy=completeness,
            detail=detail
        )

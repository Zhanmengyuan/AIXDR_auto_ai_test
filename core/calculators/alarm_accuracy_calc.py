"""
关联告警准确率计算器
计算AI识别的告警列表与API查询结果的匹配准确率
"""
from typing import Any, Dict, List
from .base_calculator import BaseCalculator, MetricResult


class AlarmAccuracyCalculator(BaseCalculator):
    """关联告警准确率计算器"""

    METRIC_NAME = "alarm_accuracy"
    METRIC_CN = "关联告警准确率"
    MAX_SCORE = 5

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算告警列表准确率

        逻辑：
        - AI返回告警ID列表
        - 检查AI返回的告警ID是否在API列表中存在
        - 准确率 = 匹配数 / AI返回数

        评分：
        - 0个错误: 100%
        - 1个错误: 80%
        - 2个错误: 60%
        - 3个错误: 40%
        - 4个错误: 20%
        - 5个及以上错误: 0%
        """
        ai_alarms = self._to_list(ai_data.get('alarm_list', []))
        api_alarms = self._to_list(api_data.get('alarm_list', []))

        if not api_alarms:
            api_alarms = api_data.get('alarms', [])

        api_alarm_set = set(self._normalize(v) for v in api_alarms)

        matched = []
        extra = []

        for alarm in ai_alarms:
            norm_alarm = self._normalize(alarm)
            if norm_alarm in api_alarm_set:
                matched.append(alarm)
            else:
                extra.append(alarm)

        ai_count = len(ai_alarms)
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
            "api_count": len(api_alarms),
            "matched": len(matched),
            "error": error_count,
            "matched_alarms": matched,
            "extra_alarms": extra,
            "ai_alarms": ai_alarms,
            "api_alarms": list(api_alarm_set)
        }

        return self._create_result(
            ai_value=ai_alarms,
            api_value=list(api_alarm_set),
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
        """标准化告警ID - 移除ALE-前缀便于比较"""
        if not value:
            return ""
        v = str(value).strip()
        if v.upper().startswith("ALE-"):
            return v[4:].strip()
        return v

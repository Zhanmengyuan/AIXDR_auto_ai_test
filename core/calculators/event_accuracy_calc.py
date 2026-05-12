"""
关联事件准确率计算器
计算AI识别的事件列表与API查询结果的匹配准确率
"""
from typing import Any, Dict, List
from .base_calculator import BaseCalculator, MetricResult


class EventAccuracyCalculator(BaseCalculator):
    """关联事件准确率计算器"""

    METRIC_NAME = "event_accuracy"
    METRIC_CN = "关联事件准确率"
    MAX_SCORE = 5

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算事件列表准确率

        逻辑：
        - AI返回事件ID列表
        - 检查AI返回的事件ID是否在API列表中存在
        - 准确率 = 匹配数 / AI返回数

        评分：
        - 0个错误: 100%
        - 1个错误: 80%
        - 2个错误: 60%
        - 3个错误: 40%
        - 4个错误: 20%
        - 5个及以上错误: 0%
        """
        ai_events = self._to_list(ai_data.get('event_list', []))
        api_events = self._to_list(api_data.get('event_list', []))

        if not api_events:
            api_events = api_data.get('events', [])

        api_event_set = set(self._normalize(v) for v in api_events)

        matched = []
        extra = []

        for event in ai_events:
            norm_event = self._normalize(event)
            if norm_event in api_event_set:
                matched.append(event)
            else:
                extra.append(event)

        ai_count = len(ai_events)
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
            "api_count": len(api_events),
            "matched": len(matched),
            "error": error_count,
            "matched_events": matched,
            "extra_events": extra,
            "ai_events": ai_events,
            "api_events": list(api_event_set)
        }

        return self._create_result(
            ai_value=ai_events,
            api_value=list(api_event_set),
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
        """标准化事件ID"""
        if not value:
            return ""
        return str(value).strip()

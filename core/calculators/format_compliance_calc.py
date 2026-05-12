"""
格式合规率计算器
检查AI输出的Markdown是否包含所有必需章节
"""
import re
from typing import Any, Dict, List
from .base_calculator import BaseCalculator, MetricResult


class FormatComplianceCalculator(BaseCalculator):
    """格式合规率计算器"""

    METRIC_NAME = "format_compliance"
    METRIC_CN = "格式合规率"
    MAX_SCORE = 5

    REQUIRED_SECTIONS = [
        ("分析摘要", r'(?:1[.、]|#)\s*分析摘要'),
        ("资产总览", r'(?:2[.、]|#)\s*资产(?:信息|总览)'),
        ("关联脆弱性分析", r'(?:3[.、]|#)\s*关联脆弱性'),
        ("关联告警分析", r'(?:4[.、]|#)\s*关联告警'),
        ("关联事件分析", r'(?:5[.、]|#)\s*关联事件'),
        ("修复建议", r'(?:6[.、]|#)\s*修复建议'),
    ]

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        """计算格式合规率

        逻辑：
        - 检查Markdown是否包含所有必需章节
        - 必需章节：分析摘要、资产总览、关联脆弱性分析、关联告警分析、关联事件分析、修复建议
        - 少一节扣相应百分比 (100% / 6 ≈ 16.67%)
        """
        markdown_text = self._get_markdown_text(ai_data)

        found_sections = []
        missing_sections = []

        for section_name, pattern in self.REQUIRED_SECTIONS:
            if re.search(pattern, markdown_text, re.IGNORECASE):
                found_sections.append(section_name)
            else:
                missing_sections.append(section_name)

        total_required = len(self.REQUIRED_SECTIONS)
        found_count = len(found_sections)
        missing_count = len(missing_sections)

        compliance_rate = found_count / total_required if total_required > 0 else 0.0

        detail = {
            "total_required": total_required,
            "found_count": found_count,
            "missing_count": missing_count,
            "found_sections": found_sections,
            "missing_sections": missing_sections,
            "compliance_rate": compliance_rate
        }

        return self._create_result(
            ai_value=f"{found_count}/{total_required}",
            api_value=None,
            accuracy=compliance_rate,
            detail=detail
        )

    def _get_markdown_text(self, ai_data: Dict[str, Any]) -> str:
        """获取Markdown文本"""
        if isinstance(ai_data, str):
            return ai_data
        elif isinstance(ai_data, dict):
            if 'raw_text' in ai_data:
                return ai_data['raw_text']
            elif 'markdown' in ai_data:
                return ai_data['markdown']
            else:
                return str(ai_data)
        return str(ai_data)

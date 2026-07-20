"""
结构完整率计算器
- 资产：3章结构完整率
- 告警/事件：6章结构完整率
"""
import re
from typing import Any, Dict
from .base_calculator import BaseCalculator, MetricResult


class StructureCompletenessCalculator(BaseCalculator):
    """结构完整率计算器"""

    METRIC_NAME = "chapter_structure_completeness"
    MAX_SCORE = 5

    SECTION_PATTERNS = {
        "asset": [
            ("风险速览", r'(?:^|\n)\s*(?:#{1,6}\s*(?:\d+(?:\.\d+)?\s*)?(?:第\s*[1一]\s*章\s*)?\s*风险速览|<summary>\s*第\s*[1一]\s*章\s*风险速览\s*</summary>)'),
            ("风险轨迹", r'(?:^|\n)\s*(?:#{1,6}\s*(?:\d+(?:\.\d+)?\s*)?(?:第\s*[2二]\s*章\s*)?\s*风险轨迹|<summary>\s*第\s*[2二]\s*章\s*风险轨迹\s*</summary>)'),
            ("当前威胁", r'(?:^|\n)\s*(?:#{1,6}\s*(?:\d+(?:\.\d+)?\s*)?(?:第\s*[3三]\s*章\s*)?\s*当前威胁|<summary>\s*第\s*[3三]\s*章\s*当前威胁\s*</summary>)'),
        ],
        "alarm": [
            ("第1章 告警定性", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[1一]\s*章\s*)?告警定性'),
            ("第2章 关键实体", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[2二]\s*章\s*)?关键实体'),
            ("第3章 攻击结果与举证", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[3三]\s*章\s*)?攻击结果与举证'),
            ("第4章 当前攻击影响", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[4四]\s*章\s*)?当前攻击影响'),
            ("第5章 风险预测", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[5五]\s*章\s*)?风险预测'),
            ("第6章 处置建议", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[6六]\s*章\s*)?处置建议'),
        ],
        "event": [
            ("第1章 事件定性", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[1一]\s*章\s*)?事件定性'),
            ("第2章 关键实体", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[2二]\s*章\s*)?关键实体'),
            ("第3章 攻击结果与举证", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[3三]\s*章\s*)?攻击结果与举证'),
            ("第4章 当前攻击影响", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[4四]\s*章\s*)?当前攻击影响'),
            ("第5章 风险预测", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[5五]\s*章\s*)?风险预测'),
            ("第6章 处置建议", r'(?:^|\n)\s*#{1,6}\s*(?:第\s*[6六]\s*章\s*)?处置建议'),
        ]
    }

    def __init__(self, module: str, threshold: float = 1.0):
        super().__init__(threshold=threshold)
        self.module = module

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        """计算结构完整率"""
        markdown_text = self._get_markdown_text(ai_data)
        section_patterns = self.SECTION_PATTERNS.get(self.module, [])

        found_sections = []
        missing_sections = []
        field_details = []

        for section_name, pattern in section_patterns:
            matched = re.search(pattern, markdown_text, re.IGNORECASE | re.MULTILINE)
            if matched:
                found_sections.append(section_name)
                field_details.append({
                    "field": section_name,
                    "status": "match",
                    "ai": "已匹配",
                    "api": "必需章节"
                })
            else:
                missing_sections.append(section_name)
                field_details.append({
                    "field": section_name,
                    "status": "missing",
                    "ai": "未匹配",
                    "api": "必需章节"
                })

        total_required = len(section_patterns)
        found_count = len(found_sections)
        completeness_rate = found_count / total_required if total_required > 0 else 0.0

        metric_cn = "结构完整率" if self.module == "asset" else "6章结构完整率"

        detail = {
            "module": self.module,
            "total_required": total_required,
            "found_count": found_count,
            "missing_count": total_required - found_count,
            "required_sections": [name for name, _ in section_patterns],
            "found_sections": found_sections,
            "missing_sections": missing_sections,
            "field_details": field_details,
        }

        return MetricResult(
            metric_name=self.METRIC_NAME,
            metric_cn=metric_cn,
            score=round(completeness_rate * self.MAX_SCORE, 2),
            max_score=float(self.MAX_SCORE),
            accuracy=completeness_rate,
            ai_value=f"{found_count}/{total_required}",
            api_value=f"{total_required}/{total_required}",
            detail=detail,
            is_passed=completeness_rate >= self.threshold
        )

    def _get_markdown_text(self, ai_data: Dict[str, Any]) -> str:
        """获取 Markdown 文本"""
        if isinstance(ai_data, str):
            return ai_data
        if isinstance(ai_data, dict):
            if 'raw_text' in ai_data:
                return ai_data['raw_text']
            if 'markdown' in ai_data:
                return ai_data['markdown']
            return str(ai_data)
        return str(ai_data)

"""
动态结构完整率计算器（漏洞模块用）
漏洞报告无固定章节模板，动态统计 ## 级标题数量作为结构完整性参考
"""
import re
from typing import Any, Dict, List
from .base_calculator import BaseCalculator, MetricResult


class DynamicStructureCompletenessCalculator(BaseCalculator):
    """动态结构完整率计算器"""

    METRIC_NAME = "dynamic_structure_completeness"
    METRIC_CN = "动态结构完整率"
    MAX_SCORE = 5
    MIN_EXPECTED_SECTIONS = 3  # 最少期望的 ## 级章节数

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        """计算动态结构完整率

        统计 AI 输出 Markdown 中 ## 级标题的数量，
        作为结构完整性的参考指标。

        Args:
            ai_data: AI 解析的数据，应包含 raw_text 或 markdown 字段
            api_data: 未使用（兼容接口）

        Returns:
            MetricResult: 指标计算结果
        """
        markdown_text = self._get_markdown_text(ai_data)

        # 提取所有 ## 级标题（排除 ### 和 #）
        section_pattern = r'(?:^|\n)\s*##\s+(.+?)(?:\s*#*\s*)$'
        matches = re.findall(section_pattern, markdown_text, re.MULTILINE)

        section_titles = [m.strip() for m in matches if m.strip()]
        # 过滤掉纯数字/纯标点的标题
        section_titles = [s for s in section_titles if re.search(r'[一-龥a-zA-Z]', s)]

        section_count = len(section_titles)

        # 计算完整率：实际章节数 / 期望章节数，但上限为1.0
        if section_count >= self.MIN_EXPECTED_SECTIONS:
            completeness_rate = 1.0
        elif section_count > 0:
            completeness_rate = section_count / self.MIN_EXPECTED_SECTIONS
        else:
            completeness_rate = 0.0

        detail = {
            "module": "vuln",
            "section_count": section_count,
            "min_expected": self.MIN_EXPECTED_SECTIONS,
            "section_titles": section_titles,
            "is_dynamic": True,
        }

        return MetricResult(
            metric_name=self.METRIC_NAME,
            metric_cn=self.METRIC_CN,
            score=round(completeness_rate * self.MAX_SCORE, 2),
            max_score=float(self.MAX_SCORE),
            accuracy=completeness_rate,
            ai_value=f"{section_count}个章节",
            api_value=f">={self.MIN_EXPECTED_SECTIONS}个章节",
            detail=detail,
            is_passed=section_count >= self.MIN_EXPECTED_SECTIONS
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

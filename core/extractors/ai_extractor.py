"""
AI输出提取器
从AI响应的Markdown或JSON中提取结构化数据
"""
import json
import os
import re
from typing import Any, Dict, List, Optional
from .text_extractor import TextExtractor


class AIExtractor:
    """AI输出提取器"""

    RISK_LEVELS = ['严重', '高危', '中危', '低危', '健康']

    # 资产关键字段（10个）
    ASSET_KEY_FIELDS = [
        'asset_id', 'ip_address', 'mac_address', 'hostname',
        'asset_type', 'asset_level', 'os_name', 'organization',
        'is_exposed', 'last_online_time'
    ]

    def __init__(self):
        self.text_extractor = TextExtractor()

    def extract_from_json(self, json_file: str) -> Dict[str, Any]:
        """从AI解析JSON文件中提取字段"""
        if not os.path.exists(json_file):
            return {}

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return data.get('parsed_fields', {})

    def extract_from_markdown(self, markdown_text: str) -> Dict[str, Any]:
        """从Markdown文本中提取所有字段"""
        result = {}

        # 表格格式字段提取
        result['asset_id'] = self.text_extractor.extract_table_field(markdown_text, '资产ID')
        result['ip_address'] = self.text_extractor.extract_table_field(markdown_text, 'IP地址')
        result['mac_address'] = self.text_extractor.extract_table_field(markdown_text, 'MAC地址')
        result['hostname'] = self.text_extractor.extract_table_field(markdown_text, '主机名')
        result['asset_type'] = self.text_extractor.extract_table_field(markdown_text, '资产类型')
        result['asset_level'] = self.text_extractor.extract_table_field(markdown_text, '资产等级')
        result['os_name'] = self.text_extractor.extract_table_field(markdown_text, '操作系统')
        result['organization'] = self.text_extractor.extract_table_field(markdown_text, '所属组织')
        result['is_exposed'] = self.text_extractor.extract_table_field(markdown_text, '是否暴露面')
        result['last_online_time'] = self.text_extractor.extract_table_field(markdown_text, '最后上线时间')

        result['risk_level'] = self.extract_risk_level(markdown_text)
        result['risk_score'] = self._extract_risk_score(markdown_text)

        # 清理None值
        return {k: v for k, v in result.items() if v is not None}

    def extract_risk_level(self, markdown_text: str) -> Optional[str]:
        """提取资产风险等级，优先规范格式，兜底表格/正文（含值校验）"""
        if not markdown_text:
            return None

        # 1. 规范 1.2 风险概要优先格式
        priority_patterns = [
            r'\*\*当前评分：\d+分，风险等级[：:]\s*(严重|高危|中危|低危|健康)',
            r'\*\*当前风险等级[：:]\s*(严重|高危|中危|低危|健康)',
            r'当前评分：\d+分，风险等级[：:]\s*(严重|高危|中危|低危|健康)',
            r'当前风险等级[：:]\s*(严重|高危|中危|低危|健康)',
        ]
        for pattern in priority_patterns:
            match = re.search(pattern, markdown_text)
            if match:
                return match.group(1).strip()

        # 2. 正文/列表等兜底格式
        fallback = self._extract_risk_level_fallback(markdown_text)
        if fallback:
            return fallback

        # 3. 评分括号形式：59（严重）、表格 | 风险评分 | 59（严重） |
        paren_patterns = [
            r'(?:风险评分|资产评分|安全评分)\s*\|\s*(\d+)\s*[（(]\s*(严重|高危|中危|低危|健康)\s*[）)]',
            r'(?:风险评分|资产评分|安全评分|评分)[^\n]{0,40}?(\d+)\s*[（(]\s*(严重|高危|中危|低危|健康)\s*[）)]',
        ]
        for pattern in paren_patterns:
            paren_match = re.search(pattern, markdown_text)
            if paren_match:
                return paren_match.group(2).strip()

        # 4. 两列表格（取值必须通过等级校验，避免多列表头误匹配）
        for field_name in ['资产风险等级', '风险等级', '风险级别']:
            table_val = self.text_extractor.extract_table_field(markdown_text, field_name)
            normalized = self._normalize_risk_level(table_val)
            if normalized:
                return normalized

        return None

    def _normalize_risk_level(self, value: Optional[str]) -> Optional[str]:
        """将提取值标准化为五档风险等级之一，无效值返回 None"""
        if not value:
            return None
        text = str(value).strip()
        for level in self.RISK_LEVELS:
            if level in text:
                return level
        return None

    def _extract_risk_level_fallback(self, text: str) -> Optional[str]:
        """兜底提取风险等级，支持多种 markdown 格式"""
        level_group = '|'.join(self.RISK_LEVELS)
        patterns = [
            r'(?:风险概要|风险速览).*?[-*]\s*\*{1,2}风险等级\*{1,2}\s*[：:]\s*\*{0,2}(' + level_group + r')',
            r'[-*]\s*\*{1,2}风险等级\*{1,2}\s*[：:]\s*\*{0,2}(' + level_group + r')',
            r'\*{1,2}风险等级\*{1,2}\s*[：:]\s*\*{0,2}(' + level_group + r')',
            r'\*{1,2}风险等级\*{1,2}\s*(?:判定)?[：:为]?\s*(' + level_group + r')',
            r'风险等级\s*(?:判定)?[：:为]?\s*(' + level_group + r')',
            r'(?:资产风险等级|风险级别)[：:为]?\s*\*{0,2}(' + level_group + r')',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1).strip()
        return None

    def _extract_risk_score(self, text: str) -> Optional[int]:
        """提取风险评分"""
        patterns = [
            r'(?:安全评分|风险评分|资产评分|风险分)[：:为]?\s*[*]*(\d+)分?',
            r'\*\*(\d+)分\*\*.*?(?:严重|高危|中危|低危|健康)',
            r'(?:风险评分|资产评分|风险分)[：:]\s*(\d+)',
            r'(\d+)（严重|高危|中危|低危|健康）',
            r'评分[：:为]?\s*(\d+)分?',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    continue
        return None

    def get_field_completeness(self, extracted_data: Dict[str, Any]) -> float:
        """计算字段完整率"""
        completed = sum(
            1 for field in self.ASSET_KEY_FIELDS
            if extracted_data.get(field) not in [None, ""]
        )
        return completed / len(self.ASSET_KEY_FIELDS)

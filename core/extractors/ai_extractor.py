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

        # 风险字段
        risk_level = self.text_extractor.extract_table_field_multi(
            markdown_text, ['资产风险等级', '风险等级', '风险级别']
        )
        if not risk_level:
            risk_level = self._extract_risk_level_fallback(markdown_text)
        result['risk_level'] = risk_level

        result['risk_score'] = self._extract_risk_score(markdown_text)

        # CVE列表
        result['cve_list'] = self.text_extractor.extract_cve_list(markdown_text)

        # 漏洞ID列表
        result['vuln_list'] = self.text_extractor.extract_vuln_list(markdown_text)

        # 告警ID列表
        result['alert_list'] = self.text_extractor.extract_alert_list(markdown_text)

        # 清理None值
        return {k: v for k, v in result.items() if v is not None}

    def _extract_risk_level_fallback(self, text: str) -> Optional[str]:
        """兜底提取风险等级"""
        patterns = [
            r'(?:资产风险等级|风险等级|风险级别)[：:为]?\s*\*{0,2}(严重|高危|中危|低危)',
            r'风险[：:]\s*(严重|高危|中危|低危)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1).strip()
        return None

    def _extract_risk_score(self, text: str) -> Optional[int]:
        """提取风险评分"""
        patterns = [
            r'(?:安全评分|风险评分|资产评分|风险分)[：:为]?\s*[*]*(\d+)分?',
            r'\*\*(\d+)分\*\*.*?(?:严重|高危|中危|低危)',
            r'(?:风险评分|资产评分|风险分)[：:]\s*(\d+)',
            r'(\d+)（严重|高危|中危|低危）',
            r'评分[：:为]?\s*(\d+)分?',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    return int(match.group(1))
                except:
                    continue
        return None

    def get_field_completeness(self, extracted_data: Dict[str, Any]) -> float:
        """计算字段完整率"""
        completed = sum(
            1 for field in self.ASSET_KEY_FIELDS
            if extracted_data.get(field) not in [None, ""]
        )
        return completed / len(self.ASSET_KEY_FIELDS)

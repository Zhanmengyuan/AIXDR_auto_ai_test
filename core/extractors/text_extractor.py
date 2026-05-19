"""
文本提取器基类
提供通用的正则匹配和字段提取方法
"""
import re
from typing import Any, Dict, List, Optional


class TextExtractor:
    """文本提取器基类"""

    @staticmethod
    def extract_by_pattern(text: str, pattern: str, group_idx: int = 1) -> Optional[str]:
        """根据正则表达式提取单个值"""
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(group_idx).strip() if match else None

    @staticmethod
    def extract_all_by_pattern(text: str, pattern: str) -> List[str]:
        """根据正则表达式提取所有匹配的值"""
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [m.strip() for m in matches if m]

    @staticmethod
    def extract_table_field(text: str, field_name: str) -> Optional[str]:
        """从表格格式文本中提取字段值

        表格格式: | **字段名** | 值 |
        """
        patterns = [
            rf'\|\s*[*]*\s*{field_name}[*]*\s*\|\s*([^\|]+)\s*\|',
            rf'\|\s*{field_name}\s*\|\s*([^\|]+)\s*\|',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def extract_table_field_multi(text: str, field_names: List[str]) -> Optional[str]:
        """从表格格式文本中提取字段值，支持多个字段名

        依次尝试每个字段名，返回第一个匹配的值
        """
        for field_name in field_names:
            result = TextExtractor.extract_table_field(text, field_name)
            if result:
                return result
        return None

    @staticmethod
    def extract_cve_list(text: str) -> List[str]:
        """从文本中提取CVE编号列表"""
        pattern = r'CVE[-\s]?(\d{4})[-\s]?(\d{4,})'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [f"CVE-{m[0]}-{m[1]}" for m in matches]

    @staticmethod
    def extract_vuln_list(text: str) -> List[str]:
        """从文本中提取漏洞ID列表 (AVE-xxx格式)"""
        pattern = r'AVE[-\s]?(\d{4})[-\s]?(\d+)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [f"AVE-{m[0]}-{m[1]}" for m in matches]

    @staticmethod
    def extract_alert_list(text: str) -> List[str]:
        """从文本中提取告警ID列表 (ALE-xxx格式)"""
        pattern = r'ALE[-\s]?(\d{4})[-\s]?(\d+)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [f"ALE-{m[0]}-{m[1]}" for m in matches]

    @staticmethod
    def extract_event_list(text: str) -> List[str]:
        """从文本中提取事件ID列表 (EVE-xxx格式)"""
        pattern = r'EVE[-\s]?(\d{4})[-\s]?(\d+)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [f"EVE-{m[0]}-{m[1]}" for m in matches]

    @staticmethod
    def extract_asset_list(text: str) -> List[str]:
        """从文本中提取资产ID列表"""
        patterns = [
            r'资产ID[：:]\s*([A-Za-z0-9_]+)',
            r'资产[：:]\s*([A-Za-z0-9_]+)',
        ]
        assets = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            assets.extend(matches)
        return list(set(assets))

    @staticmethod
    def extract_affected_asset_analysis(text: str) -> Dict[str, Any]:
        """提取受影响资产分析的10个字段

        字段：资产ID、IP地址、国家、主机名、资产类型、资产等级、操作系统、资产状态、是否暴露面、最后上线时间

        Returns:
            Dict: 包含10个字段的结构化数据
        """
        required_fields = [
            'asset_id',           # 资产ID
            'ip_address',         # IP地址
            'organization',       # 组织
            'hostname',           # 主机名
            'asset_type',         # 资产类型
            'asset_level',        # 资产等级
            'os_name',            # 操作系统
            'asset_status',       # 资产状态
            'is_exposed',         # 是否暴露面
            'last_online_time'    # 最后上线时间
        ]

        section_pattern = r'##\s*[^#]*受影响资产[^#]*|(?<=##\s*\d+[^#]*)[^#]+(?=##\s*\d+|$)'
        section_match = re.search(r'##\s*[^#\n]*受影响资产[^#\n]*.*?(?=##\s*[^#\n]+(?:##|$))', text, re.DOTALL)
        
        if not section_match:
            section_match = re.search(r'##\s*[^#\n]*受影响资产[^#\n]*.*', text, re.DOTALL)
        
        section_text = section_match.group(0) if section_match else text

        result = {}
        for field in required_fields:
            value = None

            if field == 'asset_id':
                value = TextExtractor.extract_table_field(section_text, '资产ID')
                if not value:
                    match = re.search(r'资产ID[：:]\s*([A-Za-z0-9_\-]+)', section_text)
                    value = match.group(1) if match else None

            elif field == 'ip_address':
                value = TextExtractor.extract_table_field(section_text, 'IP地址')
                if not value:
                    value = TextExtractor.extract_table_field(section_text, 'IP')
                if not value:
                    match = re.search(r'IP[：:为]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', section_text)
                    value = match.group(1) if match else None

            elif field == 'organization':
                value = TextExtractor.extract_table_field(section_text, '组织')
                if not value:
                    value = TextExtractor.extract_table_field(section_text, '所属组织')
                if not value:
                    match = re.search(r'组织[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None
                if not value:
                    match = re.search(r'所属组织[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'hostname':
                value = TextExtractor.extract_table_field(section_text, '主机名')
                if not value:
                    match = re.search(r'主机名[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'asset_type':
                value = TextExtractor.extract_table_field(section_text, '资产类型')
                if not value:
                    match = re.search(r'资产类型[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'asset_level':
                value = TextExtractor.extract_table_field(section_text, '资产等级')
                if not value:
                    match = re.search(r'资产等级[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'os_name':
                value = TextExtractor.extract_table_field(section_text, '操作系统')
                if not value:
                    match = re.search(r'操作系统[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'asset_status':
                value = TextExtractor.extract_table_field(section_text, '资产状态')
                if not value:
                    match = re.search(r'资产状态[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'is_exposed':
                value = TextExtractor.extract_table_field(section_text, '是否暴露面')
                if not value:
                    match = re.search(r'是否暴露面[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            elif field == 'last_online_time':
                value = TextExtractor.extract_table_field(section_text, '最后上线时间')
                if not value:
                    match = re.search(r'最后上线时间[：:]\s*([^\n\|]+)', section_text)
                    value = match.group(1).strip() if match else None

            result[field] = value

        present_count = sum(1 for v in result.values() if v)
        result['present_count'] = present_count
        result['total_count'] = 10
        result['field_completeness'] = present_count / 10

        return result

    @staticmethod
    def normalize_value(value: Any) -> str:
        """标准化字段值"""
        if value is None:
            return ""
        return str(value).strip()

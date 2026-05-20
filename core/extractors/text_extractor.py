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
        """提取受影响资产分析的字段

        支持两种格式：
        1. 表格格式: | **字段名** | 值 |
        2. 列表格式: - **字段名**：值

        Returns:
            Dict: 包含提取字段的结构化数据
        """
        # 首先找到受影响资产分析章节
        section_match = re.search(r'##\s*[^#\n]*受影响资产[^#\n]*.*?(?=##\s*[^#\n]+|$)', text, re.DOTALL)
        
        if not section_match:
            section_match = re.search(r'##\s*[^#\n]*受影响资产[^#\n]*.*', text, re.DOTALL)
        
        section_text = section_match.group(0) if section_match else text

        # 通用提取函数：支持表格格式和列表格式
        def extract_field(field_names: list) -> str:
            """从文本中提取字段值，支持多个字段名和多种格式"""
            for field_name in field_names:
                # 1. 先尝试表格格式
                value = TextExtractor.extract_table_field(section_text, field_name)
                if value:
                    return value.strip()
                
                # 2. 尝试列表格式：- **字段名**：值 或者 - **字段名**: 值
                patterns = [
                    rf'-\s*\*\*{field_name}\*\*[：:]\s*([^\n]+)',
                    rf'\*\*{field_name}\*\*[：:]\s*([^\n]+)',
                    rf'{field_name}[：:]\s*([^\n\|]+)',
                ]
                for pattern in patterns:
                    match = re.search(pattern, section_text)
                    if match:
                        return match.group(1).strip()
            return None

        result = {}
        
        # 提取各个字段
        result['asset_id'] = extract_field(['资产ID'])
        result['ip_address'] = extract_field(['IP地址', 'IP'])
        result['country'] = extract_field(['国家'])
        result['hostname'] = extract_field(['主机名'])
        result['asset_type'] = extract_field(['资产类型'])
        result['asset_level'] = extract_field(['资产等级'])
        result['security_domain'] = extract_field(['安全域'])
        result['os_name'] = extract_field(['操作系统'])
        result['machine_room'] = extract_field(['机房位置'])
        result['responsible_person'] = extract_field(['责任人'])
        result['asset_status'] = extract_field(['资产状态'])
        result['is_exposed'] = extract_field(['是否暴露面'])
        result['last_online_time'] = extract_field(['最后上线时间'])

        # 统计完整度（检查所有可能的字段）
        all_fields = [
            'asset_id', 'ip_address', 'country', 'hostname', 
            'asset_type', 'asset_level', 'security_domain', 
            'os_name', 'machine_room', 'responsible_person',
            'asset_status', 'is_exposed', 'last_online_time'
        ]
        present_count = sum(1 for field in all_fields if result.get(field))
        result['present_count'] = present_count
        result['total_count'] = 13
        result['field_completeness'] = present_count / 13

        return result

    @staticmethod
    def normalize_value(value: Any) -> str:
        """标准化字段值"""
        if value is None:
            return ""
        return str(value).strip()

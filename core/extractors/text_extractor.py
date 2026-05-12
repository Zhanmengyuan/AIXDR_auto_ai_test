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
    def normalize_value(value: Any) -> str:
        """标准化字段值"""
        if value is None:
            return ""
        return str(value).strip()

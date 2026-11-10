"""
沙箱报告解读结果解析器
从AI输出的Markdown中提取风险等级、样本基本信息、章节完整性等
基准真值来自 MySQL XDR_DDAN_RESULT.EXT_FIELD_ONE 的沙箱原始报告JSON
"""
import re
import json
from typing import Any, Dict, List


class SandboxExtractor:
    """沙箱AI解读报告解析器"""

    REQUIRED_SECTIONS = [
        "执行环境",
        "样本信息",
        "风险评估",
        "违规与检测依据",
        "关键系统行为",
        "网络行为分析",
        "释放文件分析",
        "黑名单命中情况",
        "威胁类型判断",
        "总体风险判断",
        "建议处置方式",
    ]

    RISK_RATING_MAP = {
        0: "良性",
        1: "低风险",
        2: "中风险",
        3: "高风险",
        -1: "不支持的文件类型",
        -19: "无法访问URL",
    }

    # 字段提取模式：同时支持 "字段名：值" 和 表格 "| 字段名 | 值 |" 两种格式
    FIELD_NAME_PATTERNS = {
        "原始文件名": [
            r'原始文件名[：:]\s*(.+?)(?:\n|$)',
            r'\|\s*原始文件名\s*\|\s*(.+?)\s*\|',
        ],
        "MD5": [
            r'(?:文件\s*)?MD5(?:\s*哈希值)?[：:]\s*([a-fA-F0-9]{32})',
            r'\|\s*(?:文件\s*)?MD5(?:\s*哈希值)?\s*\|\s*([a-fA-F0-9]{32})',
        ],
        "SHA1": [
            r'(?:文件\s*)?SHA-?1(?:\s*哈希值)?[：:]\s*([a-fA-F0-9]{40})',
            r'\|\s*(?:文件\s*)?SHA-?1(?:\s*哈希值)?\s*\|\s*([a-fA-F0-9]{40})',
        ],
        "SHA256": [
            r'(?:文件\s*)?SHA-?256(?:\s*哈希值)?[：:]\s*([a-fA-F0-9]{64})',
            r'\|\s*(?:文件\s*)?SHA-?256(?:\s*哈希值)?\s*\|\s*([a-fA-F0-9]{64})',
        ],
        "父样本SHA1": [
            r'父(?:样本|文件)\s*SHA-?1(?:\s*哈希值)?[：:]\s*([a-fA-F0-9]{40})',
            r'\|\s*父(?:样本|文件)\s*SHA-?1(?:\s*哈希值)?\s*\|\s*([a-fA-F0-9]{40})',
        ],
        "文件大小": [
            r'(?:文件大小|文件字节大小)[：:]\s*(.+?)(?:\n|$)',
            r'\|\s*(?:文件字节大小|文件大小)\s*\|\s*(.+?)\s*\|',
        ],
        "分析开始时间": [
            r'分析开始时间[：:]\s*(.+?)(?:\n|$)',
            r'\|\s*分析开始时间\s*\|\s*(.+?)\s*\|',
        ],
        "分析结束时间": [
            r'分析结束时间[：:]\s*(.+?)(?:\n|$)',
            r'\|\s*分析结束时间\s*\|\s*(.+?)\s*\|',
        ],
        "样本解压密码": [
            r'(?:样本解压密码|提取密码|解压密码)[：:]\s*(.+?)(?:\n|$)',
            r'\|\s*(?:样本解压密码|提取密码|解压密码)\s*\|\s*(.+?)\s*\|',
        ],
        "文件真实类型": [
            r'(?:文件真实类型|真实文件类型|文件类型)[：:]\s*(.+?)(?:\n|$)',
            r'\|\s*(?:文件真实类型|真实文件类型|文件类型)\s*\|\s*(.+?)\s*\|',
        ],
    }

    FORBIDDEN_FIELD_NAMES = [
        "ROZRating", "OverallROZRating", "VirusDetected", "GRIDIsKnownGood",
        "AuthenticodeIsGood", "AnalysisViolation", "SYSTEM_BEHAVIOR_RECORD",
        "NETWORK_ACCESS_RECORD", "NETWORK_ACCESS_URL", "DroppedFiles",
        "BLACKLIST", "VirusName", "isKnownThreat",
    ]

    PROMPT_RESIDUE_PATTERNS = [
        r'\{\{.*?\}\}',
        r'<\|.*?\|>',
        r'\[INST\]',
        r'\[/INST\]',
        r'<\|im_start\|>',
        r'<\|im_end\|>',
    ]

    CONTROL_CHAR_PATTERN = r'[\x00-\x08\x0b\x0c\x0e-\x1f]'

    def extract_all(self, raw_text: str) -> Dict[str, Any]:
        """解析AI解读报告，提取所有指标所需数据"""
        return {
            "risk_level": self.extract_risk_level(raw_text),
            "sample_info": self.extract_sample_info(raw_text),
            "section_completeness": self.check_section_completeness(raw_text),
            "format_violations": self.check_format_violations(raw_text),
            "disposal_suggestion": self.extract_disposal_suggestion(raw_text),
        }

    def extract_risk_level(self, raw_text: str) -> str:
        """提取AI输出的风险等级判断

        优先从「风险评估」段落取段落描述信息，若无该段落再全文关键词兜底
        """
        # 1. 定位「风险评估」段落
        section = self._extract_section(raw_text, "风险评估")
        search_text = section if section else raw_text

        # 2. 在段落内正则提取风险等级值（匹配"风险评估为高危害"等表述）
        patterns = [
            r'(?:综合|总体|文件)?风险(?:等级|评估|判断)?(?:为|是)[：:]?\s*\*{0,2}\s*(良性|低风险|中风险|高风险|无危害|安全|可疑|灰色|恶意|高危害|低危害|中危害)',
            r'(?:综合|总体)?风险(?:等级|评估|判断)[：:]\s*\*{0,2}\s*(良性|低风险|中风险|高风险|无危害|安全|可疑|灰色|恶意|高危害|低危害|中危害)',
        ]
        for pattern in patterns:
            match = re.search(pattern, search_text, re.IGNORECASE)
            if match:
                return self._normalize_risk(match.group(1))

        # 3. 关键词兜底（优先段落内，段落内无则全文）
        keyword_map = {"良性": ["良性", "无危害", "可放行"], "低风险": ["低风险", "低危害"],
                       "中风险": ["中风险", "灰色", "可疑", "中危害"],
                       "高风险": ["高风险", "恶意", "隔离", "威胁", "高危害"]}
        for risk, keywords in keyword_map.items():
            for kw in keywords:
                if kw in search_text:
                    return self._normalize_risk(kw)
        if section:
            for risk, keywords in keyword_map.items():
                for kw in keywords:
                    if kw in raw_text:
                        return self._normalize_risk(kw)
        return "未获取到"

    def _extract_section(self, raw_text: str, section_name: str) -> str:
        """提取指定标题段落的内容（标题到下一个标题之间）"""
        escaped = re.escape(section_name)
        pattern = rf'#{1,6}\s*{escaped}\s*\n(.*?)(?=\n#{1,6}\s|\Z)'
        match = re.search(pattern, raw_text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    def _normalize_risk(self, value: str) -> str:
        value = value.strip()
        if any(kw in value for kw in ["良性", "无危害", "安全", "无风险", "可放行"]):
            return "良性"
        if any(kw in value for kw in ["低风险", "低危害"]):
            return "低风险"
        if any(kw in value for kw in ["中风险", "灰色", "可疑", "隔离观察", "中危害"]):
            return "中风险"
        if any(kw in value for kw in ["高风险", "恶意", "隔离", "阻断", "威胁", "高危害"]):
            return "高风险"
        return value

    def extract_sample_info(self, raw_text: str) -> Dict[str, str]:
        """提取样本基本信息字段（支持"字段名：值"和表格两种格式）"""
        info = {}
        for field_name, patterns in self.FIELD_NAME_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, raw_text, re.IGNORECASE)
                if match:
                    info[field_name] = match.group(1).strip()
                    break
            if field_name not in info:
                info[field_name] = ""
        return info

    def check_section_completeness(self, raw_text: str) -> Dict[str, Any]:
        """检查11个固定章节的完整性"""
        found = []
        missing = []
        for section in self.REQUIRED_SECTIONS:
            if self._section_present(raw_text, section):
                found.append(section)
            else:
                missing.append(section)
        total = len(self.REQUIRED_SECTIONS)
        rate = len(found) / total if total > 0 else 0.0
        return {
            "total": total, "found_count": len(found), "missing_count": len(missing),
            "found_sections": found, "missing_sections": missing, "completeness_rate": rate,
        }

    def _section_present(self, raw_text: str, section_name: str) -> bool:
        """检查章节是否存在（标题匹配，非正文子串）"""
        escaped = re.escape(section_name)
        patterns = [
            r'#{1,6}\s*(?:\d+[.、\s]*)?' + escaped,
            r'(?:^|\n)\s*[-—*]+\s*' + escaped,
            r'<summary>\s*' + escaped,
            r'\|\s*' + escaped,
        ]
        for pattern in patterns:
            if re.search(pattern, raw_text, re.IGNORECASE):
                return True
        return False

    def check_format_violations(self, raw_text: str) -> Dict[str, Any]:
        """检查格式规范性"""
        violations = []
        control_matches = re.findall(self.CONTROL_CHAR_PATTERN, raw_text)
        if control_matches:
            violations.append({"type": "控制字符", "count": len(control_matches)})
        for pattern in self.PROMPT_RESIDUE_PATTERNS:
            matches = re.findall(pattern, raw_text)
            if matches:
                violations.append({"type": "Prompt模板残留", "count": len(matches), "sample": matches[0][:50]})
        for field_name in self.FORBIDDEN_FIELD_NAMES:
            if field_name in raw_text:
                violations.append({"type": "原始字段名", "field": field_name})
        return {"violation_count": len(violations), "violations": violations, "is_compliant": len(violations) == 0}

    def extract_disposal_suggestion(self, raw_text: str) -> str:
        """提取建议处置方式段落

        支持3种格式：
        1. "建议处置方式：" 后跟内容
        2. "### 建议处置方式" 标题后跟内容（下一行开始）
        3. "建议处置方式" 在表格中
        """
        # 标题格式：### 建议处置方式\n 内容
        match = re.search(r'#{1,6}\s*建议处置方式\s*\n(.+?)(?:\n#{1,6}\s|\Z)', raw_text, re.DOTALL)
        if match:
            return match.group(1).strip()[:2000]
        # 冒号格式：建议处置方式：内容
        match = re.search(r'建议处置方式[：:]\s*(.+?)(?:\n\n|\n#{1,6}|\Z)', raw_text, re.DOTALL)
        if match:
            return match.group(1).strip()[:2000]
        # 通用处置建议
        match = re.search(r'处置建议[：:]\s*(.+?)(?:\n\n|\n#{1,6}|\Z)', raw_text, re.DOTALL)
        if match:
            return match.group(1).strip()[:2000]
        return ""

    def _get_nested(self, data: Dict, *keys, default=None):
        """安全嵌套取值"""
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data

    def _get_report_data(self, biz_content: Dict[str, Any]) -> Dict[str, Any]:
        """从沙箱JSON中获取报告数据（位于 REPORTS.FILE_ANALYZE_REPORT[0]）"""
        reports = biz_content.get("REPORTS", {})
        far_list = reports.get("FILE_ANALYZE_REPORT", [])
        if far_list and isinstance(far_list, list):
            return far_list[0]
        if isinstance(far_list, dict):
            return far_list
        return reports.get("IMAGE_TYPE", {})

    def extract_risk_from_api(self, biz_content: Dict[str, Any]) -> str:
        """从沙箱原始报告JSON（EXT_FIELD_ONE）提取基准真值风险等级

        优先取 OverallROZRating（综合风险评估等级），其次取 ROZRating/@ROZRating
        映射：0=良性, 1=低风险, 2=中风险, 3=高风险, 负数=检测失败
        """
        report = self._get_report_data(biz_content)

        overall_rating = report.get("OverallROZRating")
        roz_rating = report.get("ROZRating")
        if roz_rating is None:
            roz_rating = self._get_nested(biz_content, "REPORTS", "IMAGE_TYPE", "TYPE", "@ROZRating")

        rating = overall_rating if overall_rating is not None else roz_rating
        if rating is None:
            virus_detected = report.get("VirusDetected")
            virus_name = report.get("VirusName", {})
            is_known_threat = virus_name.get("@isKnownThreat") if isinstance(virus_name, dict) else None
            if virus_detected or is_known_threat:
                return "高风险"
            return "良性"

        try:
            rating_int = int(rating)
        except (ValueError, TypeError):
            return "未知"

        if rating_int in self.RISK_RATING_MAP:
            return self.RISK_RATING_MAP[rating_int]
        if rating_int < 0:
            return "检测失败"
        return "未知"

    def extract_sample_info_from_api(self, biz_content: Dict[str, Any]) -> Dict[str, str]:
        """从沙箱原始报告JSON提取样本基本信息（基准真值）

        字段路径：REPORTS.FILE_ANALYZE_REPORT[0].{字段名}
        """
        report = self._get_report_data(biz_content)

        return {
            "原始文件名": str(report.get("OrigFileName") or report.get("DownloadedFileName") or ""),
            "MD5": str(report.get("FileMD5") or ""),
            "SHA1": str(report.get("FileSHA1") or ""),
            "SHA256": str(report.get("FileSHA256") or ""),
            "父样本SHA1": str(report.get("ParentSHA1") or ""),
            "文件大小": str(report.get("FileSize") or ""),
            "分析开始时间": str(report.get("AnalyzeStartTime") or ""),
            "分析结束时间": str(report.get("AnalyzeTime") or ""),
            "样本解压密码": str(report.get("SampleFilePassword") or ""),
            "文件真实类型": str(report.get("TrueFileType") or ""),
        }

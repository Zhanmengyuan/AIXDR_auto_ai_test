"""
沙箱报告解读指标计算器
覆盖5类评测指标：性能、准确性、处置合理性、格式规范性、完整性
"""
import re
from typing import Any, Dict, List
from .base_calculator import BaseCalculator, MetricResult


class SandboxRiskLevelCalculator(BaseCalculator):
    """风险评估等级判定准确性（关键项，判定是否正确）"""

    METRIC_NAME = "risk_level_accuracy"
    METRIC_CN = "风险评估等级判定准确性"
    MAX_SCORE = 100
    DIMENSION = "accuracy"

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        ai_risk = ai_data.get("risk_level", "未获取到")
        api_risk = api_data.get("risk_level", "未知")

        if ai_risk == "未获取到":
            return self._create_result(
                ai_value="未获取到", api_value=api_risk,
                accuracy=0.0,
                detail={"error": "AI未提取到风险等级", "error_type": "extraction_failure"}
            )

        is_match = self._normalize_risk(ai_risk) == self._normalize_risk(api_risk)

        error_type = ""
        if not is_match:
            if "高风险" in api_risk and ("良性" in ai_risk or "安全" in ai_risk):
                error_type = "漏判（高风险判为低风险，最严重）"
            elif ("良性" in api_risk or "安全" in api_risk) and ("高风险" in ai_risk or "恶意" in ai_risk):
                error_type = "误判（低风险判为高风险）"
            else:
                error_type = "等级偏差"

        return self._create_result(
            ai_value=ai_risk, api_value=api_risk,
            accuracy=1.0 if is_match else 0.0,
            detail={"is_match": is_match, "error_type": error_type} if not is_match else {"is_match": True}
        )

    def _normalize_risk(self, value: str) -> str:
        value = value.strip()
        if any(kw in value for kw in ["良性", "无危害", "安全", "无风险", "可放行"]):
            return "良性"
        if any(kw in value for kw in ["中风险", "灰色", "可疑", "隔离观察"]):
            return "中风险"
        if any(kw in value for kw in ["高风险", "恶意", "隔离", "阻断", "威胁"]):
            return "高风险"
        return value


class SandboxInfoExtractionCalculator(BaseCalculator):
    """样本基本信息提取正确率"""

    METRIC_NAME = "sample_info_accuracy"
    METRIC_CN = "样本基本信息提取正确率"
    MAX_SCORE = 100
    DIMENSION = "accuracy"

    REQUIRED_FIELDS = ["原始文件名", "MD5", "SHA1", "SHA256",
                       "父样本SHA1", "文件大小", "分析开始时间",
                       "分析结束时间", "样本解压密码", "文件真实类型"]

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        ai_info = ai_data.get("sample_info", {})
        api_info = api_data.get("sample_info", {})

        correct = 0
        total = 0
        field_details = []

        for field in self.REQUIRED_FIELDS:
            ai_val = (ai_info.get(field) or "").strip()
            api_val = (api_info.get(field) or "").strip()

            # 只有AI提取到的字段才参与比对
            if not ai_val:
                continue

            # 基准值为空则无法比对，跳过
            if not api_val:
                continue

            total += 1

            if self._values_match(ai_val, api_val):
                correct += 1
                field_details.append({"field": field, "status": "正确", "ai": ai_val[:50], "api": api_val[:50]})
            else:
                field_details.append({"field": field, "status": "错误", "ai": ai_val[:50], "api": api_val[:50]})

        accuracy = correct / total if total > 0 else 0.0

        return self._create_result(
            ai_value=f"{correct}/{total}",
            api_value=f"{total}/{total}",
            accuracy=accuracy,
            detail={"correct": correct, "total": total, "field_details": field_details}
        )

    def _values_match(self, ai_val: str, api_val: str) -> bool:
        ai_lower = ai_val.lower().strip()
        api_lower = api_val.lower().strip()
        if ai_lower == api_lower:
            return True
        if ai_lower.replace("-", "") == api_lower.replace("-", ""):
            return True
        if api_lower in ai_lower or ai_lower in api_lower:
            return True
        # 时间字段时区归一化比对（UTC vs UTC+8 等差8小时的情况）
        if self._time_matches(ai_val, api_val):
            return True
        return False

    def _time_matches(self, ai_val: str, api_val: str) -> bool:
        """时间字段时区归一化比对"""
        from datetime import datetime, timedelta
        time_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y/%m/%d %H:%M:%S",
            "%y-%m-%d %H:%M:%S",
            "%y-%m-%d %H:%M",
        ]
        ai_dt = None
        api_dt = None
        for fmt in time_formats:
            try:
                ai_dt = datetime.strptime(ai_val.strip(), fmt)
                break
            except (ValueError, TypeError):
                continue
        for fmt in time_formats:
            try:
                api_dt = datetime.strptime(api_val.strip(), fmt)
                break
            except (ValueError, TypeError):
                continue
        if ai_dt is None or api_dt is None:
            return False
        # 直接相等
        if ai_dt == api_dt:
            return True
        # API 基准值为 UTC 时间，加 8 小时后（转北京时间）与 AI 值比对
        if api_dt + timedelta(hours=8) == ai_dt:
            return True
        # 反向兼容：AI 值为 UTC 时间，加 8 小时后与 API 值比对
        if ai_dt + timedelta(hours=8) == api_dt:
            return True
        return False


class SandboxDisposalCalculator(BaseCalculator):
    """处置建议合理性（LLM-as-a-Judge 独立裁判，满分100）

    4 维度打分：
    - 证据匹配 35分：处置建议是否与报告中证据吻合（确凿证据须阻断/告警，未激活须持续观察）
    - 可执行性 30分：建议是否给出可执行命令或具体操作步骤，非笼统表述
    - 延伸覆盖 20分：是否覆盖关联对象（父压缩包、同源样本、弱口令等）
    - 字段准确性 15分：是否使用自然语言描述，不暴露原始 API 字段名
    """

    METRIC_NAME = "disposal_rationality"
    METRIC_CN = "处置建议合理性"
    MAX_SCORE = 100
    DIMENSION = "accuracy"

    def __init__(self):
        super().__init__(threshold=0.6)

    SYSTEM_PROMPT = """你是一位沙箱安全分析领域的资深专家，负责评估 AI 生成的沙箱报告解读中「建议处置方式」段落的质量。

## 评分维度与分值（满分100分）

### 1. 证据匹配（35分）
判断处置建议是否与报告中的证据和风险等级吻合：
- 确凿证据（恶意行为/病毒检出/高风险）→ 必须建议阻断/隔离/告警，否则扣分
- 未激活/低风险/良性 → 必须建议持续观察/放行，过度处置扣分
- 处置方向必须与风险评估结论一致

### 2. 可执行性（30分）
判断建议是否具有实际可操作性：
- 必须给出可执行命令（含参数）或具体操作步骤
- 笼统表述（如"加强安全防护""提高安全意识"）扣分
- 每条建议须明确操作对象、操作方式

### 3. 延伸覆盖（20分）
判断建议是否覆盖关联对象：
- 父压缩包/父样本是否给出进一步分析建议
- 同源样本/同 IP 样本是否关联排查
- 弱口令/暴露面是否提示整改
- 完全覆盖=20分，部分覆盖=10分，无延伸=0分

### 4. 字段准确性（15分）
判断建议中是否正确使用字段名称：
- 必须使用自然语言描述，不得暴露原始 API 字段名（如 ROZRating、VirusDetected、DroppedFiles 等）
- 出现原始字段名每处扣5分，扣完为止

## 输出格式（严格 JSON，不要输出其他内容）
{
    "evidence_match": {"score": 35, "reason": "..."},
    "executability": {"score": 30, "reason": "..."},
    "extended_coverage": {"score": 20, "reason": "..."},
    "field_accuracy": {"score": 15, "reason": "..."},
    "total_score": 100,
    "summary": "一句话总评"
}"""

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        raw_text = ai_data.get("raw_text", "")
        disposal = ai_data.get("disposal_suggestion", "")
        risk_level = ai_data.get("risk_level", "未获取到")
        api_risk = api_data.get("risk_level", "未知") if api_data else "未知"

        if not disposal:
            return self._create_result(
                ai_value="未提取到处置建议", api_value=f"风险={api_risk}",
                accuracy=0.0,
                detail={"error": "AI未输出处置建议"}
            )

        from core.llm_client import LLMClient

        user_prompt = f"""## 沙箱报告风险等级
- AI 判定风险等级：{risk_level}
- 基准真值风险等级：{api_risk}

## AI 输出的处置建议段落
{disposal[:2000]}

## 完整报告上下文（节选）
{raw_text[:3000]}

请按4个维度评估处置建议的质量并输出 JSON。"""

        try:
            llm = LLMClient()
            response = llm.call_llm(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=2048
            )

            if not response:
                return self._create_result(
                    ai_value=disposal[:100], api_value=f"风险={api_risk}",
                    accuracy=0.0,
                    detail={"error": "LLM裁判调用失败"}
                )

            import json
            result = json.loads(response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip())

            total = min(result.get("total_score", 0), 100)
            accuracy = total / 100.0

            detail = {
                "evidence_match": result.get("evidence_match", {}),
                "executability": result.get("executability", {}),
                "extended_coverage": result.get("extended_coverage", {}),
                "field_accuracy": result.get("field_accuracy", {}),
                "total_score": total,
                "summary": result.get("summary", ""),
                "judge_raw": response[:500]
            }

            return self._create_result(
                ai_value=f"{total}分",
                api_value=f"风险={api_risk}",
                accuracy=accuracy,
                detail=detail
            )

        except Exception as e:
            return self._create_result(
                ai_value=disposal[:100], api_value=f"风险={api_risk}",
                accuracy=0.0,
                detail={"error": f"LLM裁判异常: {e}"}
            )


class SandboxFormatCalculator(BaseCalculator):
    """格式规范性指标（非法字符 + 原始字段名 + Prompt残留）"""

    METRIC_NAME = "format_compliance"
    METRIC_CN = "格式规范性"
    MAX_SCORE = 100
    DIMENSION = "compliance"

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        format_result = ai_data.get("format_violations", {})
        violation_count = format_result.get("violation_count", 0)
        violations = format_result.get("violations", [])

        if violation_count == 0:
            accuracy = 1.0
        else:
            accuracy = max(0.0, 1.0 - violation_count * 0.1)

        return self._create_result(
            ai_value=f"{violation_count}处违规",
            api_value="0处违规",
            accuracy=accuracy,
            detail={"violation_count": violation_count, "violations": violations}
        )


class SandboxCompletenessCalculator(BaseCalculator):
    """章节完整性指标（11个固定章节）"""

    METRIC_NAME = "section_completeness"
    METRIC_CN = "章节完整性"
    MAX_SCORE = 100
    DIMENSION = "compliance"

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any] = None) -> MetricResult:
        completeness = ai_data.get("section_completeness", {})
        found_count = completeness.get("found_count", 0)
        total = completeness.get("total", 11)
        missing = completeness.get("missing_sections", [])
        rate = completeness.get("completeness_rate", 0.0)

        return self._create_result(
            ai_value=f"{found_count}/{total}",
            api_value=f"{total}/{total}",
            accuracy=rate,
            detail={"found_count": found_count, "total": total,
                    "missing_sections": missing, "completeness_rate": rate}
        )

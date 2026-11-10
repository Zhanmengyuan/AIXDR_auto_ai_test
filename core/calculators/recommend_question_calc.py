"""
推荐问题质量评估计算器
使用 LLM-as-a-Judge 评估 SSE 流中生成的3个推荐问题的质量

评估三个维度（各0~1）：
1. 规范符合度：是否符合 recommend_prompt.md 中的规则（字数、工具边界、IP规则、导向等）
2. 报告关联性：问题中的实体（IP/进程/域名等）是否来自解读报告
3. 问题多样性：3个问题是否覆盖不同排查方向，无重复冗余

综合得分 = 三个维度的加权平均（各1/3）
"""
import os
import json
import re
from typing import Any, Dict, List, Optional


class RecommendQuestionCalculator:
    """推荐问题质量评估计算器（LLM-as-a-Judge）"""

    METRIC_NAME = "recommend_question_quality"
    METRIC_CN = "推荐问题质量"
    DIMENSION = "compliance"

    def __init__(self):
        # 加载 recommend_prompt 规范
        self._prompt_spec = self._load_prompt_spec()

    def _load_prompt_spec(self) -> str:
        """加载推荐问题生成规范"""
        spec_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "skills", "recommend_prompt", "recommend_prompt.md"
        )
        if os.path.exists(spec_path):
            with open(spec_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def calculate(
        self,
        questions: List[str],
        raw_report: str,
        module: str = "alarm"
    ) -> Dict[str, Any]:
        """评估推荐问题质量

        Args:
            questions: SSE 中捕获的3个推荐问题列表
            raw_report: 对应的解读报告原文（用于关联性判断）
            module: 模块类型 alarm/event

        Returns:
            包含三个维度得分和综合得分的字典（0~1）
        """
        if not questions:
            return {
                "metric_name": self.METRIC_NAME,
                "metric_cn": self.METRIC_CN,
                "accuracy": None,
                "is_extraction_failure": True,
                "dimension": self.DIMENSION,
                "detail": {"reason": "未捕获到推荐问题"}
            }

        from core.llm_client import LLMClient
        llm = LLMClient()

        system_prompt = f"""你是推荐问题质量评审专家，负责评估AI生成的3个推荐问题的质量。

## 评估规范（推荐问题生成标准）

{self._prompt_spec}

## 评估任务

你需要从以下三个维度评估，每个维度给出 0~1 的分数：

### 维度1：规范符合度（compliance_score）
逐条检查每个问题是否符合生成规范：
- 不超过30个字
- 只问"查什么/确认什么"，不含"隔离""阻断""查杀"等处置动作
- 包含至少一个具体实体（IP/进程/域名/文件名/Hash等）
- 工具边界：不能问文件是否存在、实时内存/CPU/DNS缓存等无工具支持的内容
- 资产IP规则：非资产IP（攻击者IP）不能用于本地进程排查，只能查情报/告警

### 维度2：报告关联性（relevance_score）
检查问题中引用的实体（IP/进程/域名等）是否均能在解读报告中找到来源，不得引用报告中不存在的实体。

### 维度3：问题多样性（diversity_score）
3个问题是否覆盖不同排查方向（本地排查/关联扩散/情报回溯），是否存在重复或高度相似的问题。

## 输出格式（严格JSON，不含其他文字）

{{
  "compliance_score": 0.0~1.0,
  "relevance_score": 0.0~1.0,
  "diversity_score": 0.0~1.0,
  "overall_score": 0.0~1.0,
  "is_qualified": true/false,
  "fail_reasons": ["未达标的维度说明，如规范符合度不足（0.6<0.8）"],
  "compliance_detail": "规范符合度说明，指出具体违规项（如有）",
  "relevance_detail": "关联性说明，指出哪些实体来自报告/哪些无法溯源",
  "diversity_detail": "多样性说明，指出是否有重复或覆盖不全",
  "questions_review": ["问题1评语", "问题2评语", "问题3评语"]
}}

overall_score = (compliance_score + relevance_score + diversity_score) / 3，保留2位小数。
合格判定：三个维度分数均 ≥ 0.8 时 is_qualified=true，否则 is_qualified=false，并在 fail_reasons 中列出未达标的维度。
"""

        module_name = "告警" if module == "alarm" else "事件"
        user_prompt = f"""## 解读报告（{module_name}解读）

{raw_report[:3000]}

## 待评估的3个推荐问题

{json.dumps(questions, ensure_ascii=False, indent=2)}

请按照评估规范对以上3个推荐问题进行评估，输出JSON格式结果。"""

        try:
            response = llm.call_llm(system_prompt, user_prompt, max_tokens=2048)
            if not response:
                return self._error_result("LLM评估无响应")

            # 提取JSON
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return self._error_result("LLM响应无法解析为JSON")

            result = json.loads(json_match.group())

            compliance = float(result.get("compliance_score", 0))
            relevance  = float(result.get("relevance_score", 0))
            diversity  = float(result.get("diversity_score", 0))
            overall    = round((compliance + relevance + diversity) / 3, 2)

            # 合格判定：三个维度均 ≥ 0.8 才算合格
            THRESHOLD = 0.8
            compliance_ok = compliance >= THRESHOLD
            relevance_ok  = relevance  >= THRESHOLD
            diversity_ok  = diversity  >= THRESHOLD
            is_qualified  = compliance_ok and relevance_ok and diversity_ok

            fail_reasons = result.get("fail_reasons", [])
            if not fail_reasons:
                # 如果 LLM 没有输出 fail_reasons，自动生成
                if not compliance_ok:
                    fail_reasons.append(f"规范符合度不足（{compliance:.2f}<{THRESHOLD}）")
                if not relevance_ok:
                    fail_reasons.append(f"报告关联性不足（{relevance:.2f}<{THRESHOLD}）")
                if not diversity_ok:
                    fail_reasons.append(f"问题多样性不足（{diversity:.2f}<{THRESHOLD}）")

            return {
                "metric_name": self.METRIC_NAME,
                "metric_cn": self.METRIC_CN,
                "accuracy": overall,          # 三维度均值（0~1），用于记录趋势
                "is_qualified": is_qualified,  # 合格/不合格（核心结论）
                "is_passed": is_qualified,
                "dimension": self.DIMENSION,
                "detail": {
                    "questions": questions,
                    "compliance_score": compliance,
                    "compliance_passed": compliance_ok,
                    "relevance_score": relevance,
                    "relevance_passed": relevance_ok,
                    "diversity_score": diversity,
                    "diversity_passed": diversity_ok,
                    "fail_reasons": fail_reasons,
                    "compliance_detail": result.get("compliance_detail", ""),
                    "relevance_detail": result.get("relevance_detail", ""),
                    "diversity_detail": result.get("diversity_detail", ""),
                    "questions_review": result.get("questions_review", []),
                }
            }

        except Exception as e:
            return self._error_result(f"评估异常: {e}")

    def _error_result(self, reason: str) -> Dict[str, Any]:
        return {
            "metric_name": self.METRIC_NAME,
            "metric_cn": self.METRIC_CN,
            "accuracy": None,
            "is_extraction_failure": True,
            "dimension": self.DIMENSION,
            "detail": {"reason": reason}
        }

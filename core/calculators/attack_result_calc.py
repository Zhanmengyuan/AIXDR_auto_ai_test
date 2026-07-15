"""
攻击结果准确率计算器
比较 AI 解读 Markdown 报告中"攻击结果"字段与 API (pageAlarm/pageEvent) 返回的 AI_RESULT/RESULT 真实值

API 字段含义:
    AI_RESULT 或 RESULT → 成功/失败/未知

多样本评测采用宏平均F1计算方式
"""
from typing import Any, Dict, List, Tuple
from .base_calculator import BaseCalculator, MetricResult


# API 标准标签 → AI 可能出现的同义/近义表达
ATTACK_RESULT_SYNONYMS = {
    "成功": ["成功", "攻击成功", "攻击有效", "有效", "确认攻击", "攻击确认", "是"],
    "失败": ["失败", "攻击失败", "攻击无效", "无效", "非攻击", "否"],
    "未知": ["未知", "不能确认", "不确定", "无法确定", "无法判断", "可疑", "待确认", ""],
}


def match_attack_result(ai_text: str, api_label: str) -> float:
    """判断 AI 提取的攻击结果文本是否与 API 标准标签匹配

    Args:
        ai_text: AI 从 Markdown 中提取的"攻击结果"文本
        api_label: API 返回的标准标签（成功/失败/未知）

    Returns:
        1.0 = 匹配, 0.5 = 部分匹配(包含关系), 0.0 = 不匹配
    """
    if not api_label:
        return 0.0

    ai_clean = ai_text.strip().strip('*').strip().rstrip('|').strip() if ai_text else ""
    api_clean = api_label.strip()

    # 1. 精确匹配
    if ai_clean == api_clean:
        return 1.0

    # 2. 同义词匹配
    synonyms = ATTACK_RESULT_SYNONYMS.get(api_clean, [api_clean])
    if ai_clean in synonyms:
        return 1.0

    # 3. 检查 AI 文本是否包含同义词中的任意一个
    for syn in synonyms:
        if syn and len(syn) >= 2 and syn in ai_clean:
            return 1.0

    # 4. 部分匹配：一方包含另一方
    if ai_clean and (ai_clean in api_clean or api_clean in ai_clean):
        return 0.5

    # 5. 检查是否有任何同义词部分匹配
    for syn in synonyms:
        if syn and len(syn) >= 2:
            if syn in ai_clean or ai_clean in syn:
                return 0.5

    return 0.0


class AttackResultCalculator(BaseCalculator):
    """攻击结果准确率计算器（支持宏平均F1）"""

    METRIC_NAME = "attack_result_accuracy"
    METRIC_CN = "攻击结果准确率"
    MAX_SCORE = 100.0
    EXPECTED_F1 = 0.95
    DEDUCTION_INTERVAL = 0.05
    DEDUCTION_AMOUNT = 5

    # 攻击结果类别（多分类）
    ATTACK_CLASSES = ["成功", "失败", "未知"]

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算攻击结果准确率

        Args:
            ai_data: AI 解析的数据，包含 attack_result 字段
            api_data: API 返回的数据，包含 attack_result 字段

        Returns:
            MetricResult: 指标计算结果
        """
        ai_value = self._normalize_value(ai_data.get("attack_result"))
        api_value = self._normalize_value(api_data.get("attack_result"))

        accuracy = match_attack_result(ai_value, api_value)

        detail = {
            "ai_attack_result": ai_value,
            "api_attack_result": api_value,
            "ai_result_raw": api_data.get("ai_result_raw", ""),
            "result_raw": api_data.get("result_raw", ""),
            "match_type": "exact" if accuracy >= 1.0 else ("partial" if accuracy >= 0.5 else "none"),
        }

        return self._create_result(ai_value, api_value, accuracy, detail)

    def calculate_batch_f1(
        self,
        pairs: List[Tuple[str, str]]
    ) -> MetricResult:
        """批量计算攻击结果宏平均F1

        对每一对 (AI文本, API标签) 先归一化到三个类别之一，
        再计算每类的精确率/召回率/F1，最后宏平均。

        Args:
            pairs: [(ai_text, api_label), ...] 列表

        Returns:
            宏平均F1 MetricResult
        """
        y_true = []
        y_pred = []

        for ai_text, api_label in pairs:
            ai_class = self._normalize_to_class(ai_text)
            api_class = self._normalize_to_class(api_label)
            y_pred.append(ai_class)
            y_true.append(api_class)

        macro_f1 = self._calculate_macro_f1(y_true, y_pred)

        score = self._calculate_score(macro_f1)

        detail = {
            "macro_f1": macro_f1,
            "expected_f1": self.EXPECTED_F1,
            "total_samples": len(pairs),
            "classes": self.ATTACK_CLASSES,
            "y_true": y_true,
            "y_pred": y_pred,
        }

        return MetricResult(
            metric_name="attack_result_macro_f1",
            metric_cn="攻击结果宏平均F1",
            score=score,
            max_score=self.MAX_SCORE,
            accuracy=macro_f1,
            ai_value=f"{macro_f1:.4f}",
            api_value=f">={self.EXPECTED_F1}",
            detail=detail,
            is_passed=macro_f1 >= self.EXPECTED_F1
        )

    def _normalize_to_class(self, text: str) -> str:
        """将攻击结果文本归一化到三个标准类别之一"""
        if not text or not text.strip():
            return ""

        text = text.strip().strip('*').strip().rstrip('|').strip()

        for cls, synonyms in ATTACK_RESULT_SYNONYMS.items():
            if text == cls:
                return cls
            if text in synonyms:
                return cls
            for syn in synonyms:
                if syn and len(syn) >= 2 and (syn in text or text in syn):
                    return cls

        return ""

    def _calculate_macro_f1(self, y_true: List[str], y_pred: List[str]) -> float:
        """计算多分类宏平均F1"""
        all_labels = set(y_true + y_pred)
        all_labels.discard("")
        labels = [c for c in self.ATTACK_CLASSES if c in all_labels]

        if not labels:
            return 0.0

        f1_scores = []

        for label in labels:
            tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
            fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
            fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            f1_scores.append(f1)

        macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0.0
        return macro_f1

    def _calculate_score(self, macro_f1: float) -> float:
        """根据宏平均F1计算得分"""
        if macro_f1 >= self.EXPECTED_F1:
            return float(self.MAX_SCORE)

        deduction = ((self.EXPECTED_F1 - macro_f1) / self.DEDUCTION_INTERVAL) * self.DEDUCTION_AMOUNT
        score = self.MAX_SCORE - deduction

        return max(0.0, score)

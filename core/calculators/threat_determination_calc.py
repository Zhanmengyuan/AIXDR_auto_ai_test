"""
威胁定性（威胁判定）准确率计算器
比较 AI 解读 Markdown 报告中"威胁定性"字段与 API (pageAlarm) 返回的 ALERT_RESULT_FLAG 真实值

API ALERT_RESULT_FLAG 含义:
    1  → 正报
    2  → 误报
    3 或空 → 不能确认

多样本评测采用宏平均F1计算方式
"""
from typing import Any, Dict, List, Optional, Tuple
from .base_calculator import BaseCalculator, MetricResult


# API 标准标签 → AI 可能出现的同义/近义表达
THREAT_DETERMINATION_SYNONYMS = {
    "正报": ["正报", "攻击成功", "确认攻击", "攻击确认", "攻击行为", "真实告警", "确认"],
    "误报": ["误报", "攻击失败", "非攻击行为", "未发现攻击", "无攻击", "虚假告警", "忽略"],
    "不能确认": ["不能确认", "未知", "无法确定", "无法判断", "不确定", "可疑", "待确认"],
}


def match_threat_determination(ai_text: str, api_label: str) -> float:
    """判断 AI 提取的威胁定性文本是否与 API 标准标签匹配

    Args:
        ai_text: AI 从 Markdown 中提取的"威胁定性"文本
        api_label: API 返回的标准标签（正报/误报/不能确认）

    Returns:
        1.0 = 匹配, 0.5 = 部分匹配(包含关系), 0.0 = 不匹配
    """
    if not ai_text or not api_label:
        return 0.0

    ai_clean = ai_text.strip().strip('*').strip().rstrip('|').strip()
    api_clean = api_label.strip()

    # 1. 精确匹配
    if ai_clean == api_clean:
        return 1.0

    # 2. 同义词匹配
    synonyms = THREAT_DETERMINATION_SYNONYMS.get(api_clean, [api_clean])
    if ai_clean in synonyms:
        return 1.0

    # 3. 检查 AI 文本是否包含同义词中的任意一个
    for syn in synonyms:
        if syn and len(syn) >= 2 and syn in ai_clean:
            return 1.0

    # 4. 部分匹配：一方包含另一方
    if ai_clean in api_clean or api_clean in ai_clean:
        return 0.5

    # 5. 检查是否有任何同义词部分匹配
    for syn in synonyms:
        if syn and len(syn) >= 2:
            if syn in ai_clean or ai_clean in syn:
                return 0.5

    return 0.0


class ThreatDeterminationCalculator(BaseCalculator):
    """威胁定性准确率计算器（支持宏平均F1）"""

    METRIC_NAME = "threat_determination_accuracy"
    METRIC_CN = "威胁定性准确率"
    MAX_SCORE = 100.0
    EXPECTED_F1 = 0.95
    DEDUCTION_INTERVAL = 0.05
    DEDUCTION_AMOUNT = 5

    # 威胁定性类别（多分类）
    THREAT_CLASSES = ["正报", "误报", "不能确认"]

    def calculate(self, ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> MetricResult:
        """计算威胁定性准确率

        Args:
            ai_data: AI 解析的数据，包含 threat_determination 字段
            api_data: API 返回的数据，包含 threat_determination 字段

        Returns:
            MetricResult: 指标计算结果
        """
        ai_value = self._normalize_value(ai_data.get("threat_determination"))
        api_value = self._normalize_value(api_data.get("threat_determination"))

        accuracy = match_threat_determination(ai_value, api_value)

        detail = {
            "ai_threat_determination": ai_value,
            "api_threat_determination": api_value,
            "api_alert_result_flag": api_data.get("alert_result_flag_raw", ""),
            "match_type": "exact" if accuracy >= 1.0 else ("partial" if accuracy >= 0.5 else "none"),
        }

        return self._create_result(ai_value, api_value, accuracy, detail)

    def calculate_batch_f1(
        self,
        pairs: List[Tuple[str, str]]
    ) -> MetricResult:
        """批量计算威胁定性宏平均F1

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
            "classes": self.THREAT_CLASSES,
            "y_true": y_true,
            "y_pred": y_pred,
        }

        return MetricResult(
            metric_name="threat_determination_macro_f1",
            metric_cn="威胁定性宏平均F1",
            score=score,
            max_score=self.MAX_SCORE,
            accuracy=macro_f1,
            ai_value=f"{macro_f1:.4f}",
            api_value=f">={self.EXPECTED_F1}",
            detail=detail,
            is_passed=macro_f1 >= self.EXPECTED_F1
        )

    def _normalize_to_class(self, text: str) -> str:
        """将威胁定性文本归一化到三个标准类别之一"""
        if not text or not text.strip():
            return ""

        text = text.strip().strip('*').strip().rstrip('|').strip()

        for cls, synonyms in THREAT_DETERMINATION_SYNONYMS.items():
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
        labels = [c for c in self.THREAT_CLASSES if c in all_labels]

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

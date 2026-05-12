"""
综合报告生成器
生成资产解读模块的评测报告
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, List
from dataclasses import dataclass, asdict


@dataclass
class MetricScore:
    """单个指标得分"""
    name: str
    cn_name: str
    score: float
    max_score: float
    accuracy: float
    is_passed: bool
    detail: Dict[str, Any]


@dataclass
class AssetMetricsReport:
    """资产解读模块评测报告"""
    asset_id: str
    timestamp: str
    total_score: float
    max_score: float
    pass_rate: float
    metrics: List[MetricScore]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReportGenerator:
    """报告生成器"""

    def __init__(self, output_dir: str = None):
        if output_dir is None:
            output_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "..", "outputs"
            )
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(
        self,
        asset_id: str,
        metric_results: List[Any],
        ai_data: Dict[str, Any],
        api_data: Dict[str, Any]
    ) -> AssetMetricsReport:
        """生成评测报告"""
        metrics = []
        total_score = 0
        max_score = 0
        passed_count = 0

        for result in metric_results:
            if hasattr(result, 'to_dict'):
                metric_dict = result.to_dict()
            else:
                metric_dict = result

            metrics.append(MetricScore(
                name=metric_dict.get('metric_name', ''),
                cn_name=metric_dict.get('metric_cn', ''),
                score=metric_dict.get('score', 0),
                max_score=metric_dict.get('max_score', 0),
                accuracy=metric_dict.get('accuracy', 0),
                is_passed=metric_dict.get('is_passed', False),
                detail=metric_dict.get('detail', {})
            ))

            total_score += metric_dict.get('score', 0)
            max_score += metric_dict.get('max_score', 0)
            if metric_dict.get('is_passed', False):
                passed_count += 1

        pass_rate = passed_count / len(metrics) if metrics else 0

        report = AssetMetricsReport(
            asset_id=asset_id,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_score=total_score,
            max_score=max_score,
            pass_rate=pass_rate,
            metrics=metrics
        )

        self._save_report(report)

        return report

    def _save_report(self, report: AssetMetricsReport):
        """保存报告到JSON文件"""
        filename = f"metrics_report_{report.asset_id}.json"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)

        print(f"📄 报告已保存: {filepath}")

    def print_summary(self, report: AssetMetricsReport):
        """打印报告摘要"""
        print("\n" + "=" * 60)
        print(f"📋 资产解读模块评测报告 - 资产ID: {report.asset_id}")
        print("=" * 60)
        print(f"⏰ 评测时间: {report.timestamp}")
        print(f"📊 总得分: {report.total_score:.1f}/{report.max_score}")
        print(f"📈 通过率: {report.pass_rate*100:.1f}%")
        print("-" * 60)

        for metric in report.metrics:
            status = "✅" if metric.is_passed else "❌"
            print(f"{status} {metric.cn_name}: {metric.score:.1f}/{metric.max_score} "
                  f"(准确率: {metric.accuracy*100:.1f}%)")

        print("=" * 60)

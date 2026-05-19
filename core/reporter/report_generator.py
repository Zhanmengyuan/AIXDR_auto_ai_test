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


class TraceReportGenerator:
    """溯源测试报告生成器"""

    MODULE_NAMES = {
        "asset": "资产解读",
        "vuln": "漏洞解读",
        "alert": "告警解读",
        "event": "事件解读"
    }

    def __init__(self, results: Dict[str, Any], config: Any):
        self.results = results
        self.config = config

    def generate_trace_report(self) -> Dict[str, Any]:
        """生成溯源测试报告"""
        report = {
            "report_metadata": {
                "title": "AI解读模块自动化测试溯源报告",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "test_agent_version": "1.0.0",
                "environment": "生产环境"
            },
            "modules": {}
        }

        for module, results in self.results.items():
            if results:
                module_report = self._generate_module_trace(module, results)
                report["modules"][module] = module_report

        return report

    def _generate_module_trace(self, module: str, results: List[Any]) -> Dict[str, Any]:
        """生成单个模块的溯源报告"""
        module_name = self.MODULE_NAMES.get(module, module)

        module_descriptions = {
            "asset": "测试AI对资产信息解读的准确性，包括风险等级、风险评分、漏洞列表、告警列表、事件列表等字段的提取和比对",
            "vuln": "测试AI对漏洞信息解读的准确性，包括CVSS评分、风险等级、影响版本等字段的提取和比对",
            "alert": "测试AI对告警信息解读的准确性，包括攻击判定、风险等级等字段的提取和比对",
            "event": "测试AI对事件信息解读的准确性，包括事件类型、风险等级等字段的提取和比对"
        }

        module_report = {
            "module_name": module_name,
            "module_description": module_descriptions.get(module, ""),
            "single_asset_results": [],
            "multi_asset_summary": {}
        }

        for result in results:
            if result.success and result.parsed_data:
                asset_result = self._generate_single_asset_trace(module, result)
                module_report["single_asset_results"].append(asset_result)

        if module_report["single_asset_results"]:
            module_report["multi_asset_summary"] = self._generate_multi_asset_summary(
                module, module_report["single_asset_results"]
            )

        return module_report

    def _generate_single_asset_trace(self, module: str, result: Any) -> Dict[str, Any]:
        """生成单个资产的溯源数据"""
        asset_id = result.parsed_data.get("asset_id", "")

        api_client_map = {
            "asset": AssetAPIClient(self.config) if 'AssetAPIClient' in dir() else None,
            "vuln": VulnAPIClient(self.config) if 'VulnAPIClient' in dir() else None,
            "alert": AlertAPIClient(self.config) if 'AlertAPIClient' in dir() else None,
            "event": EventAPIClient(self.config) if 'EventAPIClient' in dir() else None
        }

        api_client = api_client_map.get(module)
        api_data = {}
        if api_client:
            try:
                api_get_method = getattr(api_client, f"get_{module}_detail", None)
                if api_get_method:
                    api_data = api_get_method(asset_id)
            except Exception:
                pass

        trace = {
            "asset_id": asset_id,
            "test_timestamp": result.timestamp,
            "ai_interpreted_data": result.parsed_data,
            "ground_truth_data": api_data,
            "metrics": {},
            "data_source_tracing": {
                "ai_interpretation_source": "AI模型 flowStream API",
                "ground_truth_source": self._get_api_source_description(module),
                "issue_source": "待分析"
            }
        }

        if hasattr(result, 'metrics') and result.metrics:
            trace["metrics"] = self._format_metrics_with_trace(result.metrics, result.parsed_data, api_data)

        return trace

    def _format_metrics_with_trace(self, metrics: Dict[str, Any], ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> Dict[str, Any]:
        """格式化指标，添加溯源信息"""
        formatted = {}
        metric_names = {
            "risk_level_accuracy": "风险等级准确率",
            "risk_score_accuracy": "风险评分准确率",
            "field_completeness": "字段完整率",
            "vuln_list_accuracy": "漏洞列表准确率",
            "alert_list_accuracy": "告警列表准确率",
            "event_list_accuracy": "事件列表准确率",
            "format_compliance": "格式合规率"
        }

        for key, metric in metrics.items():
            if isinstance(metric, dict):
                formatted[key] = {
                    "cn_name": metric_names.get(key, key),
                    "value": metric.get("accuracy", metric.get("value", 0)),
                    "ai_value": metric.get("ai_value"),
                    "api_value": metric.get("api_value"),
                    "score": metric.get("score", 0),
                    "max_score": metric.get("max_score", 0),
                    "is_correct": metric.get("passed", False),
                    "explanation": self._generate_metric_explanation(key, metric, ai_data, api_data)
                }

        return formatted

    def _generate_metric_explanation(self, metric_key: str, metric: Dict[str, Any], ai_data: Dict[str, Any], api_data: Dict[str, Any]) -> str:
        """生成指标说明"""
        ai_value = metric.get("ai_value")
        api_value = metric.get("api_value")

        explanations = {
            "risk_level_accuracy": f"AI解读的风险等级为'{ai_value}'，API真实值为'{api_value}'",
            "risk_score_accuracy": self._generate_risk_score_explanation(ai_value, api_value),
            "field_completeness": f"字段完整率为{metric.get('value', 0)*100:.1f}%",
            "vuln_list_accuracy": f"AI解读发现{metric.get('ai_vuln_count', 0)}个漏洞，API真实有{metric.get('api_vuln_count', 0)}个",
            "alert_list_accuracy": f"AI解读关联{metric.get('ai_alert_count', 0)}个告警，API真实有{metric.get('api_alert_count', 0)}个",
            "event_list_accuracy": f"AI解读关联{metric.get('ai_event_count', 0)}个事件，API真实有{metric.get('api_event_count', 0)}个",
            "format_compliance": f"格式合规率为{metric.get('value', 0)*100:.1f}%"
        }

        return explanations.get(metric_key, "指标计算中...")

    def _generate_risk_score_explanation(self, ai_value: Any, api_value: Any) -> str:
        """生成风险评分说明"""
        try:
            ai_num = float(ai_value) if ai_value is not None else 0
            api_num = float(api_value) if api_value is not None else 0
            diff = abs(ai_num - api_num)
            return f"AI解读的风险评分为'{ai_value}'，API真实值为'{api_value}'，差异为{diff}分"
        except (ValueError, TypeError):
            return f"AI解读的风险评分为'{ai_value}'，API真实值为'{api_value}'"

    def _generate_multi_asset_summary(self, module: str, single_results: List[Dict]) -> Dict[str, Any]:
        """生成多样本汇总"""
        total = len(single_results)

        summary = {
            "total_assets": total,
            "metrics_breakdown": {}
        }

        if total > 0:
            all_first_packet = [r.get("first_packet_time", 0) for r in single_results]
            all_total_time = [r.get("total_response_time", 0) for r in single_results]

            summary["avg_first_packet_time"] = sum(all_first_packet) / total if all_first_packet else 0
            summary["avg_response_time"] = sum(all_total_time) / total if all_total_time else 0

            risk_level_accuracies = []
            for r in single_results:
                metrics = r.get("metrics", {})
                if "risk_level_accuracy" in metrics:
                    risk_level_accuracies.append(metrics["risk_level_accuracy"].get("value", 0))

            if risk_level_accuracies:
                summary["risk_level_f1"] = sum(risk_level_accuracies) / len(risk_level_accuracies)
            else:
                summary["risk_level_f1"] = 0

        return summary

    def _get_api_source_description(self, module: str) -> str:
        """获取API数据源描述"""
        sources = {
            "asset": "资产详情API接口 /ai/asset/detail + 漏洞列表API + 告警列表API + 事件列表API",
            "vuln": "漏洞详情API接口 /ai/vuln/detail",
            "alert": "告警详情API接口 /ai/alert/detail",
            "event": "事件详情API接口 /ai/event/detail"
        }
        return sources.get(module, "API接口")

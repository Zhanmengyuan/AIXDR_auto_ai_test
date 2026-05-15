"""
资产解读模块评测 - 整合测试（单资产）
======================================

资产解读模块评测指标（单资产）：
1. 资产风险评分准确率      - 10分
2. 资产关键字段完整率      - 10分
3. 漏洞列表准确率          - 10分
4. 关联告警准确率          - 5分
5. 关联事件准确率          - 5分
6. 格式合规率              - 5分
7. 稳定性（重复执行）      - 5分
8. 整体内容正确性         - 20分

多资产批量评测指标（使用独立脚本）：
- 风险等级准确率（宏平均F1）→ test_risk_level_batch.py
- 首包响应时间 / 平均响应时间 → test_response_time.py
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.config_loader import ConfigLoader
from core.extractors import AIExtractor
from core.api_clients import AssetAPIClient, VulnAPIClient, AlertAPIClient, EventAPIClient
from core.calculators import (
    FieldCompletenessCalculator,
    VulnAccuracyCalculator,
    RiskScoreCalculator,
    AlertAccuracyCalculator,
    EventAccuracyCalculator,
    FormatComplianceCalculator
)
from core.reporter import ReportGenerator


def load_ai_data(asset_id: str, outputs_dir: str) -> tuple:
    """加载AI解析数据，返回(parsed_data, markdown_text)"""
    # outputs目录在项目根目录
    project_root = os.path.dirname(os.path.dirname(__file__))
    json_file = os.path.join(project_root, "outputs", "raw_json", f"asset_data_{asset_id}.json")
    md_file = os.path.join(project_root, "outputs", "raw_md", f"asset_report_{asset_id}.md")

    if not os.path.exists(json_file):
        print(f"❌ AI解析数据不存在: {json_file}")
        print(f"💡 请先运行 test_AI.py 生成解析数据")
        return {}, ""

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    parsed_fields = data.get('parsed_fields', {})

    markdown_text = ""
    if os.path.exists(md_file):
        with open(md_file, 'r', encoding='utf-8') as f:
            markdown_text = f.read()

    return parsed_fields, markdown_text


def run_asset_metrics_evaluation(asset_id: str = None):
    """运行资产解读模块评测"""
    print("\n" + "=" * 60)
    print("🚀 资产解读模块自动化评测")
    print("=" * 60)

    config = ConfigLoader()

    if asset_id is None:
        asset_id = config.test_assets[0]

    print(f"📋 评测资产ID: {asset_id}")

    project_root = os.path.dirname(os.path.dirname(__file__))
    outputs_dir = os.path.join(project_root, "outputs")
    os.makedirs(outputs_dir, exist_ok=True)

    print("\n📥 步骤1: 加载AI解析数据...")
    ai_data, markdown_text = load_ai_data(asset_id, outputs_dir)
    if not ai_data:
        return
    print(f"✅ AI数据加载成功，包含 {len(ai_data)} 个字段")
    print(f"✅ Markdown文本长度: {len(markdown_text)} 字符")

    print("\n📥 步骤2: 调用API获取标准数据...")

    asset_client = AssetAPIClient(config)
    vuln_client = VulnAPIClient(config)
    alert_client = AlertAPIClient(config)
    event_client = EventAPIClient(config)

    api_asset_data = asset_client.get_asset_detail(asset_id)
    if "error" in api_asset_data:
        print(f"❌ 资产详情API调用失败: {api_asset_data['error']}")
        return
    print(f"✅ 资产详情API调用成功")

    api_vulns = vuln_client.get_asset_vulns(asset_id)
    api_asset_data['vuln_list'] = api_vulns
    print(f"✅ 漏洞列表API调用成功，获取 {len(api_vulns)} 个漏洞")

    api_alerts = alert_client.get_asset_alerts(asset_id)
    api_asset_data['alert_list'] = api_alerts
    print(f"✅ 告警列表API调用成功，获取 {len(api_alerts)} 个告警")

    api_events = event_client.get_asset_events(asset_id)
    api_asset_data['event_list'] = api_events
    print(f"✅ 事件列表API调用成功，获取 {len(api_events)} 个事件")

    print("\n📊 步骤3: 计算各项指标...")

    metric_results = []

    # 1. 资产风险评分准确率 (10分)
    risk_score_calc = RiskScoreCalculator()
    risk_score_result = risk_score_calc.calculate(ai_data, api_asset_data)
    metric_results.append(risk_score_result)
    print(f"  - 资产风险评分准确率: {risk_score_result.accuracy*100:.1f}%")

    # 2. 资产关键字段完整率 (10分)
    field_calc = FieldCompletenessCalculator()
    field_result = field_calc.calculate_with_comparison(ai_data, api_asset_data)
    metric_results.append(field_result)
    print(f"  - 资产关键字段完整率: {field_result.accuracy*100:.1f}%")

    # 3. 漏洞列表准确率 (10分)
    vuln_calc = VulnAccuracyCalculator()
    vuln_result = vuln_calc.calculate(ai_data, api_asset_data)
    metric_results.append(vuln_result)
    print(f"  - 漏洞列表准确率: {vuln_result.accuracy*100:.1f}%")

    # 4. 关联告警准确率 (5分)
    alert_calc = AlertAccuracyCalculator()
    alert_result = alert_calc.calculate(ai_data, api_asset_data)
    metric_results.append(alert_result)
    print(f"  - 关联告警准确率: {alert_result.accuracy*100:.1f}%")

    # 5. 关联事件准确率 (5分)
    event_calc = EventAccuracyCalculator()
    event_result = event_calc.calculate(ai_data, api_asset_data)
    metric_results.append(event_result)
    print(f"  - 关联事件准确率: {event_result.accuracy*100:.1f}%")

    # 6. 格式合规率 (5分)
    format_calc = FormatComplianceCalculator()
    format_result = format_calc.calculate({"raw_text": markdown_text})
    metric_results.append(format_result)
    print(f"  - 格式合规率: {format_result.accuracy*100:.1f}%")

    print("\n📋 步骤4: 生成评测报告...")

    reporter = ReportGenerator(outputs_dir)
    report = reporter.generate(asset_id, metric_results, ai_data, api_asset_data)

    reporter.print_summary(report)

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='资产解读模块评测')
    parser.add_argument('--asset-id', type=str, help='资产ID')

    args = parser.parse_args()

    run_asset_metrics_evaluation(args.asset_id)

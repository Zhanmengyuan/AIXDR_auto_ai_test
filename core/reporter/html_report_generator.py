"""
HTML 可视化报告生成器
生成美观易读的 HTML 报告，显示指标值、计算溯源和出处
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, List
from pathlib import Path


class HTMLReportGenerator:
    """HTML 报告生成器"""

    # CSS 样式
    CSS = """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: #333;
        line-height: 1.6;
        padding: 20px;
        min-height: 100vh;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
    }

    .header {
        background: white;
        border-radius: 12px;
        padding: 30px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    .header h1 {
        font-size: 28px;
        color: #667eea;
        margin-bottom: 10px;
    }

    .header-meta {
        display: flex;
        gap: 20px;
        color: #666;
        font-size: 14px;
        flex-wrap: wrap;
    }

    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-bottom: 20px;
    }

    .summary-card {
        background: white;
        border-radius: 12px;
        padding: 25px;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.3s;
    }

    .summary-card:hover {
        transform: translateY(-5px);
    }

    .summary-card .value {
        font-size: 36px;
        font-weight: bold;
        margin: 10px 0;
    }

    .summary-card.pass .value { color: #48bb78; }
    .summary-card.fail .value { color: #f56565; }
    .summary-card.neutral .value { color: #667eea; }

    .summary-card .label {
        color: #666;
        font-size: 14px;
    }

    .module-section {
        background: white;
        border-radius: 12px;
        padding: 25px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    .module-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 15px;
        border-bottom: 2px solid #eee;
    }

    .module-title {
        font-size: 22px;
        font-weight: bold;
        color: #333;
    }

    .module-stats {
        display: flex;
        gap: 15px;
    }

    .stat-badge {
        padding: 5px 12px;
        border-radius: 20px;
        font-size: 13px;
        font-weight: 500;
    }

    .stat-badge.success { background: #c6f6d5; color: #22543d; }
    .stat-badge.error { background: #fed7d7; color: #742a2a; }
    .stat-badge.info { background: #bee3f8; color: #2a4365; }

    .test-case {
        margin-bottom: 20px;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        overflow: hidden;
    }

    .test-case-header {
        background: #f7fafc;
        padding: 15px 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
    }

    .test-case-header:hover {
        background: #edf2f7;
    }

    .test-case-title {
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .status-icon {
        font-size: 24px;
    }

    .test-case-body {
        padding: 20px;
        display: none;
    }

    .test-case-body.open {
        display: block;
    }

    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 15px;
        margin-bottom: 20px;
    }

    .metric-card {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        overflow: hidden;
    }

    .metric-header {
        padding: 12px 15px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .metric-header.pass { background: #c6f6d5; }
    .metric-header.fail { background: #fed7d7; }

    .metric-name {
        font-weight: 600;
    }

    .metric-score {
        font-size: 18px;
        font-weight: bold;
    }

    .metric-content {
        padding: 15px;
    }

    .metric-details {
        font-size: 13px;
    }

    .detail-row {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #f0f0f0;
    }

    .detail-row:last-child {
        border-bottom: none;
    }

    .detail-label {
        font-weight: 500;
        color: #666;
    }

    .detail-value {
        color: #333;
    }

    .ai-value {
        color: #667eea;
    }

    .api-value {
        color: #48bb78;
    }

    .field-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
        font-size: 13px;
    }

    .field-table th,
    .field-table td {
        padding: 10px;
        text-align: left;
        border-bottom: 1px solid #e2e8f0;
    }

    .field-table th {
        background: #f7fafc;
        font-weight: 600;
    }

    .field-table tr.match td { background: #f0fff4; }
    .field-table tr.mismatch td { background: #fff5f5; }
    .field-table tr.missing td { background: #fffaf0; }

    .status-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 500;
    }

    .status-badge.match { background: #c6f6d5; color: #22543d; }
    .status-badge.mismatch { background: #fed7d7; color: #742a2a; }
    .status-badge.missing { background: #feebc8; color: #7c2d12; }

    .collapse-toggle {
        background: #667eea;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 14px;
    }

    .collapse-toggle:hover {
        background: #5a67d8;
    }

    .source-section {
        background: #f7fafc;
        padding: 15px;
        border-radius: 8px;
        margin-top: 15px;
    }

    .source-title {
        font-weight: 600;
        margin-bottom: 10px;
        color: #667eea;
    }

    .source-info {
        font-size: 13px;
        color: #666;
    }

    .time-info {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 10px;
        margin-bottom: 15px;
    }

    .time-card {
        background: #f7fafc;
        padding: 12px;
        border-radius: 6px;
        text-align: center;
    }

    .time-value {
        font-size: 20px;
        font-weight: bold;
        color: #667eea;
    }

    .time-label {
        font-size: 12px;
        color: #666;
    }

    .raw-data-toggle {
        margin-top: 15px;
        text-align: right;
    }

    .raw-data {
        background: #1a1a2e;
        color: #16c79a;
        padding: 15px;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        overflow-x: auto;
        margin-top: 10px;
        display: none;
    }

    .raw-data.open {
        display: block;
    }
    """

    # JavaScript
    JS = """
    function toggleTestCase(element) {
        const body = element.nextElementSibling;
        body.classList.toggle('open');
    }

    function toggleRawData(element) {
        const rawData = element.nextElementSibling;
        rawData.classList.toggle('open');
        element.textContent = rawData.classList.contains('open') ? '隐藏原始数据' : '显示原始数据';
    }

    document.addEventListener('DOMContentLoaded', function() {
        console.log('AI测试报告已加载');
    });
    """

    def __init__(self, output_dir: str = None):
        if output_dir is None:
            output_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "..", "outputs"
            )
        self.output_dir = output_dir
        self.html_reports_dir = os.path.join(output_dir, "html_reports")
        os.makedirs(self.html_reports_dir, exist_ok=True)

    def generate(self, report_data: Dict[str, Any]) -> List[str]:
        """按模块生成 HTML 报告，返回所有生成的文件路径"""
        generated_paths = []
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        module_names = {
            "asset": "资产解读",
            "vuln": "漏洞解读",
            "alarm": "安全告警解读",
            "event": "安全事件解读"
        }

        # 1. 生成综合报告
        comprehensive_dir = os.path.join(self.html_reports_dir, "comprehensive")
        os.makedirs(comprehensive_dir, exist_ok=True)

        html = self._build_html(report_data)
        comp_filename = f"test_report_comprehensive_{timestamp}.html"
        comp_path = os.path.join(comprehensive_dir, comp_filename)
        with open(comp_path, 'w', encoding='utf-8') as f:
            f.write(html)
        comp_latest = os.path.join(comprehensive_dir, "test_report_comprehensive.html")
        with open(comp_latest, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"📄 综合 HTML 报告: {comp_path}")
        generated_paths.append(comp_path)

        # 2. 按模块生成独立的 HTML 报告
        modules = report_data.get('modules', {})
        for module_key, module_data in modules.items():
            module_name = module_names.get(module_key, module_key)
            module_dir = os.path.join(self.html_reports_dir, module_key)
            os.makedirs(module_dir, exist_ok=True)

            module_html = self._build_module_page(report_data, module_key, module_name, timestamp)
            mod_filename = f"test_report_{module_key}_{timestamp}.html"
            mod_path = os.path.join(module_dir, mod_filename)
            with open(mod_path, 'w', encoding='utf-8') as f:
                f.write(module_html)
            mod_latest = os.path.join(module_dir, f"test_report_{module_key}.html")
            with open(mod_latest, 'w', encoding='utf-8') as f:
                f.write(module_html)
            print(f"📄 {module_name} HTML 报告: {mod_path}")
            generated_paths.append(mod_path)

        print(f"📄 全部 HTML 报告存放于: {self.html_reports_dir}")

        return generated_paths

    def _build_module_page(self, report_data: Dict[str, Any], module_key: str, module_name: str, timestamp: str) -> str:
        """构建单个模块独立 HTML 页面"""
        modules = report_data.get('modules', {})
        module_data = modules.get(module_key, {})
        generated_at = report_data.get('generated_at', timestamp)

        total_cases = module_data.get('total_cases', 0)
        success_count = module_data.get('success_count', 0)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{module_name} - AI 解读测试报告</title>
    <style>{self.CSS}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{module_name} — 测试报告</h1>
            <div class="header-meta">
                <span>📅 生成时间: {generated_at}</span>
                <span>📋 测试用例: {total_cases}</span>
                <span>✅ 有效: {module_data.get('valid_count', success_count)}</span>
                <span>❌ 失败: {module_data.get('error_count', total_cases - success_count)}</span>
                <span>⚠️ 失效: {module_data.get('invalid_count', 0)}</span>
            </div>
        </div>
        <div class="summary-grid">
            <div class="summary-card pass">
                <div class="value">{success_count / total_cases * 100:.1f}%</div>
                <div class="label">成功率</div>
            </div>
            <div class="summary-card neutral">
                <div class="value">{len(module_data.get('test_cases', []))}</div>
                <div class="label">用例数</div>
            </div>
        </div>
        {self._build_single_module_metrics_summary(module_data)}
        <div class="module-section">
            <div class="module-header">
                <div class="module-title">📦 {module_name}</div>
                <div class="module-stats">
                    <span class="stat-badge info">总数: {total_cases}</span>
                    <span class="stat-badge success">成功: {success_count}</span>
                    <span class="stat-badge error">失败: {total_cases - success_count}</span>
                </div>
            </div>
            {''.join(self._build_test_case(tc, idx, module_key) for idx, tc in enumerate(module_data.get('test_cases', [])))}
        </div>
        <div style="text-align:center;padding:20px;color:#999;font-size:13px;">
            <a href="../comprehensive/test_report_comprehensive.html" style="color:#667eea;">查看综合报告</a>
        </div>
    </div>
    <script>{self.JS}</script>
</body>
</html>"""

    def _build_html(self, data: Dict[str, Any]) -> str:
        """构建完整的 HTML 文档"""
        return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 解读自动化测试报告</title>
    <style>{self.CSS}</style>
</head>
<body>
    <div class="container">
        {self._build_header(data)}
        {self._build_summary(data)}
        {self._build_module_timing_summary(data)}
        {self._build_module_metrics_summary(data)}
        {self._build_module_sections(data)}
    </div>
    <script>{self.JS}</script>
</body>
</html>
"""

    def _build_header(self, data: Dict[str, Any]) -> str:
        """构建页面头部"""
        generated_at = data.get('generated_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        modules = data.get('modules', {})

        total_cases = sum(m.get('total_cases', 0) for m in modules.values())
        valid_cases = sum(m.get('valid_count', 0) for m in modules.values())
        error_cases = sum(m.get('error_count', 0) for m in modules.values())
        invalid_cases = sum(m.get('invalid_count', 0) for m in modules.values())

        return f"""
        <div class="header">
            <h1>🤖 AI 解读自动化测试报告</h1>
            <div class="header-meta">
                <span>📅 生成时间: {generated_at}</span>
                <span>📋 总测试用例: {total_cases}</span>
                <span>✅ 有效: {valid_cases}（参与指标计算）</span>
                <span>❌ 失败: {error_cases}（AI调用失败）</span>
                <span>⚠️ 失效: {invalid_cases}（API查不到业务数据）</span>
            </div>
        </div>
        """

    def _build_summary(self, data: Dict[str, Any]) -> str:
        """构建概览卡片"""
        modules = data.get('modules', {})
        total_cases = sum(m.get('total_cases', 0) for m in modules.values())
        success_cases = sum(m.get('success_count', 0) for m in modules.values())
        success_rate = (success_cases / total_cases * 100) if total_cases > 0 else 0
        
        all_first_packet = []
        all_total_time = []
        
        for module in modules.values():
            for tc in module.get('test_cases', []):
                if tc.get('first_packet_time'):
                    all_first_packet.append(tc['first_packet_time'])
                if tc.get('total_response_time'):
                    all_total_time.append(tc['total_response_time'])
        
        avg_first_packet = sum(all_first_packet) / len(all_first_packet) if all_first_packet else 0
        avg_total_time = sum(all_total_time) / len(all_total_time) if all_total_time else 0
        
        return f"""
        <div class="summary-grid">
            <div class="summary-card pass">
                <div class="value">{success_rate:.1f}%</div>
                <div class="label">成功率</div>
            </div>
            <div class="summary-card neutral">
                <div class="value">{avg_first_packet:.2f}s</div>
                <div class="label">平均首包时间</div>
            </div>
            <div class="summary-card neutral">
                <div class="value">{avg_total_time:.2f}s</div>
                <div class="label">平均响应时间</div>
            </div>
            <div class="summary-card neutral">
                <div class="value">{len(modules)}</div>
                <div class="label">测试模块数</div>
            </div>
        </div>
        """

    def _build_module_timing_summary(self, data: Dict[str, Any]) -> str:
        """构建各模块响应时间统计表格"""
        modules = data.get('modules', {})
        module_names = {
            "asset": "资产解读",
            "vuln": "漏洞解读",
            "alarm": "安全告警解读",
            "event": "安全事件解读"
        }

        rows = []
        for module_key, module_data in modules.items():
            module_name = module_names.get(module_key, module_key)
            avg_first_packet = module_data.get('avg_first_packet_time', 0)
            avg_total_time = module_data.get('avg_total_response_time', 0)
            success_count = module_data.get('success_count', 0)

            rows.append(f"""
            <tr>
                <td style="padding:12px;border:1px solid #e2e8f0;font-weight:bold;">{module_name}</td>
                <td style="padding:12px;border:1px solid #e2e8f0;text-align:center;">{success_count}</td>
                <td style="padding:12px;border:1px solid #e2e8f0;text-align:center;color:#667eea;font-weight:bold;">{avg_first_packet:.2f}s</td>
                <td style="padding:12px;border:1px solid #e2e8f0;text-align:center;color:#764ba2;font-weight:bold;">{avg_total_time:.2f}s</td>
            </tr>""")

        return f"""
        <div class="module-section" style="background:white;border-radius:12px;padding:25px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,0.1);">
            <div class="module-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                <div class="module-title" style="font-size:18px;font-weight:bold;color:#333;">⏱️ 各模块响应时间统计</div>
            </div>
            <table style="width:100%;border-collapse:collapse;background:white;">
                <thead>
                    <tr style="background:#f7fafc;">
                        <th style="padding:12px;border:1px solid #e2e8f0;text-align:left;color:#666;">模块名称</th>
                        <th style="padding:12px;border:1px solid #e2e8f0;text-align:center;color:#666;">成功样本数</th>
                        <th style="padding:12px;border:1px solid #e2e8f0;text-align:center;color:#666;">平均首包响应时间</th>
                        <th style="padding:12px;border:1px solid #e2e8f0;text-align:center;color:#666;">平均总报告时长</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """

    def _build_module_metrics_summary(self, data: Dict[str, Any]) -> str:
        """构建各模块指标平均值统计表格"""
        modules = data.get('modules', {})
        module_names = {
            "asset": "资产解读",
            "vuln": "漏洞解读",
            "alarm": "安全告警解读",
            "event": "安全事件解读",
            "sandbox": "沙箱报告解读"
        }

        module_metric_labels = {
            "asset": {
                "risk_level_accuracy": "风险等级准确率",
                "chapter_structure_completeness": "结构完整率",
            },
            "alarm": {
                "threat_determination_accuracy": "威胁定性准确率",
                "attack_result_accuracy": "攻击结果准确率",
                "chapter_structure_completeness": "6章结构完整率",
                "core_conclusion_stability": "核心结论稳定性",
                "recommend_question_quality": "推荐问题质量",
            },
            "event": {
                "threat_determination_accuracy": "威胁定性准确率",
                "attack_result_accuracy": "攻击结果准确率",
                "chapter_structure_completeness": "6章结构完整率",
                "recommend_question_quality": "推荐问题质量",
                "core_conclusion_stability": "核心结论稳定性",
            },
            "vuln": {
                "dynamic_structure_completeness": "动态结构完整率",
            },
            "sandbox": {
                "risk_level_accuracy": "风险评估等级判定准确性",
                "sample_info_accuracy": "样本信息提取正确率",
                "disposal_rationality": "处置建议合理性",
                "format_compliance": "格式规范性",
                "section_completeness": "章节完整性",
            }
        }

        sections_html = []
        for module_key, module_data in modules.items():
            multi_sample_stats = module_data.get("multi_sample_stats", {})
            avg_accuracies = multi_sample_stats.get("avg_accuracies", {})
            if not avg_accuracies:
                continue

            module_name = module_names.get(module_key, module_key)
            labels = module_metric_labels.get(module_key, {})

            rows = []
            for metric_key, label in labels.items():
                # 推荐问题质量：从 test_cases 里统计合格率，不走 avg_accuracies
                if metric_key == "recommend_question_quality":
                    test_cases = module_data.get("test_cases", [])
                    rq_list = [
                        tc["metrics"]["recommend_question_quality"]
                        for tc in test_cases
                        if tc.get("success") and not tc.get("is_invalid")
                        and tc.get("metrics") and "recommend_question_quality" in tc["metrics"]
                        and tc["metrics"]["recommend_question_quality"].get("accuracy") is not None
                    ]
                    if rq_list:
                        qualified = sum(1 for rq in rq_list if rq.get("is_qualified"))
                        total = len(rq_list)
                        color = "#38a169" if qualified == total else "#e53e3e"
                        display = f'<span style="color:{color};font-weight:bold;">合格{qualified}/{total}</span>'
                        rows.append(f"""
                        <tr>
                            <td style="padding:10px;border:1px solid #e2e8f0;">{label}</td>
                            <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;">{display}</td>
                            <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;font-size:12px;">{total}</td>
                        </tr>""")
                    continue

                avg_val = avg_accuracies.get(metric_key)
                if avg_val is not None:
                    avg_accuracy = float(avg_val.get("avg_accuracy", 0.0))
                    display = f"{avg_accuracy:.1%}"
                    valid_count = avg_val.get("valid_count", 0)
                    excluded_count = avg_val.get("excluded_count", 0)
                    sample_info = f"{valid_count}"
                    if excluded_count > 0:
                        sample_info += f' <span style="color:#e53e3e;font-size:11px;">(排除{excluded_count})</span>'
                    rows.append(f"""
                    <tr>
                        <td style="padding:10px;border:1px solid #e2e8f0;">{label}</td>
                        <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#667eea;font-weight:bold;">{display}</td>
                        <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;font-size:12px;">{sample_info}</td>
                    </tr>""")

            if not rows:
                continue

            sections_html.append(f"""
            <div style="margin-bottom:15px;">
                <h4 style="margin:0 0 8px 0;color:#555;font-size:15px;">📊 {module_name}</h4>
                <table style="width:100%;border-collapse:collapse;background:white;font-size:13px;">
                    <thead>
                        <tr style="background:#f7fafc;">
                            <th style="padding:10px;border:1px solid #e2e8f0;text-align:left;color:#666;">指标名称</th>
                            <th style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;">平均值</th>
                            <th style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;">有效样本</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>""")

        if not sections_html:
            return ""

        return f"""
        <div class="module-section" style="background:white;border-radius:12px;padding:25px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,0.1);">
            <div class="module-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                <div class="module-title" style="font-size:18px;font-weight:bold;color:#333;">📈 各模块指标平均值统计</div>
            </div>
            {''.join(sections_html)}
        </div>
        """

    def _build_single_module_metrics_summary(self, module_data: Dict[str, Any]) -> str:
        """构建单个模块的指标平均值统计"""
        multi_sample_stats = module_data.get("multi_sample_stats", {})
        avg_accuracies = multi_sample_stats.get("avg_accuracies", {})
        test_cases = module_data.get("test_cases", [])

        # 检查是否有推荐问题数据
        rq_list = [
            tc["metrics"]["recommend_question_quality"]
            for tc in test_cases
            if tc.get("success") and not tc.get("is_invalid")
            and tc.get("metrics") and "recommend_question_quality" in tc["metrics"]
            and tc["metrics"]["recommend_question_quality"].get("accuracy") is not None
        ]

        if not avg_accuracies and not rq_list:
            return ""

        module_metric_labels = {
            "risk_level_accuracy": "风险等级准确率",
            "threat_determination_accuracy": "威胁定性准确率",
            "attack_result_accuracy": "攻击结果准确率",
            "chapter_structure_completeness": "结构完整率",
            "dynamic_structure_completeness": "动态结构完整率",
        }

        rows = []
        for metric_key, label in module_metric_labels.items():
            avg_val = avg_accuracies.get(metric_key)
            if avg_val is not None:
                avg_accuracy = float(avg_val.get("avg_accuracy", 0.0))
                display = f"{avg_accuracy:.1%}"
                valid_count = avg_val.get("valid_count", 0)
                excluded_count = avg_val.get("excluded_count", 0)
                sample_info = f"{valid_count}"
                if excluded_count > 0:
                    sample_info += f' <span style="color:#e53e3e;font-size:11px;">(排除{excluded_count})</span>'
                rows.append(f"""
                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;">{label}</td>
                    <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#667eea;font-weight:bold;">{display}</td>
                    <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;font-size:12px;">{sample_info}</td>
                </tr>""")

        # 推荐问题合格率行
        if rq_list:
            qualified = sum(1 for rq in rq_list if rq.get("is_qualified"))
            total = len(rq_list)
            color = "#38a169" if qualified == total else "#e53e3e"
            rows.append(f"""
                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;">推荐问题质量</td>
                    <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;font-weight:bold;color:{color};">合格{qualified}/{total}</td>
                    <td style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;font-size:12px;">{total}</td>
                </tr>""")

        if not rows:
            return ""

        return f"""
        <div class="module-section" style="background:white;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,0.1);">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                <div style="font-size:16px;font-weight:bold;color:#333;">📈 指标平均值统计</div>
            </div>
            <table style="width:100%;border-collapse:collapse;background:white;font-size:13px;">
                <thead>
                    <tr style="background:#f7fafc;">
                        <th style="padding:10px;border:1px solid #e2e8f0;text-align:left;color:#666;">指标名称</th>
                        <th style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;">平均值</th>
                        <th style="padding:10px;border:1px solid #e2e8f0;text-align:center;color:#666;">有效样本</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """

    def _build_module_sections(self, data: Dict[str, Any]) -> str:
        """构建各模块的测试详情"""
        modules = data.get('modules', {})
        html_parts = []
        
        module_names = {
            "asset": "资产解读",
            "vuln": "漏洞解读",
            "alarm": "安全告警解读",
            "event": "安全事件解读"
        }
        
        for module_key, module_data in modules.items():
            html_parts.append(self._build_single_module(module_key, module_data, module_names.get(module_key, module_key)))
        
        return ''.join(html_parts)

    def _build_single_module(self, module_key: str, module_data: Dict[str, Any], module_name: str) -> str:
        """构建单个模块的测试详情"""
        total_cases = module_data.get('total_cases', 0)
        valid_count = module_data.get('valid_count', 0)
        error_count = module_data.get('error_count', 0)
        invalid_count = module_data.get('invalid_count', 0)
        test_cases = module_data.get('test_cases', [])

        # 有效/失效/失败样本ID列表
        valid_ids = module_data.get('valid_sample_ids', [])
        invalid_ids = module_data.get('invalid_sample_ids', [])
        failed_ids = module_data.get('failed_sample_ids', [])

        sample_list_html = ""
        if valid_ids:
            sample_list_html += f'<div style="margin-top:10px;font-size:12px;color:#38a169;"><strong>✅ 有效样本({len(valid_ids)})：</strong>{", ".join(valid_ids)}</div>'
        if invalid_ids:
            sample_list_html += f'<div style="margin-top:6px;font-size:12px;color:#dd6b20;"><strong>⚠️ 失效样本({len(invalid_ids)})：</strong>{", ".join(invalid_ids)}</div>'
        if failed_ids:
            sample_list_html += f'<div style="margin-top:6px;font-size:12px;color:#e53e3e;"><strong>❌ 失败样本({len(failed_ids)})：</strong>{", ".join(failed_ids)}</div>'

        return f"""
        <div class="module-section">
            <div class="module-header">
                <div class="module-title">📦 {module_name}</div>
                <div class="module-stats">
                    <span class="stat-badge info">总数: {total_cases}</span>
                    <span class="stat-badge success">有效: {valid_count}</span>
                    <span class="stat-badge error">失败: {error_count}</span>
                    <span class="stat-badge info">失效: {invalid_count}</span>
                </div>
            </div>
            {sample_list_html}
            {''.join(self._build_test_case(tc, idx, module_key) for idx, tc in enumerate(test_cases))}
        </div>
        """

    def _build_test_case(self, test_case: Dict[str, Any], idx: int, module_key: str = "") -> str:
        """构建单个测试用例"""
        case_id = test_case.get('case_id', f'case_{idx}')
        success = test_case.get('success', False)
        is_invalid = test_case.get('is_invalid', False)
        error_msg = test_case.get('error', '')

        # 状态图标：有效且全部指标通过=✅，有效但有指标未通过=❌，失败=❌，失效=⚠️
        if not success:
            status_icon = "❌"
            status_label = '<span style="color:#e53e3e;font-size:12px;">失败</span>'
        elif is_invalid:
            status_icon = "⚠️"
            status_label = '<span style="color:#dd6b20;font-size:12px;">失效（不参与指标计算）</span>'
        else:
            # 检查所有指标是否都通过（排除时间指标和不可审查指标）
            TIME_METRICS = {"first_packet_time", "total_response_time"}
            EXCLUDE_METRICS = {"recommend_question_quality"}
            metrics = test_case.get('metrics', {})
            any_failed = False
            for mkey, mval in metrics.items():
                if mkey in TIME_METRICS or mkey in EXCLUDE_METRICS:
                    continue
                if isinstance(mval, dict) and mval.get('is_extraction_failure'):
                    continue
                is_perfect = mval.get('accuracy') == 1.0 or str(mval.get('accuracy')) == "100.0%"
                passed = True if is_perfect else mval.get('is_passed', mval.get('passed', False))
                if not passed:
                    any_failed = True
                    break
            if any_failed:
                status_icon = "❌"
                status_label = '<span style="color:#e53e3e;font-size:12px;">有效（部分指标未通过）</span>'
            else:
                status_icon = "✅"
                status_label = '<span style="color:#38a169;font-size:12px;">有效</span>'

        # 获取业务ID（如漏洞ID、资产ID等）
        id_field_map = {
            "asset": "asset_id",
            "vuln": "vuln_id",
            "alarm": "alarm_id",
            "event": "event_id",
            "sandbox": "sandbox_id"
        }
        id_field = id_field_map.get(module_key, "")
        biz_id = test_case.get(id_field, test_case.get('input_data', {}).get(id_field, ""))

        # 构建显示标题：业务ID为主；用序号（对应 config 顺序）标注
        if biz_id:
            case_title = f"样本 #{idx + 1:02d} | {id_field}: {biz_id}"
        else:
            case_title = case_id

        metrics_html = self._build_metrics(test_case.get('metrics', {}), module_key)
        time_info_html = self._build_time_info(test_case)
        source_info_html = self._build_source_info(test_case)
        raw_data_html = self._build_raw_data(test_case)

        return f"""
        <div class="test-case">
            <div class="test-case-header" onclick="toggleTestCase(this)">
                <div class="test-case-title">
                    <span class="status-icon">{status_icon}</span>
                    <span>测试用例: {case_title}</span>
                    {status_label}
                    {f'<span style="color:#f56565; font-size:13px;">({error_msg})</span>' if error_msg else ''}
                </div>
                <span style="font-size:12px;color:#666;">点击展开详情 ▼</span>
            </div>
            <div class="test-case-body">
                {time_info_html}
                {metrics_html}
                {source_info_html}
                {raw_data_html}
            </div>
        </div>
        """

    def _build_time_info(self, test_case: Dict[str, Any]) -> str:
        """构建时间信息展示"""
        first_packet = test_case.get('first_packet_time', 0)
        total_time = test_case.get('total_response_time', 0)
        
        return f"""
        <div class="time-info">
            <div class="time-card">
                <div class="time-value">{first_packet:.2f}s</div>
                <div class="time-label">首包响应时间</div>
            </div>
            <div class="time-card">
                <div class="time-value">{total_time:.2f}s</div>
                <div class="time-label">总响应时间</div>
            </div>
        </div>
        """

    def _build_metrics(self, metrics: Dict[str, Any], module_key: str = "") -> str:
        """构建指标展示"""
        if not metrics:
            return '<div style="color:#666;padding:15px;text-align:center;">无指标数据</div>'
        
        # 根据模块类型设置不同的指标名称
        base_metric_names = {
            "first_packet_time": "首包响应时间",
            "total_response_time": "总包处理时长",
            "threat_determination_accuracy": "威胁定性准确率",
            "attack_result_accuracy": "攻击结果准确率",
            "risk_level_accuracy": "资产风险等级准确率",
            "dynamic_structure_completeness": "动态章节完整率",
            "recommend_question_quality": "推荐问题质量"
        }

        # 沙箱模块使用独立的指标名称
        if module_key == "sandbox":
            base_metric_names = {
                "first_packet_time": "首包响应时间",
                "total_response_time": "总包处理时长",
                "risk_level_accuracy": "风险评估等级判定准确性",
                "sample_info_accuracy": "样本信息提取正确率",
                "disposal_rationality": "处置建议合理性",
                "format_compliance": "格式规范性",
                "section_completeness": "章节完整性",
            }
        
        # 根据模块类型设置结构完整率的显示名称
        if module_key in ["alarm", "event"]:
            base_metric_names["chapter_structure_completeness"] = "6章结构完整率"
        elif module_key == "asset":
            base_metric_names["chapter_structure_completeness"] = "结构完整率（3章）"
        elif module_key == "vuln":
            base_metric_names["chapter_structure_completeness"] = "动态结构完整率"
        else:
            base_metric_names["chapter_structure_completeness"] = "结构完整率"
        
        html_parts = []
        
        for metric_key, metric_data in metrics.items():
            if metric_key == "recommend_question_quality":
                html_parts.append(self._build_recommend_question_metric(metric_data))
            else:
                html_parts.append(self._build_single_metric(metric_key, metric_data, base_metric_names.get(metric_key, metric_key)))
        
        return f'<div class="metrics-grid">{"".join(html_parts)}</div>'

    def _build_recommend_question_metric(self, metric_data: Dict[str, Any]) -> str:
        """构建推荐问题质量指标卡片（展示三维度得分）"""
        if metric_data.get("is_extraction_failure"):
            reason = metric_data.get("detail", {}).get("reason", "未捕获到推荐问题")
            return f'''
            <div class="metric-card" style="grid-column: 1/-1;">
                <div class="metric-header fail" style="background:#fefcbf;">
                    <span class="metric-name">推荐问题质量</span>
                    <span class="metric-score" style="color:#975a16;">未评估</span>
                </div>
                <div class="metric-content">
                    <div class="detail-row"><span class="detail-label">原因</span><span class="detail-value">{reason}</span></div>
                </div>
            </div>'''

        overall = metric_data.get("accuracy", 0)
        is_qualified = metric_data.get("is_qualified", False)
        detail = metric_data.get("detail", {})
        questions = detail.get("questions", [])
        compliance = detail.get("compliance_score", 0)
        compliance_ok = detail.get("compliance_passed", compliance >= 0.8)
        relevance = detail.get("relevance_score", 0)
        relevance_ok = detail.get("relevance_passed", relevance >= 0.8)
        diversity = detail.get("diversity_score", 0)
        diversity_ok = detail.get("diversity_passed", diversity >= 0.8)
        fail_reasons = detail.get("fail_reasons", [])
        compliance_detail = detail.get("compliance_detail", "")
        relevance_detail = detail.get("relevance_detail", "")
        diversity_detail = detail.get("diversity_detail", "")
        reviews = detail.get("questions_review", [])

        header_class = "pass" if is_qualified else "fail"
        status_text = "✅ 合格" if is_qualified else "❌ 不合格"

        def dim_badge(ok): return '✅' if ok else '❌'
        def dim_color(ok): return '#38a169' if ok else '#e53e3e'

        q_parts = []
        for i, q in enumerate(questions):
            review_part = f"　<span style='color:#999;'>{reviews[i]}</span>" if i < len(reviews) else ""
            q_parts.append(f'<div style="margin:4px 0;font-size:12px;color:#4a5568;">Q{i+1}: {q}{review_part}</div>')
        questions_html = "".join(q_parts)

        fail_html = ""
        if fail_reasons:
            fail_html = f'<div style="margin-top:10px;padding:8px;background:#fff5f5;border-left:3px solid #e53e3e;border-radius:4px;font-size:12px;color:#742a2a;">' + \
                        "".join(f"<div>• {r}</div>" for r in fail_reasons) + "</div>"

        return f'''
        <div class="metric-card" style="grid-column: 1/-1;">
            <div class="metric-header {header_class}">
                <span class="metric-name">💡 推荐问题质量</span>
                <span class="metric-score">{status_text}（三维度全部≥0.8才合格）</span>
            </div>
            <div class="metric-content">
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;">
                    <div style="text-align:center;background:#f7fafc;padding:10px;border-radius:6px;border:2px solid {dim_color(compliance_ok)}20;">
                        <div style="font-size:22px;">{dim_badge(compliance_ok)}</div>
                        <div style="font-size:16px;font-weight:bold;color:{dim_color(compliance_ok)};">{compliance:.2f}</div>
                        <div style="font-size:11px;color:#666;margin-top:2px;">规范符合度</div>
                        <div style="font-size:10px;color:#999;margin-top:4px;">{compliance_detail[:50] + "..." if len(compliance_detail)>50 else compliance_detail}</div>
                    </div>
                    <div style="text-align:center;background:#f7fafc;padding:10px;border-radius:6px;border:2px solid {dim_color(relevance_ok)}20;">
                        <div style="font-size:22px;">{dim_badge(relevance_ok)}</div>
                        <div style="font-size:16px;font-weight:bold;color:{dim_color(relevance_ok)};">{relevance:.2f}</div>
                        <div style="font-size:11px;color:#666;margin-top:2px;">报告关联性</div>
                        <div style="font-size:10px;color:#999;margin-top:4px;">{relevance_detail[:50] + "..." if len(relevance_detail)>50 else relevance_detail}</div>
                    </div>
                    <div style="text-align:center;background:#f7fafc;padding:10px;border-radius:6px;border:2px solid {dim_color(diversity_ok)}20;">
                        <div style="font-size:22px;">{dim_badge(diversity_ok)}</div>
                        <div style="font-size:16px;font-weight:bold;color:{dim_color(diversity_ok)};">{diversity:.2f}</div>
                        <div style="font-size:11px;color:#666;margin-top:2px;">问题多样性</div>
                        <div style="font-size:10px;color:#999;margin-top:4px;">{diversity_detail[:50] + "..." if len(diversity_detail)>50 else diversity_detail}</div>
                    </div>
                </div>
                {fail_html}
                <div style="background:#f7fafc;padding:10px;border-radius:6px;margin-top:10px;">
                    <div style="font-size:12px;font-weight:600;color:#4a5568;margin-bottom:6px;">推荐问题（共{len(questions)}个）：</div>
                    {questions_html}
                </div>
            </div>
        </div>'''

    def _build_single_metric(self, metric_key: str, metric_data: Dict[str, Any], metric_name: str) -> str:
        """构建单个指标卡片"""
        is_extraction_failure = metric_data.get("is_extraction_failure", False)

        if is_extraction_failure:
            ai_value = metric_data.get('ai_value')
            api_value = metric_data.get('api_value')
            detail = metric_data.get("detail", {})
            failure_reason = detail.get("extraction_failure", "提取失败") if isinstance(detail, dict) else "提取失败"

            ai_display = self._format_value(ai_value)
            api_display = self._format_value(api_value)

            return f'''
            <div class="metric-card">
                <div class="metric-header fail" style="background:#fefcbf;">
                    <span class="metric-name">{metric_name}</span>
                    <span class="metric-score" style="color:#975a16;">提取失败</span>
                </div>
                <div class="metric-content">
                    <div class="metric-details">
                        <div class="detail-row" style="align-items:flex-start;">
                            <span class="detail-label" style="white-space:nowrap;">AI 解读值</span>
                            <span class="detail-value ai-value" style="text-align:right;word-break:break-all;">{ai_display}</span>
                        </div>
                        <div class="detail-row" style="align-items:flex-start;">
                            <span class="detail-label" style="white-space:nowrap;">API 真实值</span>
                            <span class="detail-value api-value" style="text-align:right;word-break:break-all;">{api_display}</span>
                        </div>
                        <div class="detail-row" style="align-items:flex-start;">
                            <span class="detail-label" style="white-space:nowrap;color:#975a16;">失败原因</span>
                            <span class="detail-value" style="text-align:right;color:#975a16;font-size:12px;">{failure_reason}</span>
                        </div>
                    </div>
                </div>
            </div>
            '''

        # 强制修正：如果准确率为100%，则状态必须为通过
        is_perfect = metric_data.get("accuracy") == 1.0 or str(metric_data.get("accuracy")) == "100.0%"
        passed = True if is_perfect else metric_data.get('is_passed', metric_data.get('passed', False))

        accuracy = metric_data.get('accuracy', metric_data.get('value', 0))
        threshold = metric_data.get('threshold', '')
        ai_value = metric_data.get('ai_value')
        api_value = metric_data.get('api_value')

        is_time_metric = metric_key in ("first_packet_time", "total_response_time")

        header_class = 'pass' if passed else 'fail'
        status_text = '通过' if passed else '未通过'

        if is_time_metric:
            display_value = f"{accuracy:.2f}s"
        elif metric_key.endswith("structure_completeness"):
            display_value = str(ai_value) # e.g., "3/3"
        else:
            display_value = f"{accuracy*100:.1f}%"

        details_html = ""

        # AI值 vs API值
        if ai_value is not None or api_value is not None:
            ai_display = self._format_value(ai_value)
            api_display = self._format_value(api_value)
            details_html += f'''
            <div class="detail-row" style="align-items:flex-start;">
                <span class="detail-label" style="white-space:nowrap;">AI 解读值</span>
                <span class="detail-value ai-value" style="text-align:right;word-break:break-all;">{ai_display}</span>
            </div>
            <div class="detail-row" style="align-items:flex-start;">
                <span class="detail-label" style="white-space:nowrap;">API 真实值</span>
                <span class="detail-value api-value" style="text-align:right;word-break:break-all;">{api_display}</span>
            </div>
            '''

        # 结构完整率，补充展示章节列表（可折叠）
        if metric_key.endswith("structure_completeness"):
            detail_data = metric_data.get("detail", {})
            required = detail_data.get("required_sections", [])
            missing = detail_data.get("missing_sections", [])
            found = detail_data.get("found_sections", [s for s in required if s not in missing])

            found_text = '、'.join(found) if found else '无'
            required_text = '、'.join(required) if required else '无'
            missing_text = '、'.join(missing) if missing else '无'

            details_html += f'''
            <details style="margin-top:10px;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;background:#fafafa;">
                <summary style="cursor:pointer;color:#4a5568;font-weight:600;">查看章节明细</summary>
                <div class="detail-row" style="align-items:flex-start; margin-top: 8px;">
                    <span class="detail-label" style="white-space:nowrap;">AI检出章节</span>
                    <span class="detail-value ai-value" style="text-align:right;word-break:break-all;">{found_text}</span>
                </div>
                <div class="detail-row" style="align-items:flex-start;">
                    <span class="detail-label" style="white-space:nowrap;">要求章节</span>
                    <span class="detail-value api-value" style="text-align:right;word-break:break-all;">{required_text}</span>
                </div>
                <div class="detail-row" style="align-items:flex-start;">
                    <span class="detail-label" style="white-space:nowrap;">缺失章节</span>
                    <span class="detail-value" style="text-align:right;word-break:break-all;color:#e53e3e;">{missing_text}</span>
                </div>
            </details>
            '''

        if threshold:
            details_html += f'''
            <div class="detail-row">
                <span class="detail-label">判定阈值</span>
                <span class="detail-value">{threshold}</span>
            </div>
            '''

        return f'''
        <div class="metric-card">
            <div class="metric-header {header_class}">
                <span class="metric-name">{metric_name}</span>
                <span class="metric-score">{display_value} {status_text}</span>
            </div>
            <div class="metric-content">
                <div class="metric-details">
                    {details_html}
                </div>
            </div>
        </div>
        '''

    def _build_field_details_table(self, field_details: List[Dict[str, Any]]) -> str:
        """构建字段详情表格"""
        rows_html = []
        
        for field in field_details:
            field_name = field.get('field', '')
            status = field.get('status', '')
            ai_val = field.get('ai', '')
            api_val = field.get('api', '')
            
            status_badge = f'<span class="status-badge {status}">{self._get_status_text(status)}</span>'
            
            rows_html.append(f"""
            <tr class="{status}">
                <td>{field_name}</td>
                <td>{status_badge}</td>
                <td class="ai-value">{self._format_value(ai_val)}</td>
                <td class="api-value">{self._format_value(api_val)}</td>
            </tr>
            """)
        
        return f"""
        <table class="field-table">
            <thead>
                <tr>
                    <th>字段</th>
                    <th>状态</th>
                    <th>AI 解读值</th>
                    <th>API 真实值</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows_html)}
            </tbody>
        </table>
        """

    def _build_source_info(self, test_case: Dict[str, Any]) -> str:
        """构建数据溯源信息"""
        return f"""
        <div class="source-section">
            <div class="source-title">📚 数据溯源</div>
            <div class="source-info">
                <div><strong>AI 解读来源:</strong> AI 模型 flowStream API</div>
                <div><strong>真实数据来源:</strong> 对应业务 API 接口</div>
                <div><strong>计算方式:</strong> AI 解读字段与 API 真实字段逐位比对</div>
            </div>
        </div>
        """

    def _build_raw_data(self, test_case: Dict[str, Any]) -> str:
        """构建原始数据展示"""
        raw_json = json.dumps(test_case, ensure_ascii=False, indent=2)
        
        return f"""
        <div class="raw-data-toggle">
            <button class="collapse-toggle" onclick="toggleRawData(this)">显示原始数据</button>
            <div class="raw-data">{self._escape_html(raw_json)}</div>
        </div>
        """

    def _format_value(self, value: Any) -> str:
        """格式化值显示"""
        if value is None:
            return '<span style="color:#999;">无</span>'
        return str(value)

    def _get_status_text(self, status: str) -> str:
        """获取状态文本"""
        status_map = {
            "match": "匹配",
            "mismatch": "不匹配",
            "missing": "缺失",
            "both_empty": "均为空"
        }
        return status_map.get(status, status)

    def _escape_html(self, text: str) -> str:
        """转义 HTML 特殊字符"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

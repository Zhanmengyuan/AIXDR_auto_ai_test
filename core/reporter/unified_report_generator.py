"""
统一报告生成器 (Demo)

读取多个智能体的 StandardResult 数据，按维度横向对比，生成统一 HTML 报告。

核心效果：
  - 第一张表：准确性，横向排列各智能体
  - 第二张表：性能
  - 第三张表：合规审查
  - 点击智能体名称 → 下钻到该智能体的样本级详情

Demo 数据来源：
  1. Pull 模式：现有解读测试产出的 standard_results.json（需补 dimension 标签）
  2. Push 模式：模拟安全Copilot的 mock_copilot_results.json
"""
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.contract import StandardResult, Metric


# ── 智能体元信息（Demo 用，真实场景从 manifest 读取）──
AGENT_INFO = {
    "ai_interpret_alarm":   {"name": "告警解读智能体", "team": "解读组", "mode": "pull"},
    "ai_interpret_event":  {"name": "事件解读智能体", "team": "解读组", "mode": "pull"},
    "ai_interpret_asset":  {"name": "资产解读智能体", "team": "解读组", "mode": "pull"},
    "ai_interpret_vuln":   {"name": "漏洞解读智能体", "team": "解读组", "mode": "pull"},
    "ai_interpret_sandbox":{"name": "沙箱解读智能体", "team": "解读组", "mode": "pull"},
    "xdr_copilot":         {"name": "安全Copilot",   "team": "平台组", "mode": "push"},
}

# ── 维度展示顺序和中文标签 ──
DIMENSION_LABELS = {
    "accuracy": "准确性",
    "performance": "性能",
    "stability": "稳定性",
    "compliance": "合规审查",
}

DIMENSION_ORDER = ["accuracy", "performance", "stability", "compliance"]

# ── 各维度下的指标展示顺序（key → 中文名）──
DIMENSION_METRICS = {
    "accuracy": {
        "threat_determination_accuracy": "威胁定性准确率",
        "attack_result_accuracy": "攻击结果准确率",
        "risk_level_accuracy": "风险等级准确率",
        "chapter_structure_completeness": "结构完整率",
        "dynamic_structure_completeness": "动态结构完整率",
        "sample_info_accuracy": "样本信息提取正确率",
        "factuality": "事实准确性",
        "citation": "引用准确性",
    },
    "performance": {
        "first_packet_time": "首包响应时间",
        "total_response_time": "总响应时长",
        "response_time": "响应时间",
    },
    "stability": {
        "core_conclusion_stability": "核心结论稳定性",
    },
    "compliance": {
        "recommend_question_quality": "推荐问题质量",
        "format_compliance": "格式规范性",
        "format_compliance_calc": "格式合规率",
        "section_completeness": "章节完整性",
    },
}


class UnifiedReportGenerator:
    """统一报告生成器：读取多个智能体的 StandardResult，按维度横向对比"""

    def __init__(self, output_dir: str = None):
        if not output_dir:
            output_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "outputs", "demo"
            )
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, results_by_agent: Dict[str, List[dict]], run_id: str = None) -> str:
        """生成统一 HTML 报告

        Args:
            results_by_agent: {agent_id: [StandardResult dict, ...]}
            run_id: 批次ID

        Returns:
            生成的 HTML 文件路径
        """
        if not run_id:
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 聚合各智能体各维度的指标统计
        agent_stats = self._aggregate_agent_stats(results_by_agent)

        # 生成 HTML
        html = self._build_html(agent_stats, run_id, results_by_agent)

        # 保存
        filepath = os.path.join(self.output_dir, f"unified_report_{run_id}.html")
        latest_path = os.path.join(self.output_dir, "unified_report_latest.html")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        with open(latest_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"✅ 统一报告已生成: {filepath}")
        print(f"✅ 最新报告链接: {latest_path}")
        return filepath

    def _aggregate_agent_stats(self, results_by_agent: Dict[str, List[dict]]) -> Dict[str, Dict]:
        """聚合每个智能体的各维度指标统计

        返回结构:
        {
            agent_id: {
                "info": {name, team, mode},
                "total": N, "valid": M, "failed": F, "invalid": I,
                "dimensions": {
                    "accuracy": {
                        "threat_determination_accuracy": {
                            "avg_accuracy": 0.92, "valid_count": 48, "label": "威胁定性准确率"
                        },
                        ...
                    },
                    "performance": {
                        "first_packet_time": {"avg_value": 1.5, "unit": "s", ...},
                        ...
                    },
                    ...
                },
                "sample_details": [...]  # 样本级详情（下钻用）
            }
        """
        stats = {}

        for agent_id, results in results_by_agent.items():
            info = AGENT_INFO.get(agent_id, {"name": agent_id, "team": "未知", "mode": "未知"})

            total = len(results)
            valid = sum(1 for r in results if r.get("status") == "valid")
            failed = sum(1 for r in results if r.get("status") == "failed")
            invalid = sum(1 for r in results if r.get("status") == "invalid")

            # 按维度聚合指标
            dim_metrics = defaultdict(lambda: defaultdict(list))
            for r in results:
                for m in r.get("metrics", []):
                    dim = m.get("dimension", "accuracy")
                    key = m.get("key", "")
                    if not key:
                        continue
                    dim_metrics[dim][key].append(m)

            # 计算每个指标的统计值
            dimensions = {}
            for dim, metrics_map in dim_metrics.items():
                dimensions[dim] = {}
                for key, metric_list in metrics_map.items():
                    label = self._get_metric_label(dim, key)
                    accuracies = [
                        m["accuracy"] for m in metric_list
                        if m.get("accuracy") is not None
                    ]
                    avg_acc = sum(accuracies) / len(accuracies) if accuracies else None
                    dimensions[dim][key] = {
                        "label": label,
                        "avg_accuracy": avg_acc,
                        "valid_count": len(accuracies),
                        "total_count": len(metric_list),
                    }
                    # 性能指标额外提取平均值
                    if dim == "performance":
                        values = []
                        for m in metric_list:
                            v = m.get("value")
                            if isinstance(v, (int, float)):
                                values.append(v)
                            elif isinstance(v, str):
                                try:
                                    values.append(float(v.rstrip("s秒")))
                                except (ValueError, AttributeError):
                                    pass
                        if values:
                            dimensions[dim][key]["avg_value"] = sum(values) / len(values)

            stats[agent_id] = {
                "info": info,
                "total": total,
                "valid": valid,
                "failed": failed,
                "invalid": invalid,
                "dimensions": dimensions,
                "sample_details": self._prepare_sample_details(results),
            }

        return stats

    def _prepare_sample_details(self, results: List[dict]) -> List[dict]:
        """准备样本级详情数据（下钻用）"""
        details = []
        for r in results:
            details.append({
                "case_id": r.get("case_id", ""),
                "sample_id": r.get("sample_id", ""),
                "status": r.get("status", ""),
                "first_packet_time": r.get("first_packet_time", 0),
                "total_response_time": r.get("total_response_time", 0),
                "metrics": r.get("metrics", []),
                "error": r.get("error", ""),
            })
        return details

    def _get_metric_label(self, dimension: str, key: str) -> str:
        """获取指标的中文标签"""
        metrics_map = DIMENSION_METRICS.get(dimension, {})
        return metrics_map.get(key, key)

    # ──────────────────────────────────────────────
    # HTML 构建
    # ──────────────────────────────────────────────

    def _build_html(self, agent_stats: Dict, run_id: str, results_by_agent: Dict) -> str:
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_agents = len(agent_stats)
        total_samples = sum(s["total"] for s in agent_stats.values())
        total_valid = sum(s["valid"] for s in agent_stats.values())
        valid_rate = (total_valid / total_samples * 100) if total_samples > 0 else 0

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 智能体统一测试报告 — {run_id}</title>
    <style>{self._css()}</style>
</head>
<body>
    <div class="container">
        {self._build_header(generated_at, run_id, total_agents, total_samples, total_valid, valid_rate)}
        {self._build_dimension_tables(agent_stats)}
        {self._build_agent_details(agent_stats)}
    </div>
    <script>{self._js()}</script>
</body>
</html>"""

    def _build_header(self, generated_at, run_id, total_agents, total_samples, total_valid, valid_rate):
        return f"""
        <div class="header">
            <h1>🤖 AI 智能体统一测试报告</h1>
            <div class="header-meta">
                <span>📅 {generated_at}</span>
                <span>🏷️ 批次: {run_id}</span>
                <span>🤖 参测智能体: {total_agents}个</span>
                <span>📋 总样本: {total_samples}</span>
                <span>✅ 有效率: {valid_rate:.1f}%</span>
            </div>
        </div>"""

    def _build_dimension_tables(self, agent_stats: Dict) -> str:
        """构建各维度的横向对比表"""
        tables = []
        for dim in DIMENSION_ORDER:
            # 检查是否有智能体在该维度有数据
            has_data = any(
                dim in s.get("dimensions", {}) and s["dimensions"][dim]
                for s in agent_stats.values()
            )
            if not has_data:
                continue

            tables.append(self._build_single_dimension_table(dim, agent_stats))

        return "".join(tables)

    def _build_single_dimension_table(self, dimension: str, agent_stats: Dict) -> str:
        """构建单个维度的横向对比表"""
        dim_label = DIMENSION_LABELS.get(dimension, dimension)
        dim_icon = {"accuracy": "📈", "performance": "⏱️", "stability": "🔄", "compliance": "📋"}
        icon = dim_icon.get(dimension, "📊")

        # 收集该维度下所有出现过的指标 key（保持顺序）
        all_metric_keys = []
        seen = set()
        for s in agent_stats.values():
            dim_data = s.get("dimensions", {}).get(dimension, {})
            for key in dim_data:
                if key not in seen:
                    all_metric_keys.append(key)
                    seen.add(key)

        # 表头
        agent_cols = []
        for agent_id, s in agent_stats.items():
            info = s["info"]
            mode_badge = "🔄 Pull" if info["mode"] == "pull" else "📤 Push"
            agent_cols.append(f'<th class="agent-col">{info["name"]}<br><span class="team-tag">{info["team"]} · {mode_badge}</span></th>')

        # 每行一个指标，每列一个智能体
        rows = []
        for key in all_metric_keys:
            label = self._get_metric_label(dimension, key)
            cells = [f'<td class="metric-label">{label}</td>']

            for agent_id, s in agent_stats.items():
                dim_data = s.get("dimensions", {}).get(dimension, {})
                metric_stat = dim_data.get(key)

                if metric_stat is None or metric_stat.get("avg_accuracy") is None:
                    if dimension == "performance" and metric_stat and metric_stat.get("avg_value") is not None:
                        avg_val = metric_stat["avg_value"]
                        cells.append(f'<td class="metric-cell perf">{avg_val:.2f}s</td>')
                    else:
                        cells.append('<td class="metric-cell na">—</td>')
                else:
                    avg_acc = metric_stat["avg_accuracy"]
                    if dimension == "performance":
                        cells.append(f'<td class="metric-cell perf">{avg_acc:.1%}</td>')
                    else:
                        color = self._accuracy_color(avg_acc)
                        cells.append(
                            f'<td class="metric-cell" style="color:{color};font-weight:bold;">{avg_acc:.1%}</td>'
                        )

            rows.append(f'<tr>{"".join(cells)}</tr>')

        # 添加综合行（该维度所有指标的均值）
        summary_cells = ['<td class="metric-label summary-row">综合</td>']
        for agent_id, s in agent_stats.items():
            dim_data = s.get("dimensions", {}).get(dimension, {})
            all_accs = [m["avg_accuracy"] for m in dim_data.values() if m.get("avg_accuracy") is not None]
            if all_accs:
                avg = sum(all_accs) / len(all_accs)
                color = self._accuracy_color(avg)
                summary_cells.append(f'<td class="metric-cell summary-row" style="color:{color};font-weight:bold;">{avg:.1%}</td>')
            else:
                summary_cells.append('<td class="metric-cell na summary-row">—</td>')
        rows.append(f'<tr>{"".join(summary_cells)}</tr>')

        # 样本统计行
        sample_cells = ['<td class="metric-label sample-row">有效样本</td>']
        for agent_id, s in agent_stats.items():
            sample_cells.append(f'<td class="metric-cell sample-row">{s["valid"]}/{s["total"]}</td>')
        rows.append(f'<tr>{"".join(sample_cells)}</tr>')

        return f"""
        <div class="dimension-section">
            <div class="dimension-header">
                <span class="dim-icon">{icon}</span>
                <span class="dim-title">{dim_label}</span>
                <span class="dim-hint">（点击智能体名称下钻详情）</span>
            </div>
            <table class="dimension-table">
                <thead>
                    <tr>
                        <th class="metric-col">指标 / 智能体</th>
                        {"".join(agent_cols)}
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>"""

    def _build_agent_details(self, agent_stats: Dict) -> str:
        """构建各智能体的样本级详情（下钻部分）"""
        details = []
        for agent_id, s in agent_stats.items():
            info = s["info"]
            samples = s.get("sample_details", [])
            if not samples:
                continue

            mode_badge = "🔄 Pull" if info["mode"] == "pull" else "📤 Push"
            sample_rows = []
            for idx, sample in enumerate(samples[:20]):  # 最多展示20条
                status_icon = {"valid": "✅", "failed": "❌", "invalid": "⚠️"}.get(sample["status"], "❓")
                metric_badges = []
                for m in sample.get("metrics", []):
                    dim = m.get("dimension", "accuracy")
                    acc = m.get("accuracy")
                    label = m.get("key", "")
                    if acc is not None:
                        color = self._accuracy_color(acc)
                        metric_badges.append(f'<span class="metric-badge" style="border-color:{color};color:{color};">{label} {acc:.0%}</span>')
                    elif dim == "performance":
                        val = m.get("value", "")
                        metric_badges.append(f'<span class="metric-badge perf">{label} {val}</span>')

                fp = sample.get("first_packet_time", 0)
                tr = sample.get("total_response_time", 0)
                sample_rows.append(f"""
                <tr class="sample-row-detail" onclick="toggleSampleDetail(this)">
                    <td>{status_icon}</td>
                    <td>{sample.get("case_id", "")}</td>
                    <td>{sample.get("sample_id", "")}</td>
                    <td>{fp:.2f}s</td>
                    <td>{tr:.2f}s</td>
                    <td>{"".join(metric_badges) if metric_badges else "—"}</td>
                </tr>""")

            details.append(f"""
            <div class="agent-detail" id="detail-{agent_id}">
                <div class="agent-detail-header">
                    <h3>📦 {info["name"]} <span class="team-tag">{info["team"]} · {mode_badge}</span></h3>
                    <span class="close-btn" onclick="toggleAgentDetail('{agent_id}')">收起 ▲</span>
                </div>
                <div class="agent-detail-stats">
                    <span class="stat-badge total">总数 {s["total"]}</span>
                    <span class="stat-badge valid">有效 {s["valid"]}</span>
                    <span class="stat-badge failed">失败 {s["failed"]}</span>
                    <span class="stat-badge invalid">失效 {s["invalid"]}</span>
                </div>
                <table class="sample-table">
                    <thead>
                        <tr>
                            <th>状态</th>
                            <th>用例编号</th>
                            <th>样本ID</th>
                            <th>首包时间</th>
                            <th>总时长</th>
                            <th>指标摘要</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(sample_rows)}
                    </tbody>
                </table>
            </div>""")

        if not details:
            return ""

        return f"""
        <div class="details-section">
            <h2>📋 智能体详情（下钻）</h2>
            {"".join(details)}
        </div>"""

    def _accuracy_color(self, acc: float) -> str:
        if acc >= 0.9:
            return "#2f855a"
        elif acc >= 0.8:
            return "#d69e2e"
        elif acc >= 0.6:
            return "#dd6b20"
        else:
            return "#e53e3e"

    def _css(self) -> str:
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333; line-height: 1.6; padding: 20px; min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }

        .header {
            background: white; border-radius: 12px; padding: 30px;
            margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 28px; color: #667eea; margin-bottom: 10px; }
        .header-meta { display: flex; gap: 20px; color: #666; font-size: 14px; flex-wrap: wrap; }

        .dimension-section {
            background: white; border-radius: 12px; padding: 25px;
            margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .dimension-header {
            display: flex; align-items: center; gap: 10px;
            margin-bottom: 20px; padding-bottom: 15px;
            border-bottom: 2px solid #eee;
        }
        .dim-icon { font-size: 24px; }
        .dim-title { font-size: 20px; font-weight: bold; color: #333; }
        .dim-hint { font-size: 13px; color: #999; }

        .dimension-table {
            width: 100%; border-collapse: collapse; font-size: 14px;
        }
        .dimension-table th {
            padding: 12px; border: 1px solid #e2e8f0; text-align: center;
            background: #f7fafc; color: #4a5568; font-weight: 600;
        }
        .dimension-table th.metric-col { text-align: left; width: 180px; }
        .dimension-table th.agent-col { min-width: 140px; }
        .dimension-table td {
            padding: 10px 12px; border: 1px solid #e2e8f0; text-align: center;
        }
        .dimension-table td.metric-label {
            text-align: left; font-weight: 500; color: #4a5568;
        }
        .dimension-table td.metric-cell { font-size: 15px; }
        .dimension-table td.metric-cell.na { color: #cbd5e0; }
        .dimension-table td.metric-cell.perf { color: #6b46c1; }
        .dimension-table td.summary-row {
            border-top: 2px solid #667eea; font-size: 16px; font-weight: bold;
        }
        .dimension-table td.sample-row {
            color: #718096; font-size: 12px; font-style: italic;
        }
        .team-tag { font-size: 12px; color: #999; font-weight: normal; }
        .dimension-table th.agent-col { cursor: pointer; }
        .dimension-table th.agent-col:hover { background: #edf2f7; }

        .details-section {
            background: white; border-radius: 12px; padding: 25px;
            margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .details-section h2 { font-size: 20px; color: #333; margin-bottom: 20px; }

        .agent-detail {
            border: 1px solid #e2e8f0; border-radius: 8px;
            margin-bottom: 15px; overflow: hidden; display: none;
        }
        .agent-detail.open { display: block; }
        .agent-detail-header {
            display: flex; justify-content: space-between; align-items: center;
            padding: 15px 20px; background: #f7fafc; border-bottom: 1px solid #e2e8f0;
        }
        .agent-detail-header h3 { font-size: 16px; color: #333; }
        .close-btn { color: #667eea; cursor: pointer; font-size: 13px; }

        .agent-detail-stats { padding: 10px 20px; display: flex; gap: 10px; }
        .stat-badge {
            padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500;
        }
        .stat-badge.total { background: #e2e8f0; color: #4a5568; }
        .stat-badge.valid { background: #c6f6d5; color: #22543d; }
        .stat-badge.failed { background: #fed7d7; color: #742a2a; }
        .stat-badge.invalid { background: #feebc8; color: #7c2d12; }

        .sample-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .sample-table th {
            padding: 8px 10px; background: #f7fafc; text-align: left;
            border-bottom: 1px solid #e2e8f0; color: #4a5568;
        }
        .sample-table td {
            padding: 8px 10px; border-bottom: 1px solid #f0f0f0;
        }
        .sample-row-detail { cursor: pointer; }
        .sample-row-detail:hover { background: #f7fafc; }

        .metric-badge {
            display: inline-block; padding: 2px 8px; margin: 2px;
            border: 1px solid; border-radius: 4px; font-size: 11px;
        }
        .metric-badge.perf { border-color: #6b46c1; color: #6b46c1; }
        """

    def _js(self) -> str:
        return """
        function toggleAgentDetail(agentId) {
            var el = document.getElementById('detail-' + agentId);
            el.classList.toggle('open');
        }

        document.addEventListener('DOMContentLoaded', function() {
            // 点击维度表中的智能体列头 → 展开该智能体详情
            var agentCols = document.querySelectorAll('.dimension-table th.agent-col');
            agentCols.forEach(function(col, idx) {
                col.addEventListener('click', function() {
                    var agentDetails = document.querySelectorAll('.agent-detail');
                    if (agentDetails[idx]) {
                        agentDetails[idx].classList.toggle('open');
                        agentDetails[idx].scrollIntoView({behavior: 'smooth', block: 'start'});
                    }
                });
            });
        });

        function toggleSampleDetail(row) {
            // 预留：展开单条样本的指标明细
        }
        """

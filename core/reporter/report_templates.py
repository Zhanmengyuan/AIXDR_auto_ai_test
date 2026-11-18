"""
报告模板

生成准确性专项HTML报告。
"""
from typing import Any, Dict
from datetime import datetime


def build_accuracy_report_html(
    agent_results: Dict[str, Dict[str, Any]],
    run_id: str,
    overall: Dict[str, Any],
) -> str:
    """生成准确性专项HTML报告"""

    # 模型标识映射：固定大类映射中文，具体型号名直接展示
    FIXED_MODEL_NAMES = {
        "180": "180一体机",
        "190": "190一体机",
        "cloud": "云端大模型",
    }

    def _model_display(model: str) -> str:
        """将 model 标识转为展示文本"""
        if model in FIXED_MODEL_NAMES:
            return FIXED_MODEL_NAMES[model]
        # 具体模型型号名（如 kimi-2.6、deepseek-v4-pro）直接展示
        return model

    # 从结果中提取所有模型（一个批次通常一个模型，但也可能混合）
    models = []
    for result in agent_results.values():
        m = result.get("model", "")
        if m and m not in models:
            models.append(m)
    model_display = "、".join(_model_display(m) for m in models) if models else "未知"

    # 分类
    category_names = {
        "detect": "🔍 检测研判类",
        "generate": "📝 内容生成类",
        "query": "🔎 查询类",
        "qa": "💬 知识问答类",
    }

    # 按类别分组
    by_category = {}
    for agent_id, result in agent_results.items():
        cat = result["category"]
        by_category.setdefault(cat, []).append(result)

    # 概览
    total_agents = len(agent_results)
    s_count = sum(1 for r in agent_results.values() if r["rating"] == "S")
    a_count = sum(1 for r in agent_results.values() if r["rating"] == "A")
    b_count = sum(1 for r in agent_results.values() if r["rating"] in ("B", "C", "D"))

    # 各类综合分
    cat_scores_html = ""
    for cat, label in category_names.items():
        if cat in overall["category_means"]:
            score = overall["category_means"][cat]
            color = _score_color(score)
            cat_scores_html += f'<tr><td class="dim-icon">{label.split()[0]}</td><td class="dim-name">{label.split()[1]}</td><td class="dim-val" style="color:{color};font-weight:700">{score}</td></tr>'

    # 计算过程展示
    cat_labels = {"detect": "检测研判类", "generate": "内容生成类", "query": "查询类", "qa": "知识问答类"}
    calc_lines = []
    for cat in ["detect", "generate", "query", "qa"]:
        if cat in by_category:
            agents = by_category[cat]
            agent_scores = [r["dimension_scores"].get("accuracy", [0]) for r in agents]
            # 取accuracy维度分
            acc_values = []
            agent_names_list = []
            for r in agents:
                acc_list = r["dimension_scores"].get("accuracy", [0])
                if isinstance(acc_list, list) and acc_list:
                    acc_val = round(sum(acc_list) / len(acc_list), 1)
                elif isinstance(acc_list, (int, float)):
                    acc_val = round(acc_list, 1)
                else:
                    acc_val = 0
                acc_values.append(acc_val)
                agent_names_list.append(r["name"])
            cat_mean = overall["category_means"].get(cat, 0)
            if acc_values:
                names_str = "、".join(agent_names_list)
                values_str = "、".join([f"{v}" for v in acc_values])
                calc_lines.append(f"{cat_labels[cat]}：mean({values_str}) = {names_str}均值 = <strong>{cat_mean}</strong>")
    calc_detail_html = "<br>".join(calc_lines) + f'<br><br>整体准确性综合分 = mean({"、".join(str(v) for v in overall["category_means"].values())}) = <strong>{overall["overall"]}</strong>'

    # 各智能体表格行
    table_sections = []
    for cat, label in category_names.items():
        agents = by_category.get(cat, [])
        if not agents:
            continue

        # 权重说明
        weights = {"detect": "准确性90%·可靠性5%·内容质量5%", "generate": "准确性70%·可靠性15%·内容质量15%", "query": "准确性80%·可靠性10%·内容质量10%", "qa": "准确性90%·可靠性5%·内容质量5%"}

        rows_html = ""
        for result in agents:
            rows_html += _build_agent_row(result)

        # 表头根据类别不同
        if cat == "detect":
            header = "<tr><th>智能体</th><th>F1值</th><th>黑样本准确率</th><th>白样本准确率</th><th>准确性分值</th><th>评级</th><th>失败样本</th></tr>"
        elif cat == "generate":
            header = "<tr><th>智能体</th><th>内容准确率</th><th>准确性分值</th><th>评级</th><th>失败样本</th></tr>"
        elif cat == "query":
            header = "<tr><th>智能体</th><th>结果准确率</th><th>准确性分值</th><th>评级</th><th>失败样本</th></tr>"
        else:
            header = "<tr><th>智能体</th><th>结果准确率</th><th>准确性分值</th><th>评级</th><th>失败样本</th></tr>"

        # 性能数据行
        perf_rows = ""
        for result in agents:
            perf = result.get("performance_raw", {})
            agent_name = result["name"]
            fp = perf.get("first_packet_time", "—")
            avg = perf.get("avg_response_time", "—")
            fp_str = f'{fp}s' if isinstance(fp, (int, float)) else fp
            avg_str = f'{avg}s' if isinstance(avg, (int, float)) else avg
            perf_rows += f'<tr><td>{agent_name}</td><td>{fp_str}</td><td>{avg_str}</td></tr>'

        table_sections.append(f'''
        <div class="type-header {cat}">{label}（{len(agents)}个）&nbsp;|&nbsp; 权重：{weights.get(cat, "")}</div>
        <table><thead>{header}</thead><tbody>{rows_html}</tbody></table>
        ''')

    # 性能展示表
    perf_table = ""
    for cat, label in category_names.items():
        agents = by_category.get(cat, [])
        if not agents:
            continue
        for result in agents:
            perf = result.get("performance_raw", {})
            agent_name = result["name"]
            fp = perf.get("first_packet_time")
            avg = perf.get("avg_response_time")
            fp_str = f'{fp}s' if isinstance(fp, (int, float)) else '<span class="c-gray">— 无首包</span>'
            avg_str = f'{avg}s' if isinstance(avg, (int, float)) else '<span class="c-gray">—</span>'
            fp_color = _time_color(fp) if isinstance(fp, (int, float)) else ""
            avg_color = _time_color(avg, slow=60) if isinstance(avg, (int, float)) else ""
            perf_table += f'<tr><td><div class="agent-name">{agent_name}</div></td><td style="font-weight:700;color:{fp_color}">{fp_str}</td><td style="font-weight:700;color:{avg_color}">{avg_str}</td></tr>'

    # 失败样本溯源
    failed_table = ""
    for agent_id, result in agent_results.items():
        failed = result.get("failed_samples", [])
        invalid = result.get("invalid_samples", [])
        total = result.get("total_samples", 0)
        valid = result.get("valid_samples", 0)
        failed_count = len(failed)
        invalid_count = len(invalid)

        if failed_count > 0:
            ids = ", ".join([f'{s["sample_id"]}（{s["reason"]}）' for s in failed[:5]])
            if failed_count > 5:
                ids += f' ...共{failed_count}条'
        else:
            ids = '<span class="c-gray">—</span>'

        failed_color = 'c-red' if failed_count > 0 else 'c-gray'
        failed_table += f'<tr><td><div class="agent-name">{result["name"]}</div></td><td>{total}</td><td>{valid}</td><td class="{failed_color}" style="font-weight:700">{failed_count}</td><td style="font-size:12px">{ids}</td></tr>'

    overall_score = overall["overall"]
    overall_color = _score_color(overall_score)
    overall_rating = "S" if overall_score >= 90 else "A" if overall_score >= 80 else "B" if overall_score >= 70 else "C"

    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI 智能体准确性专项测试报告 — {run_id}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Microsoft YaHei', sans-serif; background: #f0f2f5; color: #1a1a2e; line-height: 1.6; }}
.page-header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%); color: white; padding: 36px 48px 28px; }}
.page-header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 8px; }}
.header-meta {{ display: flex; gap: 32px; font-size: 13px; color: rgba(255,255,255,0.65); flex-wrap: wrap; margin-top: 10px; }}

/* ── 来源模型横幅 ── */
.model-banner {{
  display: inline-flex; align-items: center; gap: 12px;
  margin-top: 16px; padding: 10px 20px;
  background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.25);
  border-radius: 10px;
}}
.model-banner-label {{
  font-size: 13px; color: rgba(255,255,255,0.7); letter-spacing: 1px;
}}
.model-banner-value {{
  font-size: 20px; font-weight: 800; color: #fbbf24; letter-spacing: 1px;
}}

.section {{ padding: 32px 48px; }}
.section-title {{ font-size: 15px; font-weight: 700; color: #666; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}
.section-title::after {{ content: ''; flex: 1; height: 1px; background: #e5e7eb; }}
.overall-score-section {{ padding: 32px 48px 0; }}
.overall-score-wrap {{ background: white; border-radius: 14px; padding: 32px 40px; box-shadow: 0 1px 4px rgba(0,0,0,0.07); display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 32px; align-items: center; }}
.overall-block {{ text-align: center; }}
.overall-block .label {{ font-size: 12px; color: #9ca3af; font-weight: 600; letter-spacing: 1px; margin-bottom: 8px; }}
.overall-block .score {{ font-size: 56px; font-weight: 800; line-height: 1; }}
.overall-block .rating {{ font-size: 16px; font-weight: 700; margin-top: 8px; }}
.dim-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
.dim-table td {{ padding: 4px 4px; font-size: 13px; border: none; text-align: left; }}
.dim-table td.dim-icon {{ width: 24px; text-align: center; }}
.dim-table td.dim-name {{ color: #6b7280; }}
.dim-table td.dim-val {{ text-align: right; font-weight: 700; }}
.overview-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
.overview-card {{ background: white; border-radius: 12px; padding: 22px 20px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.07); border-top: 3px solid transparent; }}
.overview-card.total {{ border-color: #667eea; }}
.overview-card.s-card {{ border-color: #10b981; }}
.overview-card.a-card {{ border-color: #3b82f6; }}
.overview-card.b-card {{ border-color: #f59e0b; }}
.overview-card .num {{ font-size: 36px; font-weight: 800; margin-bottom: 6px; }}
.overview-card.total .num {{ color: #667eea; }}
.overview-card.s-card .num {{ color: #10b981; }}
.overview-card.a-card .num {{ color: #3b82f6; }}
.overview-card.b-card .num {{ color: #f59e0b; }}
.overview-card .label {{ font-size: 13px; color: #9ca3af; font-weight: 500; }}
.badge {{ display: inline-flex; align-items: center; justify-content: center; width: 32px; height: 32px; border-radius: 8px; font-size: 15px; font-weight: 800; flex-shrink: 0; }}
.badge-S {{ background: #d1fae5; color: #065f46; }}
.badge-A {{ background: #dbeafe; color: #1e40af; }}
.badge-B {{ background: #fef3c7; color: #92400e; }}
.main-table-wrap {{ background: white; border-radius: 14px; box-shadow: 0 1px 4px rgba(0,0,0,0.07); overflow: hidden; }}
.type-header {{ padding: 12px 24px; font-size: 12px; font-weight: 700; letter-spacing: 2px; color: white; }}
.type-header.detect {{ background: #0f3460; }}
.type-header.generate {{ background: #1a1a2e; }}
.type-header.query {{ background: #1e3a5f; }}
.type-header.qa {{ background: #2d3748; }}
table {{ width: 100%; border-collapse: collapse; }}
thead th {{ padding: 12px 14px; font-size: 12px; font-weight: 600; color: #9ca3af; text-align: center; background: #fafafa; border-bottom: 1px solid #f0f0f0; }}
thead th:first-child {{ text-align: left; padding-left: 24px; min-width: 160px; }}
thead th:nth-child(2) {{ text-align: left; min-width: 180px; }}
tbody tr {{ border-bottom: 1px solid #f5f5f5; }}
tbody tr:last-child {{ border-bottom: none; }}
tbody td {{ padding: 14px 14px; font-size: 14px; text-align: center; vertical-align: middle; }}
tbody td:first-child {{ text-align: left; padding-left: 24px; }}
tbody td:nth-child(2) {{ text-align: left; }}
.agent-name {{ font-weight: 600; font-size: 14px; color: #111; }}
.agent-sub {{ font-size: 12px; color: #9ca3af; margin-top: 2px; }}
.score-cell {{ font-size: 22px; font-weight: 800; }}
.c-green {{ color: #10b981; }}
.c-blue {{ color: #3b82f6; }}
.c-yellow {{ color: #f59e0b; }}
.c-red {{ color: #ef4444; }}
.c-gray {{ color: #9ca3af; }}
.footnote {{ padding: 24px 48px; font-size: 12px; color: #9ca3af; line-height: 2; border-top: 1px solid #e5e7eb; background: white; }}
.footnote strong {{ color: #6b7280; }}

/* ── 折叠面板 ── */
.collapsible-section {{ margin-bottom: 0; }}
.collapsible-header {{
  padding: 16px 48px; background: white; border-radius: 12px 12px 0 0;
  box-shadow: 0 1px 4px rgba(0,0,0,0.07); cursor: pointer;
  display: flex; justify-content: space-between; align-items: center;
  font-size: 15px; font-weight: 700; color: #666;
  letter-spacing: 2px; text-transform: uppercase;
}}
.collapsible-header:hover {{ background: #f8faff; }}
.collapsible-header .arrow {{ font-size: 12px; color: #9ca3af; transition: transform 0.2s; }}
.collapsible-header.open .arrow {{ transform: rotate(180deg); }}
.collapsible-body {{
  display: none; padding: 0 48px 24px;
}}
.collapsible-body.open {{ display: block; }}

/* ── 计算过程展示 ── */
.calc-detail {{
  background: #f7fafc; border-radius: 8px; padding: 14px 18px;
  margin-top: 10px; font-size: 12px; line-height: 2.2; color: #4a5568;
  text-align: left;
}}
.calc-detail strong {{ color: #667eea; }}

/* ── 指标详情下钻 ── */
.agent-row {{ cursor: pointer; }}
.agent-row:hover {{ background: #f8faff; }}
.agent-detail-row {{ display: none; background: #f8faff; }}
.agent-detail-row.open {{ display: table-row; }}
.agent-detail-inner {{ padding: 16px 32px; }}
.detail-metric {{ background: white; border-radius: 8px; padding: 12px 16px; margin-bottom: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
.detail-metric .m-title {{ font-size: 13px; font-weight: 700; color: #667eea; margin-bottom: 8px; }}
.detail-metric .m-row {{ display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; border-bottom: 1px solid #f5f5f5; }}
.detail-metric .m-row:last-child {{ border-bottom: none; }}
.detail-metric .m-name {{ color: #6b7280; }}
.detail-metric .m-val {{ font-weight: 700; }}
</style>
</head>
<body>

<div class="page-header">
  <h1>📈 AI 智能体准确性专项测试报告</h1>
  <div class="model-banner">
    <span class="model-banner-label">来源模型</span>
    <span class="model-banner-value">{model_display}</span>
  </div>
  <div class="header-meta">
    <span>📅 报告期：{datetime.now().strftime("%Y-%m-%d")}</span>
    <span>🏷️ 批次：{run_id}</span>
    <span>🎯 测试维度：仅准确性</span>
    <span>📊 参测智能体：{total_agents}个</span>
    <span>⚙️ 评分方案：v2.0</span>
  </div>
</div>

<div class="overall-score-section">
  <div class="section-title">平台智能体准确性整体评分（类间等权）</div>
  <div class="overall-score-wrap">
    <div class="overall-block">
      <div class="label">准确性综合分</div>
      <div class="score" style="color:{overall_color}">{overall_score}</div>
      <div class="rating" style="color:{overall_color}">{overall_rating} 级</div>
      <div style="font-size:11px;color:#9ca3af;margin-top:6px;line-height:1.5">
        计算方式：各类内智能体准确性分取均值，4类等权再取均值
      </div>
      <div class="calc-detail">
        <strong>计算过程：</strong><br>
        {calc_detail_html}
      </div>
    </div>
    <div class="overall-block">
      <div class="label">各类准确性分</div>
      <table class="dim-table">{cat_scores_html}</table>
    </div>
    <div class="overall-block">
      <div class="label">准确性概览</div>
      <table class="dim-table">
        <tr><td class="dim-icon">📊</td><td class="dim-name">参测智能体</td><td class="dim-val">{total_agents}</td></tr>
        <tr><td class="dim-icon">⭐</td><td class="dim-name">S级（≥90）</td><td class="dim-val c-green">{s_count}</td></tr>
        <tr><td class="dim-icon">✅</td><td class="dim-name">A级（80~89）</td><td class="dim-val c-blue">{a_count}</td></tr>
        <tr><td class="dim-icon">⚠️</td><td class="dim-name">B级及以下</td><td class="dim-val c-gray">{b_count}</td></tr>
      </table>
    </div>
    <div class="overall-block">
      <div class="label">整体结论</div>
      <div class="rating c-green">{'准确性优秀' if overall_rating == 'S' else '准确性良好' if overall_rating == 'A' else '需关注'}</div>
      <div style="font-size:12px;color:#6b7280;margin-top:6px;line-height:1.6">
        {total_agents}个智能体参测<br>
        {s_count}个S级，{a_count}个A级，{b_count}个B级及以下
      </div>
    </div>
  </div>
</div>

<div class="section" style="padding-top:24px;">
  <div class="overview-cards">
    <div class="overview-card total"><div class="num">{total_agents}</div><div class="label">参测智能体</div></div>
    <div class="overview-card s-card"><div class="num">{s_count}</div><div class="label">S级（≥90）</div></div>
    <div class="overview-card a-card"><div class="num">{a_count}</div><div class="label">A级（80~89）</div></div>
    <div class="overview-card b-card"><div class="num">{b_count}</div><div class="label">B级及以下</div></div>
  </div>
</div>

<div class="section" style="padding-top:0;">
  <div class="collapsible-header" onclick="toggleSection(this)">各智能体准确性评分 <span class="arrow">▼</span></div>
  <div class="collapsible-body open">
    <div class="main-table-wrap">
      {''.join(table_sections)}
    </div>
  </div>
</div>

<div class="section" style="padding-top:0;">
  <div class="collapsible-header" onclick="toggleSection(this)">各智能体性能指标 <span class="arrow">▼</span></div>
  <div class="collapsible-body">
    <div class="main-table-wrap">
      <table>
        <thead><tr><th>智能体</th><th>首包响应时间</th><th>平均响应时间</th></tr></thead>
        <tbody>{perf_table}</tbody>
      </table>
    </div>
  </div>
</div>

<div class="section" style="padding-top:0;">
  <div class="collapsible-header" onclick="toggleSection(this)">失败样本溯源 <span class="arrow">▼</span></div>
  <div class="collapsible-body">
    <div class="main-table-wrap">
      <table>
        <thead><tr><th>智能体</th><th>总样本</th><th>有效样本</th><th>失败样本数</th><th>失败样本ID（溯源）</th></tr></thead>
        <tbody>{failed_table}</tbody>
      </table>
    </div>
  </div>
</div>

<div class="footnote">
  <strong>准确性专项测试说明：</strong>
  本次为准确性专项测试，仅评估准确性维度。性能指标只展示原始值，不算分。
  &nbsp;|&nbsp;
  <strong>各分类准确性指标：</strong>
  检测研判类 → F1（框架从黑白样本数量计算）；内容生成类 → 整体内容合规性（LLM Judge审查）；查询类 → 结果准确率；知识问答类 → 答案正确性。
  &nbsp;|&nbsp;
  <strong>分类权重（性能不算分）：</strong>
  检测类准90%·靠5%·内5%；生成类准70%·靠15%·内15%；查询类准80%·靠10%·内10%；问答类准90%·靠5%·内5%。
  &nbsp;|&nbsp;
  <strong>评级标准：</strong> S≥90 · A 80~89 · B 70~79 · C 60~69 · D&lt;60。
  &nbsp;|&nbsp;
  本报告由 AIXDR QA 团队自动生成 | {run_id} | 自动生成于 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}。
</div>

<script>
function toggleSection(el) {{
  el.classList.toggle('open');
  var body = el.nextElementSibling;
  body.classList.toggle('open');
}}

function toggleAgentDetail(row) {{
  var detail = row.nextElementSibling;
  if (detail && detail.classList.contains('agent-detail-row')) {{
    detail.classList.toggle('open');
  }}
}}
</script>
</body>
</html>'''


def _build_agent_row(result: Dict[str, Any]) -> str:
    """构建单个智能体的数据行 + 详情行"""
    name = result["name"]
    model = result["model"]
    score = result["agent_score"]
    rating = result["rating"]
    dim_scores = result["dimension_scores"]
    details = result.get("metric_details", {})
    failed_count = len(result.get("failed_samples", []))

    score_color = _score_color(score)
    badge_class = f"badge-{rating}"

    # 准确性维度分
    acc_score = dim_scores.get("accuracy", [])
    acc_val = round(sum(acc_score) / len(acc_score), 1) if acc_score else 0

    cat = result["category"]

    # 生成数据行
    if cat == "detect":
        f1_detail = details.get("accuracy", {}).get("f1_score", {}).get("detail", {})
        f1_val = f1_detail.get("f1_score", 0)
        black_acc = f1_detail.get("black_accuracy", 0)
        white_acc = f1_detail.get("white_accuracy", 0)
        data_row = f'''<tr class="agent-row" onclick="toggleAgentDetail(this)">
          <td><div class="agent-name">{name}</div><div class="agent-sub">大模型：{model}</div></td>
          <td style="font-weight:700;color:{_score_color(f1_val*100)}">{f1_val:.3f}</td>
          <td style="font-weight:700;color:{_score_color(black_acc*100)}">{black_acc*100:.2f}%</td>
          <td style="font-weight:700;color:{_score_color(white_acc*100)}">{white_acc*100:.2f}%</td>
          <td><div class="score-cell" style="color:{score_color}">{acc_val:.0f}</div></td>
          <td><span class="badge {badge_class}">{rating}</span></td>
          <td class="{'c-red' if failed_count > 0 else 'c-gray'}">{failed_count if failed_count > 0 else '0'}</td>
        </tr>'''
    elif cat == "generate":
        content = details.get("accuracy", {}).get("content_compliance", {})
        content_raw = content.get("raw_value", 0)
        data_row = f'''<tr class="agent-row" onclick="toggleAgentDetail(this)">
          <td><div class="agent-name">{name}</div><div class="agent-sub">大模型：{model}</div></td>
          <td style="font-weight:700;color:{_score_color(content_raw)}">{content_raw}/100</td>
          <td><div class="score-cell" style="color:{score_color}">{acc_val:.0f}</div></td>
          <td><span class="badge {badge_class}">{rating}</span></td>
          <td class="{'c-red' if failed_count > 0 else 'c-gray'}">{failed_count if failed_count > 0 else '0'}</td>
        </tr>'''
    elif cat == "query":
        acc_detail = details.get("accuracy", {})
        first_key = list(acc_detail.keys())[0] if acc_detail else ""
        acc_raw = acc_detail.get(first_key, {}).get("raw_value", 0)
        data_row = f'''<tr class="agent-row" onclick="toggleAgentDetail(this)">
          <td><div class="agent-name">{name}</div><div class="agent-sub">大模型：{model}</div></td>
          <td style="font-weight:700;color:{_score_color(acc_raw*100)}">{acc_raw*100:.1f}%</td>
          <td><div class="score-cell" style="color:{score_color}">{acc_val:.0f}</div></td>
          <td><span class="badge {badge_class}">{rating}</span></td>
          <td class="{'c-red' if failed_count > 0 else 'c-gray'}">{failed_count if failed_count > 0 else '0'}</td>
        </tr>'''
    else:  # qa
        acc_detail = details.get("accuracy", {})
        first_key = list(acc_detail.keys())[0] if acc_detail else ""
        acc_raw = acc_detail.get(first_key, {}).get("raw_value", 0)
        data_row = f'''<tr class="agent-row" onclick="toggleAgentDetail(this)">
          <td><div class="agent-name">{name}</div><div class="agent-sub">大模型：{model}</div></td>
          <td style="font-weight:700;color:{_score_color(acc_raw*100)}">{acc_raw*100:.1f}%</td>
          <td><div class="score-cell" style="color:{score_color}">{acc_val:.0f}</div></td>
          <td><span class="badge {badge_class}">{rating}</span></td>
          <td class="{'c-red' if failed_count > 0 else 'c-gray'}">{failed_count if failed_count > 0 else '0'}</td>
        </tr>'''

    # 生成详情行
    detail_html = _build_agent_detail(name, cat, details, result, acc_val)

    colspan = 7 if cat == "detect" else 5
    detail_row = f'''<tr class="agent-detail-row">
      <td colspan="{colspan}"><div class="agent-detail-inner">{detail_html}</div></td>
    </tr>'''

    return data_row + detail_row


def _build_agent_detail(name: str, cat: str, details: Dict, result: Dict, acc_val: float) -> str:
    """构建单个智能体的计算详情HTML"""
    html_parts = []

    # 准确性维度的指标详情
    acc_details = details.get("accuracy", {})
    for key, meta in acc_details.items():
        if key == "f1_score":
            # F1计算过程
            f1 = meta.get("detail", {})
            bs = f1.get("tp", 0) + f1.get("fn", 0)
            bc = f1.get("tp", 0)
            ws = f1.get("tn", 0) + f1.get("fp", 0)
            wc = f1.get("tn", 0)
            html_parts.append(f'''
            <div class="detail-metric">
              <div class="m-title">📈 计算过程</div>
              <div class="m-row"><span class="m-name">输入：黑样本总数/正确</span><span class="m-val">{bs}/{bc}</span></div>
              <div class="m-row"><span class="m-name">输入：白样本总数/正确</span><span class="m-val">{ws}/{wc}</span></div>
              <div class="m-row"><span class="m-name">TP（黑样本正确判定）</span><span class="m-val">{f1.get("tp", 0)}</span></div>
              <div class="m-row"><span class="m-name">FN（黑样本漏判）</span><span class="m-val">{f1.get("fn", 0)}</span></div>
              <div class="m-row"><span class="m-name">FP（白样本误判）</span><span class="m-val">{f1.get("fp", 0)}</span></div>
              <div class="m-row"><span class="m-name">TN（白样本正确判定）</span><span class="m-val">{f1.get("tn", 0)}</span></div>
              <div class="m-row"><span class="m-name">黑样本准确率 = black_correct/black_samples</span><span class="m-val">{f1.get("black_accuracy", 0)*100:.2f}%</span></div>
              <div class="m-row"><span class="m-name">白样本准确率 = white_correct/white_samples</span><span class="m-val">{f1.get("white_accuracy", 0)*100:.2f}%</span></div>
              <div class="m-row"><span class="m-name">精确率 P = TP/(TP+FP)</span><span class="m-val">{f1.get("precision", 0)*100:.2f}%</span></div>
              <div class="m-row"><span class="m-name">召回率 R = TP/(TP+FN)</span><span class="m-val">{f1.get("recall", 0)*100:.2f}%</span></div>
              <div class="m-row"><span class="m-name">F1 = 2×P×R/(P+R)</span><span class="m-val c-green" style="font-size:15px;">{f1.get("f1_score", 0):.4f}</span></div>
              <div class="m-row"><span class="m-name">准确性分值 = F1×100</span><span class="m-val c-green" style="font-size:15px;">{acc_val:.1f}分</span></div>
            </div>''')
        else:
            raw = meta.get("raw_value", 0)
            score_val = meta.get("score", 0)
            html_parts.append(f'''
            <div class="detail-metric">
              <div class="m-title">📈 计算过程</div>
              <div class="m-row"><span class="m-name">原始值</span><span class="m-val">{raw}</span></div>
              <div class="m-row"><span class="m-name">归一化标准分</span><span class="m-val">{score_val:.1f}分</span></div>
            </div>''')

    return "".join(html_parts)


def _score_color(score: float) -> str:
    if score >= 90:
        return "#10b981"
    elif score >= 80:
        return "#3b82f6"
    elif score >= 70:
        return "#f59e0b"
    else:
        return "#ef4444"


def _time_color(val: float, slow: float = 5) -> str:
    if val is None:
        return "#9ca3af"
    if val <= 1:
        return "#10b981"
    elif val <= slow:
        return "#3b82f6"
    else:
        return "#f59e0b"

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产解读报告审计评分计算器 (asset_report_audit)

规则直接来源于 SKILL.md 各章节标注，共31条规则，总分100分。
五大维度：结构完整性20 / 内容规范性30 / 数据准确性20 / 红线合规20 / 格式完整性10
"""
import argparse, json, sys

SCORING_RULES = {
    # ── 一、结构骨架完整性规则 → 结构完整性（20分）─────────────────────────
    "STR-01": {"dimension": "结构完整性", "points": 4,
               "description": "报告开头固定4行格式（#资产解读报告+>资产ID+>主机名称+>生成时间）+ 开头前无引导语，任一缺失/乱序/格式变更即违规"},
    "STR-02": {"dimension": "结构完整性", "points": 4,
               "description": "强制3章节顺序固定（第1章风险速览→第2章风险轨迹→第3章当前威胁），缺/增/乱序=严重违规"},
    "STR-03": {"dimension": "结构完整性", "points": 4,
               "description": "第2/3章必须用details/summary折叠包裹；第1章禁止使用details标签"},
    "STR-04": {"dimension": "结构完整性", "points": 4,
               "description": "报告结束标记：第3章</details>之后不得有任何字符（总结段/空行追加文字/署名/分隔线等均违规）"},
    "STR-05": {"dimension": "结构完整性", "points": 2,
               "description": "章节间禁止有过渡文字；summary与第一个###子节之间禁止有过渡文字（只允许一个空行）"},
    "STR-06": {"dimension": "结构完整性", "points": 2,
               "description": "章节名称禁止添加emoji或额外修饰文字"},

    # ── 二、章节内容规范规则 → 内容规范性（30分）────────────────────────────
    "CNT-01": {"dimension": "内容规范性", "points": 3,
               "description": "1.1定位结论句式固定（**定位：XXX，安全优先级XXX。**）；资产类型/安全优先级按查表规则判定，不得凭主观调整"},
    "CNT-02": {"dimension": "内容规范性", "points": 2,
               "description": "1.1支撑依据4项（资产归属→部署概况→风险计数→内网关联度）顺序/句式/量词正确；空项正确跳过"},
    "CNT-03": {"dimension": "内容规范性", "points": 4,
               "description": "1.2当前评分+风险等级两项同时存在；等级取自scoreHistory.riskLevel字段，禁止自行推算"},
    "CNT-04": {"dimension": "内容规范性", "points": 4,
               "description": "1.2三十天评分走势按场景表匹配句式；高危/严重等级稳定场景禁止使用稳定/平稳/良好等违禁褒义词"},
    "CNT-05": {"dimension": "内容规范性", "points": 3,
               "description": "1.2高危路径结构完整（路径N+风险定性+端口+漏洞+攻击后果）；无路径时按当前风险等级匹配固定句式"},
    "CNT-06": {"dimension": "内容规范性", "points": 3,
               "description": "1.3按两级响应规则生成（第一级基于高危路径，第二级基于原始风险数据）；行动句式动词开头；能追溯具体数据源；良好时输出固定句"},
    "CNT-07": {"dimension": "内容规范性", "points": 3,
               "description": "2.1跨等级时有『跨越风险等级』子句；归因明确命中一种类型（告警/漏洞/情报/数据失效/数据不充分）；推测标注『推测为』；评分无变化时按等级输出单行"},
    "CNT-08": {"dimension": "内容规范性", "points": 2,
               "description": "3.1总述存在；表格固定6列（漏洞名称/CVE编号/CVSS评分/远程利用/在野利用/处置状态）列名/顺序正确；紧急漏洞加粗"},
    "CNT-09": {"dimension": "内容规范性", "points": 4,
               "description": "3.2总述包含『最近7天』；告警表第4列=告警类型；事件表第4列=攻击阶段（不是告警类型）；超危/攻击成功行名称加粗；各类空数据固定提示正确"},
    "CNT-10": {"dimension": "内容规范性", "points": 2,
               "description": "3.3防线状态4条按顺序（暴露面→Agent防护→弱密码统计→资产信息完善度）；Agent离线时追加『当前处于无防护状态』"},

    # ── 三、逻辑联动与数据准确性规则 → 数据准确性（20分）──────────────────
    "DAT-01": {"dimension": "数据准确性", "points": 6,
               "description": "1.1风险计数（告警数/事件数/漏洞数/风险端口数/弱口令数）与3.1/3.2/3.3统计数据内部一致（审查报告内部自洽性，不对照原始接口数据）"},
    "DAT-02": {"dimension": "数据准确性", "points": 4,
               "description": "1.2高危路径→1.3必须有对应紧急行动；1.2无路径（输出固定句）时1.3走第二级"},
    "DAT-03": {"dimension": "数据准确性", "points": 4,
               "description": "字段取值合规：威胁等级（超危/高危/中危/低危）、攻击结果（成功/失败/未知）、处置状态（待派单/待加固/已回退/待复核/已关闭/已忽略）、路径风险定性（严重/高/中）等均在允许范围内"},
    "DAT-04": {"dimension": "数据准确性", "points": 3,
               "description": "评分走势中等级标注与当前评分所在区间无明显矛盾（如写『健康』但评分极低）；不得自行推算等级"},
    "DAT-05": {"dimension": "数据准确性", "points": 3,
               "description": "1.3紧急行动能追溯到1.2路径、第3章具体威胁或第二级原始数据源；禁止脱离数据空谈行动"},

    # ── 四、红线禁用项合规规则 → 红线合规（20分）───────────────────────────
    "RED-01": {"dimension": "红线合规", "points": 8,
               "description": "零英文字段名（SNAKE_CASE全大写/美元符拼接格式，如ASSET_ID/KILL_CHAIN/ALERT_CAT_FIRST/ASSET_LEVEL$NAME等）；白名单（CVE/CVSS/WAF/HTTP/软件产品名等）不计违规"},
    "RED-02": {"dimension": "红线合规", "points": 5,
               "description": "禁止捏造幻觉数据：数据缺失只能标注『暂未查询到相关数据』，禁止编造具体IP/端口/CVE编号/软件版本/弱密码/攻击者IP等"},
    "RED-04": {"dimension": "红线合规", "points": 4,
               "description": "禁止暴露接口名：base_extractInfoForInterpret/asset_getRiskPort/asset_getTopoWithThreat/vuln_getVulnLevelGroup等"},
    "RED-05": {"dimension": "红线合规", "points": 3,
               "description": "禁止联网搜索痕迹：搜索引擎标识（根据搜索结果/百度Google等）、外部网站引用（来源xxx.com）、通用知识库口吻（据公开资料/业界普遍认为等）"},

    # ── 五、格式与空值处理规则 → 格式完整性（10分）─────────────────────────
    "FMT-01": {"dimension": "格式完整性", "points": 3,
               "description": "3.3风险端口表格固定5列（端口/协议/进程/风险等级/处置状态），列名与顺序不可调整，列数不符即违规"},
    "FMT-02": {"dimension": "格式完整性", "points": 2,
               "description": "空值模板正确（> 暂未查询到相关数据。），禁止用空表格或多个—占位"},
    "FMT-03": {"dimension": "格式完整性", "points": 2,
               "description": "无数据固定提示正确：3.2分场景提示（告警事件都空/仅告警空/仅事件空）/3.3端口为空/1.3无紧急风险，固定话术不得自行修改"},
    "FMT-04": {"dimension": "格式完整性", "points": 1,
               "description": "禁止非法占位符（—/null/无等填表格），表格内数据缺失使用『未查询到』"},
    "FMT-05": {"dimension": "格式完整性", "points": 1,
               "description": "时间格式统一：YYYY-MM-DD HH:mm（24小时制，含冒号）"},
    "FMT-06": {"dimension": "格式完整性", "points": 1,
               "description": "数字格式统一：使用阿拉伯数字，不写『两个/三个』等中文数字"},
}

DIMENSION_ORDER = ["结构完整性", "内容规范性", "数据准确性", "红线合规", "格式完整性"]
DIMENSION_MAX = {"结构完整性": 20, "内容规范性": 30, "数据准确性": 20, "红线合规": 20, "格式完整性": 10}


def calculate_score(violations):
    vset = set(violations)
    dims = {d: DIMENSION_MAX[d] for d in DIMENSION_ORDER}
    lost = {d: 0 for d in DIMENSION_ORDER}
    out = []
    for rid, rule in SCORING_RULES.items():
        isv = rid in vset
        if isv:
            dims[rule["dimension"]] -= rule["points"]
            lost[rule["dimension"]] += rule["points"]
        out.append(dict(rule_id=rid, dimension=rule["dimension"],
                        description=rule["description"],
                        max_points=rule["points"],
                        violated=isv, earned=0 if isv else rule["points"]))
    total = sum(dims.values())
    if total >= 90:   rating = "完全合规"
    elif total >= 60: rating = "局部瑕疵（需微调）"
    else:             rating = "严重违规"
    return {"total_score": total, "max_score": 100, "rating": rating,
            "dimension_scores": dims, "dimension_lost": lost,
            "rule_results": out, "violated_count": len(vset),
            "violated_rules": sorted(vset)}


def format_markdown(result):
    lines = ["## 📈 评分详情（满分100分）", ""]
    lines.append("| 维度 | 权重 | 得分 | 扣分 | 扣分说明（规则ID） |")
    lines.append("|------|------|------|------|-----------------|")
    for d in DIMENSION_ORDER:
        score  = result["dimension_scores"][d]
        lost_d = result["dimension_lost"][d]
        maxd   = DIMENSION_MAX[d]
        vs = [r for r in result["rule_results"] if r["dimension"] == d and r["violated"]]
        reasons = "; ".join(f'{r["rule_id"]}(-{r["max_points"]})' for r in vs) if vs else "无扣分"
        lines.append(f"| **{d}** | {maxd}分 | {score}分 | {lost_d}分 | {reasons} |")
    lines.append(
        f"| **合计** | **100分** | **{result['total_score']}分** | "
        f"**{100 - result['total_score']}分** | 违规{result['violated_count']}处 |"
    )
    lines.append("")
    sc = result["dimension_scores"]
    lines.append(
        f"**得分核对**：{sc['结构完整性']} + {sc['内容规范性']} + {sc['数据准确性']} + "
        f"{sc['红线合规']} + {sc['格式完整性']} = {result['total_score']}"
    )
    lines.append(f"**评级**：{result['rating']}")
    return "\n".join(lines)


def format_rules():
    lines = [f"{'规则ID':<10} {'维度':<12} {'分值':>4}  说明", "-" * 96]
    for d in DIMENSION_ORDER:
        for rid, rule in SCORING_RULES.items():
            if rule["dimension"] == d:
                lines.append(f"{rid:<10} {rule['dimension']:<12} {rule['points']:>4}  {rule['description'][:62]}")
    lines.append("-" * 96)
    total_pts = sum(r["points"] for r in SCORING_RULES.values())
    lines.append(f"合计: {total_pts}分（{len(SCORING_RULES)}条规则）")
    for d in DIMENSION_ORDER:
        dpts = sum(r["points"] for r in SCORING_RULES.values() if r["dimension"] == d)
        lines.append(f"  {d}: {dpts}分")
    return "\n".join(lines)


def selftest():
    # 无违规 → 满分100
    r = calculate_score([])
    assert r["total_score"] == 100, f"无违规应满分100，得{r['total_score']}"

    # 维度分值合计校验
    for d in DIMENSION_ORDER:
        dpts = sum(v["points"] for v in SCORING_RULES.values() if v["dimension"] == d)
        assert dpts == DIMENSION_MAX[d], f"维度{d}规则合计{dpts}≠权重{DIMENSION_MAX[d]}"

    # 总分等于各维度权重之和
    assert sum(DIMENSION_MAX.values()) == 100, "维度权重合计应为100"

    # STR-01(4) → 结构完整性16，总分96
    r = calculate_score(["STR-01"])
    assert r["dimension_scores"]["结构完整性"] == 16
    assert r["total_score"] == 96

    # CNT-04(4)+RED-01(8) → 内容26+红线12，总分88
    r = calculate_score(["CNT-04", "RED-01"])
    assert r["dimension_scores"]["内容规范性"] == 26
    assert r["dimension_scores"]["红线合规"] == 12
    assert r["total_score"] == 88
    assert r["rating"] == "局部瑕疵（需微调）"

    # 严重违规场景：结构全扣(20)+数据全扣(20)+格式全扣(10) → 总分50
    all_str = ["STR-01", "STR-02", "STR-03", "STR-04", "STR-05", "STR-06"]
    all_dat = ["DAT-01", "DAT-02", "DAT-03", "DAT-04", "DAT-05"]
    all_fmt = ["FMT-01", "FMT-02", "FMT-03", "FMT-04", "FMT-05", "FMT-06"]
    r = calculate_score(all_str + all_dat + all_fmt)
    assert r["dimension_scores"]["结构完整性"] == 0
    assert r["dimension_scores"]["数据准确性"] == 0
    assert r["dimension_scores"]["格式完整性"] == 0
    assert r["total_score"] == 50
    assert r["rating"] == "严重违规"

    # 未知规则ID不扣分
    r = calculate_score(["UNKNOWN-99"])
    assert r["total_score"] == 100

    print(f"[OK] All selftests passed. 共{len(SCORING_RULES)}条规则，总分{sum(v['points'] for v in SCORING_RULES.values())}分。")


def main():
    parser = argparse.ArgumentParser(description="资产解读报告审计自动计分 (asset_report_audit)")
    parser.add_argument("violations", nargs="*", help="违规规则ID列表，如 STR-01 CNT-04 RED-01")
    parser.add_argument("--file",     help="从JSON文件读取违规列表")
    parser.add_argument("--stdin",    action="store_true", help="从标准输入读取JSON")
    parser.add_argument("--rules",    action="store_true", help="输出全量规则列表")
    parser.add_argument("--selftest", action="store_true", help="执行自测验证")
    parser.add_argument("--format",   choices=["markdown", "json", "text"], default="markdown")
    args = parser.parse_args()

    if args.selftest:
        selftest(); return
    if args.rules:
        print(format_rules()); return

    violations = []
    if args.file:
        with open(args.file) as f:
            data = json.load(f)
            violations = data.get("violations", data) if isinstance(data, dict) else data
    elif args.stdin:
        try:
            data = json.loads(sys.stdin.read())
            violations = data.get("violations", data) if isinstance(data, dict) else data
        except Exception:
            violations = []
    elif args.violations:
        violations = args.violations
    elif not sys.stdin.isatty():
        try:
            data = json.loads(sys.stdin.read())
            violations = data.get("violations", data) if isinstance(data, dict) else data
        except Exception:
            violations = []

    result = calculate_score(violations)
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.format == "markdown":
        print(format_markdown(result))
    else:
        print(f"总分: {result['total_score']}/100    评级: {result['rating']}")


if __name__ == "__main__":
    main()

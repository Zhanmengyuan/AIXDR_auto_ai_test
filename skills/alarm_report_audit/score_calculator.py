#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
告警解读报告审计评分计算器 (alarm_report_audit)

规则直接来源于 SKILL.md 一～五章节各条标注，共31条，总分100分。
五大维度：结构完整性20 / 逻辑分支30 / 内容质量10 / 红线合规20 / 处置建议20
"""
import argparse, json, sys

SCORING_RULES = {
    # ── 一、结构骨架完整性规则 → 结构完整性（20分）──────────────────────────
    "STR-01": {"dimension": "结构完整性", "points": 4,
               "description": "头部固定元数据块：告警编号/名称/生成时间三行引用块+两条---分隔线，任一缺失/乱序/格式变更即违规"},
    "STR-02": {"dimension": "结构完整性", "points": 3,
               "description": "报告正文前不得出现任何引导语/过渡性/思考性文字"},
    "STR-03": {"dimension": "结构完整性", "points": 4,
               "description": "强制6章节顺序固定（告警定性→关键实体→攻击结果与举证→当前攻击影响→风险预测→处置建议），缺/增/乱序=严重违规"},
    "STR-04": {"dimension": "结构完整性", "points": 3,
               "description": "章节命名固定，不增减/不调顺序/禁止章节间插入非法过渡段"},
    "STR-05": {"dimension": "结构完整性", "points": 4,
               "description": "一句话总结加粗(** **)、单行、与第3章攻击结果（成功/失败/未知）完全自洽，严禁矛盾"},
    "STR-06": {"dimension": "结构完整性", "points": 2,
               "description": "固定提示语字符级精确：所有『一字不可改』固定句多一个空格/标点均违规，禁止追加任何内容"},

    # ── 二、分支联动与固定话术强制规则 → 逻辑分支（30分）─────────────────────
    "BR-01": {"dimension": "逻辑分支", "points": 5,
              "description": "两维度独立判定不混淆：威胁定性(第1章)≠攻击结果(第3章)，误报≠失败，以报告自身结论为准校验自洽"},
    "BR-02": {"dimension": "逻辑分支", "points": 6,
              "description": "优先级1(不能确认)：第4/5/6章固定句一字不可改，第6章禁止输出任何排查/处置建议"},
    "BR-03": {"dimension": "逻辑分支", "points": 6,
              "description": "优先级2(误报)：第4/5章误报专用文案一字不可改，第6章输出误报确认+根因分析+规则优化三区块，禁止排查三层结构"},
    "BR-04": {"dimension": "逻辑分支", "points": 6,
              "description": "优先级3(正报+成功)：第4章数据/业务/系统三层+第5章五项风险+第6章『处置建议』五层含『当前处置状态』开头"},
    "BR-05": {"dimension": "逻辑分支", "points": 4,
              "description": "优先级4(正报+失败/未知)：第4/5章固定句+第6章『排查建议』三层，禁止紧急止血和加固修复"},
    "BR-06": {"dimension": "逻辑分支", "points": 3,
              "description": "误报时第1章含『误报原因』+『误判对象』；不能确认时含『不能确认原因』+『缺失信息』列表，缺任一即违规"},

    # ── 三、章节内容规范规则 → 内容质量（10分）──────────────────────────────
    "QUA-01": {"dimension": "内容质量", "points": 1,
               "description": "第1章判定依据固定四字段：引擎研判/检测引擎/告警分类/核心问题，缺任一即违规"},
    "QUA-02": {"dimension": "内容质量", "points": 1,
               "description": "第2章固定四大块结构完整：告警涉及网络实体→受影响资产→攻击载荷实体→关联IOC"},
    "QUA-03": {"dimension": "内容质量", "points": 1,
               "description": "第2章空值格式合规：禁止『属性：-』占位行；大类整体无内容时必须用规定提示语，禁自定义措辞（不校验字段与接口返回是否匹配）"},
    "QUA-04": {"dimension": "内容质量", "points": 1,
               "description": "第2章资产指纹字段格式规范：严禁写『未查询到（需补充）』『待补充』等补充说明（不校验写—还是具体值是否与接口数据一致）"},
    "QUA-05": {"dimension": "内容质量", "points": 1,
               "description": "第2章不强行分配攻击者/受害者角色：只陈述网络实体事实，不根据IP归属强行定义角色"},
    "QUA-06": {"dimension": "内容质量", "points": 1,
               "description": "第2章攻击载荷输出格式规范：禁止『分类标题+逐行—』占位格式；整体为空时必须且只能输出一行『未提取到攻击载荷信息。』（不校验字段覆盖完整性）"},
    "QUA-07": {"dimension": "内容质量", "points": 1,
               "description": "第2/3章边界清晰：第2章只写客观攻击行为数据，第3章只写结果性证据，严禁在第2章写成功/失败或在第3章重复载荷原始数据"},
    "QUA-08": {"dimension": "内容质量", "points": 2,
               "description": "第3章三合一：①攻击链阶段必须输出；②成功时按告警类型四分支差异化举证（终端/网络/认证/情报，必须选其一不得混用）；③未知时按告警类型四分支差异化缺失证据（严禁共用同一套模板）"},
    "QUA-09": {"dimension": "内容质量", "points": 1,
               "description": "第3章失败时三要素缺一不可：失败原因+拦截证据+失败阶段说明"},

    # ── 四、红线禁用项合规规则 → 红线合规（20分）───────────────────────────
    "RED-01": {"dimension": "红线合规", "points": 12,
               "description": "零英文字段名（SNAKE_CASE全大写如RESULT/AI_RESULT/ALERT_RESULT_FLAG/ATTACKER_IP/KILL_CHAIN或camelCase如asset_info，出现即违规）；白名单不计违规：CVE/ATT&CK/WAF/IPS/IDS/EDR/C2/HTTP/TCP等行业术语及软件产品名"},
    "RED-02": {"dimension": "红线合规", "points": 5,
               "description": "禁止捏造第3章未知状态缺失证据清单中的具体IP/文件路径/shell命令/端口/域名/Hash，只准写证据类型名称"},
    "RED-03": {"dimension": "红线合规", "points": 3,
               "description": "判定依据禁止暗示字段缺失：禁『字段为空』『引擎标识缺失』『ALERT_RESULT_FLAG为空』等，仅允许自然语言如『信息不足，无法完成告警定性』"},

    # ── 三、第6章处置建议 → 处置建议（20分）────────────────────────────────
    "HND-01": {"dimension": "处置建议", "points": 4,
               "description": "第6章章节标题字面格式：成功→必须有『处置建议』标题/失败未知→必须有『排查建议』标题/误报→禁止出现『处置/排查建议』标题/不能确认→直接固定句无标题（与BR-04/05的边界：BR管分支联动自洽，HND-01只管标题字面格式）"},
    "HND-02": {"dimension": "处置建议", "points": 5,
               "description": "分层结构不可调换：成功五层(紧急止血→快速验证→范围排查→深层取证→加固修复)；失败/未知三层(快速验证→范围排查→深层取证)，失败/未知时禁止出现紧急止血和加固修复"},
    "HND-03": {"dimension": "处置建议", "points": 4,
               "description": "告警类型动态调整每层重点（挖矿/暴力破解/漏洞利用/webshell/外联C2等），禁套固定模板/全列告警类型"},
    "HND-04": {"dimension": "处置建议", "points": 4,
               "description": "每层可执行命令（含参数无语法错误）或具体操作步骤，禁止『进一步排查』『加强监控』『建议关注』『持续观察』等笼统描述"},
    "HND-05": {"dimension": "处置建议", "points": 2,
               "description": "环境覆盖：命令需覆盖Linux和Windows两种环境，或说明适用环境"},
    "HND-06": {"dimension": "处置建议", "points": 1,
               "description": "正报+成功时第6章开头必须输出『当前处置状态：[已处置/未处置]』，已处置追加『已处置详情：...』"},
}

DIMENSION_ORDER = ["结构完整性", "逻辑分支", "内容质量", "红线合规", "处置建议"]
DIMENSION_MAX = {"结构完整性": 20, "逻辑分支": 30, "内容质量": 10, "红线合规": 20, "处置建议": 20}


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
        score = result["dimension_scores"][d]
        lost_d = result["dimension_lost"][d]
        maxd = DIMENSION_MAX[d]
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
        f"**得分核对**：{sc['结构完整性']} + {sc['逻辑分支']} + {sc['内容质量']} + "
        f"{sc['红线合规']} + {sc['处置建议']} = {result['total_score']}"
    )
    lines.append(f"**评级**：{result['rating']}")
    return "\n".join(lines)


def format_rules():
    lines = [f"{'规则ID':<10} {'维度':<12} {'分值':>4}  说明", "-" * 96]
    for d in DIMENSION_ORDER:
        for rid, rule in SCORING_RULES.items():
            if rule["dimension"] == d:
                lines.append(f"{rid:<10} {rule['dimension']:<12} {rule['points']:>4}  {rule['description'][:60]}")
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

    # STR-01(4分) → 结构完整性96，总分96
    r = calculate_score(["STR-01"])
    assert r["dimension_scores"]["结构完整性"] == 16, f"STR-01扣4分后结构完整性应16，得{r['dimension_scores']['结构完整性']}"
    assert r["total_score"] == 96

    # BR-02(6)+BR-03(6) → 逻辑分支18，总分88
    r = calculate_score(["BR-02", "BR-03"])
    assert r["dimension_scores"]["逻辑分支"] == 18
    assert r["total_score"] == 88
    assert r["rating"] == "局部瑕疵（需微调）"

    # 全部逻辑分支违规(30分)+RED-01(12分) → 总分58，严重违规
    r = calculate_score(["BR-01", "BR-02", "BR-03", "BR-04", "BR-05", "BR-06", "RED-01"])
    assert r["dimension_scores"]["逻辑分支"] == 0
    assert r["total_score"] == 58

    # 严重违规场景：逻辑分支全扣+红线全扣 → 100-30-20=50
    r = calculate_score(["BR-01", "BR-02", "BR-03", "BR-04", "BR-05", "BR-06",
                         "RED-01", "RED-02", "RED-03"])
    assert r["total_score"] == 50
    assert r["rating"] == "严重违规"

    # 未知规则ID不扣分
    r = calculate_score(["UNKNOWN-99"])
    assert r["total_score"] == 100

    print(f"[OK] All selftests passed. 共{len(SCORING_RULES)}条规则，总分{sum(v['points'] for v in SCORING_RULES.values())}分。")


def main():
    parser = argparse.ArgumentParser(description="告警解读报告审计自动计分 (alarm_report_audit)")
    parser.add_argument("violations", nargs="*", help="违规规则ID列表，如 BR-03 RED-01")
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

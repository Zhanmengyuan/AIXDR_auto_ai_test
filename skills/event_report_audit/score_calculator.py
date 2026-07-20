#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件解读报告审计评分计算器 (event_report_audit)

规则直接来源于 SKILL.md 一～六章节各条标注，共32条，总分100分。
六大维度：结构完整性15 / 聚合视角20 / 逻辑分支25 / 红线合规15 / 处置建议15 / 内容质量10
"""
import argparse, json, sys

SCORING_RULES = {
    # ── 一、结构骨架完整性规则 → 结构完整性（15分）─────────────────────────
    "STR-01": {"dimension": "结构完整性", "points": 4,
               "description": "头部固定元数据块：事件编号/名称/生成时间/关联告警数+时间跨度五行引用块+两条---分隔线，任一缺失/乱序/格式变更即违规；正文前有引导语亦违规"},
    "STR-02": {"dimension": "结构完整性", "points": 2,
               "description": "报告正文前不得出现任何引导语/过渡性/思考性文字"},
    "STR-03": {"dimension": "结构完整性", "points": 4,
               "description": "强制6章节顺序固定（事件定性→关键实体→攻击结果与举证→当前攻击影响→风险预测→处置建议），缺/增/乱序=严重违规"},
    "STR-04": {"dimension": "结构完整性", "points": 2,
               "description": "章节命名固定，不增减/不调顺序/禁止章节间插入非法过渡段"},
    "STR-05": {"dimension": "结构完整性", "points": 3,
               "description": "一句话总结：格式固定(**一句话总结：** [内容])，必须包含攻击者+动作+对象+后果四要素，严禁工具视角描述"},

    # ── 二、聚合视角强制规则 → 聚合视角（20分）─────────────────────────────
    "AGG-01": {"dimension": "聚合视角", "points": 4,
               "description": "实体去重聚合格式规范：报告中已出现的同一IP/域名/Hash实体严禁分多行重复列出，同一实体必须标注命中次数（不校验去重是否彻底）"},
    "AGG-02": {"dimension": "聚合视角", "points": 6,
               "description": "结果矩阵按资产聚合：第3章必须以表格按资产聚合(列:资产/成功/失败/未知/核心举证/整体判定)，严禁逐条告警平铺，严禁出现'关联告警数'列，整体判定列只允许已失陷/已拦截/待确认"},
    "AGG-03": {"dimension": "聚合视角", "points": 3,
               "description": "族谱聚合格式规范：报告中已出现的同名文件/同Hash/同域名C2/同CVE严禁分多行重复列出，同类实体必须标注命中次数（不校验归并是否彻底）"},
    "AGG-04": {"dimension": "聚合视角", "points": 4,
               "description": "第1章判定依据必须包含聚合特征描述（如'同源IP在5分钟内攻击3台资产'），缺失即违规"},
    "AGG-05": {"dimension": "聚合视角", "points": 3,
               "description": "服务器资产优先：第2章已标注为服务器类型的资产行必须排在终端类型行之前；第4章影响面必须区分服务器和终端数量（不校验类型分类是否准确）"},

    # ── 三、分支联动与固定话术强制规则 → 逻辑分支（25分）──────────────────
    "BR-01": {"dimension": "逻辑分支", "points": 3,
              "description": "两维度独立判定不混淆：威胁定性(第1章)≠攻击结果(第3章)，误报≠失败，以报告自身结论为准校验自洽"},
    "BR-02": {"dimension": "逻辑分支", "points": 5,
              "description": "优先级1(不能确认)：第4/5/6章固定句一字不可改，第6章禁止输出任何排查/处置建议"},
    "BR-03": {"dimension": "逻辑分支", "points": 4,
              "description": "优先级2(误报)：第4/5章误报专用文案一字不可改，第6章输出误报确认+根因分析+规则优化三区块，禁止三维排查结构"},
    "BR-04": {"dimension": "逻辑分支", "points": 5,
              "description": "优先级3(正报+成功)：第4章影响面统计(服务器/终端/失陷/拦截/待确认)+三层分析+内部自洽(第2章有资产时禁写『未查询到受影响资产信息』)；第5章六项风险维度(批量攻击/重点资产/横向渗透/持久化/二次攻击/APT驻留)每项有依据；第6章『处置建议』+处置状态行+三段结构"},
    "BR-05": {"dimension": "逻辑分支", "points": 3,
              "description": "优先级4(正报+失败/未知)：第4/5章固定句，第6章『排查建议』按攻击者/资产/载荷三维度组织，禁止紧急止血和加固修复"},
    "BR-06": {"dimension": "逻辑分支", "points": 3,
              "description": "误报时第1章含『误报原因』+『误判对象』；不能确认时含『不能确认原因』+『缺失信息』列表，缺任一即违规"},
    "BR-07": {"dimension": "逻辑分支", "points": 2,
              "description": "固定提示语字符级精确：所有『一字不可改』固定句多一个空格/标点均违规，禁止追加任何内容"},

    # ── 四、章节内容规范规则 → 内容质量（10分）─────────────────────────────
    "CNT-01": {"dimension": "内容质量", "points": 1,
               "description": "第1章固定结构四块：威胁定性结论/事件概况/核心问题/判定依据(引擎研判+聚合特征)段落是否存在（不校验统计数字准确性）"},
    "CNT-02": {"dimension": "内容质量", "points": 1,
               "description": "第1章核心问题必须为业务白话：严禁『该事件包含N条告警，触发了XX规则』这种工具视角描述"},
    "CNT-03": {"dimension": "内容质量", "points": 1,
               "description": "第2章固定五大块结构完整：事件涉及网络实体→受影响资产(表格)→资产指纹→攻击载荷实体→关联IOC"},
    "CNT-04": {"dimension": "内容质量", "points": 1,
               "description": "第2章受影响资产表格列名固定(资产IP/名称/类型/等级/业务系统/操作系统/责任人/资产状态/关联告警数)，列名齐全即合规（不校验单元格数据准确性）"},
    "CNT-05": {"dimension": "内容质量", "points": 1,
               "description": "第2章不强行分配攻击者/受害者角色：只陈述源IP/目的IP等网络实体事实，不根据IP归属强行定义角色"},
    "CNT-06": {"dimension": "内容质量", "points": 1,
               "description": "第2章资产指纹格式规范：严禁写『未查询到（需补充）』『待补充』等补充说明（不校验写—还是具体值是否与接口数据一致）"},
    "CNT-07": {"dimension": "内容质量", "points": 1,
               "description": "第2章攻击载荷输出格式规范：禁止『分类标题+逐行—』占位格式；整体为空时必须且只能输出一行『未提取到攻击载荷信息。』"},
    "CNT-08": {"dimension": "内容质量", "points": 1,
               "description": "第3章固定起始结构：攻击结果行+结果矩阵表格(资产/成功/失败/未知/核心举证/整体判定)均为必须输出项"},
    "CNT-09": {"dimension": "内容质量", "points": 1,
               "description": "第3章失败时两要素：失败原因+拦截证据两项均须存在（结构性，不校验聚合是否彻底）"},
    "CNT-10": {"dimension": "内容质量", "points": 1,
               "description": "第2/3章边界：严禁在第3章举证中重复第2章已有的攻击载荷原始数据"},

    # ── 五、红线禁用项合规规则 → 红线合规（15分）───────────────────────────
    "RED-01": {"dimension": "红线合规", "points": 10,
               "description": "零英文字段名（SNAKE_CASE全大写/camelCase接口字段名出现即违规）；白名单不计违规：CVE/CNNVD/ATT&CK/WAF/IPS/EDR/IDS/C2/HTTP/TCP等行业术语及软件产品名（判断违规时必须先排除白名单）"},
    "RED-02": {"dimension": "红线合规", "points": 3,
               "description": "禁止捏造第3章未知状态缺失证据清单中的具体IP/文件路径/shell命令/端口/域名/Hash，只准写证据类型名称（报告正文及处置命令中的数据不纳入审查）"},
    "RED-03": {"dimension": "红线合规", "points": 2,
               "description": "判定依据禁止暗示字段缺失：禁『字段为空』『引擎标识缺失』『ALERT_RESULT_FLAG为空』等，仅允许自然语言如『信息不足，无法完成事件定性』"},

    # ── 四、第6章处置建议 → 处置建议（15分）────────────────────────────────
    "HND-01": {"dimension": "处置建议", "points": 3,
               "description": "第6章章节标题字面格式：成功→必须有『处置建议』标题/失败未知→必须有『排查建议』标题/误报→禁止出现『处置/排查建议』标题/不能确认→直接固定句无标题（与BR-04/05边界：BR管分支联动自洽，HND-01只管标题字面格式）"},
    "HND-02": {"dimension": "处置建议", "points": 4,
               "description": "三维分解结构不可调换：成功(紧急止血→批量深度排查→加固修复)+处置状态行；失败/未知(攻击者/资产/载荷三维，每维快速验证→范围排查→深层取证)；禁止失败/未知时出现紧急止血和加固修复"},
    "HND-03": {"dimension": "处置建议", "points": 3,
               "description": "事件类型动态调整每层重点（挖矿/C2/webshell/勒索/暴力破解/漏洞利用等），禁套固定模板/全列事件类型"},
    "HND-04": {"dimension": "处置建议", "points": 2,
               "description": "批量化体现：多资产事件必须给出ansible/pssh/批量脚本等批量执行方式，禁止只给出单机命令"},
    "HND-05": {"dimension": "处置建议", "points": 2,
               "description": "每层可执行命令（含参数无语法错误）或具体操作步骤，禁止『进一步排查』『加强监控』『建议关注』『持续观察』等笼统描述"},
    "HND-06": {"dimension": "处置建议", "points": 1,
               "description": "环境覆盖：命令需覆盖Linux和Windows两种环境，或说明适用环境"},
}

DIMENSION_ORDER = ["结构完整性", "聚合视角", "逻辑分支", "红线合规", "处置建议", "内容质量"]
DIMENSION_MAX = {"结构完整性": 15, "聚合视角": 20, "逻辑分支": 25, "红线合规": 15, "处置建议": 15, "内容质量": 10}


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
        f"**得分核对**：{sc['结构完整性']} + {sc['聚合视角']} + {sc['逻辑分支']} + "
        f"{sc['红线合规']} + {sc['处置建议']} + {sc['内容质量']} = {result['total_score']}"
    )
    lines.append(f"**评级**：{result['rating']}")
    return "\n".join(lines)


def format_rules():
    lines = [f"{'规则ID':<10} {'维度':<10} {'分值':>4}  说明", "-" * 96]
    for d in DIMENSION_ORDER:
        for rid, rule in SCORING_RULES.items():
            if rule["dimension"] == d:
                lines.append(f"{rid:<10} {rule['dimension']:<10} {rule['points']:>4}  {rule['description'][:62]}")
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

    # AGG-02(6分) → 聚合视角14，总分94
    r = calculate_score(["AGG-02"])
    assert r["dimension_scores"]["聚合视角"] == 14, f"AGG-02扣6后聚合视角应14，得{r['dimension_scores']['聚合视角']}"
    assert r["total_score"] == 94

    # BR-02(5)+BR-03(4) → 逻辑分支16，总分91
    r = calculate_score(["BR-02", "BR-03"])
    assert r["dimension_scores"]["逻辑分支"] == 16, f"逻辑分支应16，得{r['dimension_scores']['逻辑分支']}"
    assert r["total_score"] == 91, f"总分应91，得{r['total_score']}"
    assert r["rating"] == "完全合规"

    # 严重违规场景：逻辑分支全扣(25)+聚合视角全扣(20) → 总分55
    all_br = ["BR-01", "BR-02", "BR-03", "BR-04", "BR-05", "BR-06", "BR-07"]
    all_agg = ["AGG-01", "AGG-02", "AGG-03", "AGG-04", "AGG-05"]
    r = calculate_score(all_br + all_agg)
    assert r["dimension_scores"]["逻辑分支"] == 0
    assert r["dimension_scores"]["聚合视角"] == 0
    assert r["total_score"] == 55
    assert r["rating"] == "严重违规"

    # 未知规则ID不扣分
    r = calculate_score(["UNKNOWN-99"])
    assert r["total_score"] == 100

    print(f"[OK] All selftests passed. 共{len(SCORING_RULES)}条规则，总分{sum(v['points'] for v in SCORING_RULES.values())}分。")


def main():
    parser = argparse.ArgumentParser(description="事件解读报告审计自动计分 (event_report_audit)")
    parser.add_argument("violations", nargs="*", help="违规规则ID列表，如 AGG-02 BR-03 RED-01")
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

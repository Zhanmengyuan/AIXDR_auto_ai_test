#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞解读报告审计评分计算器 (vuln_report_audit)

基于 vuln-interpretation 规范的详细评分规则，对漏洞解读报告审计结果
进行机械化评分，确保每次输出分数的稳定性。

设计原则:
- 每条规则独立计分：通过得满分，不通过得0分
- 5 大维度合计 = 100 分（结构完整性 20 + 研判结论 28 + 内容规范 24 + 红线 20 + 格式 8）
- 评分规则硬编码在脚本中，运行结果完全确定性

使用方法:
    # 1. 命令行指定违规规则ID
    python score_calculator.py STR-01 RED-04 JUD-03

    # 2. 从JSON文件读取违规列表
    python score_calculator.py --file violations.json

    # 3. 从stdin读取JSON
    echo '{"violations":["STR-01","RED-04"]}' | python score_calculator.py --stdin

    # 4. 显示所有规则详情
    python score_calculator.py --rules

    # 5. 自检脚本正确性
    python score_calculator.py --selftest

    # 6. JSON格式输出（便于其他工具集成）
    python score_calculator.py STR-01 --format json
"""

import argparse
import json
import sys
from typing import Dict, List


# ============================================================
# 评分规则定义
# 每个规则独立计分：通过得满分，不通过得0分
# ============================================================

SCORING_RULES: Dict[str, Dict] = {
    # ---------------- 结构完整性 (20分) ----------------
    "STR-01": {
        "dimension": "结构完整性",
        "points": 4,
        "description": "报告标题块强制格式正确：H1只含CVE编号 + 引用块三行字段 + ---分隔线",
    },
    "STR-02": {
        "dimension": "结构完整性",
        "points": 4,
        "description": "章节总数正确：1个研判结论 + 3或4个折叠章节",
    },
    "STR-03": {
        "dimension": "结构完整性",
        "points": 3,
        "description": "章节编号连续：第3章跳过时修复建议章正确重编号为第3章",
    },
    "STR-04": {
        "dimension": "结构完整性",
        "points": 3,
        "description": "折叠章节格式正确：details/summary/span 标签成对闭合",
    },
    "STR-05": {
        "dimension": "结构完整性",
        "points": 1,
        "description": "子节标题用 ### 三级且嵌套在父章节 details 内",
    },
    "STR-06": {
        "dimension": "结构完整性",
        "points": 2,
        "description": "无规定外额外章节（处置修复建议/临时措施/总结/附录等）",
    },
    "STR-07": {
        "dimension": "结构完整性",
        "points": 1,
        "description": "无中文数字顶级编号（一、二、三等）",
    },
    "STR-08": {
        "dimension": "结构完整性",
        "points": 2,
        "description": "无前言/结束语/总结段/署名/客套话",
    },

    # ---------------- 研判结论规范性 (28分) ----------------
    "JUD-01": {
        "dimension": "研判结论规范性",
        "points": 2,
        "description": "## 漏洞研判结论 为 H2 标题且位置紧跟标题块",
    },
    "JUD-02": {
        "dimension": "研判结论规范性",
        "points": 6,
        "description": "判定结果只有'是'或'否'，无'建议关注/较高风险'等模糊词",
    },
    "JUD-03": {
        "dimension": "研判结论规范性",
        "points": 8,
        "description": "判定逻辑符合充要条件：公网暴露>0 + CVSS≥7(以1.1节表格值为准) + 易利用(任一) 同时满足才判'是'；CVSS在研判结论/1.1节/判断依据三处一致",
    },
    "JUD-04": {
        "dimension": "研判结论规范性",
        "points": 4,
        "description": "醒目样式正确：是→红色#d9534f；否→绿色#5cb85c",
    },
    "JUD-05": {
        "dimension": "研判结论规范性",
        "points": 2,
        "description": "研判结论未加框（无 border/background 等加框样式）",
    },
    "JUD-06": {
        "dimension": "研判结论规范性",
        "points": 3,
        "description": "研判结论包含三项：判断依据 + 受影响资产数 + 公网暴露风险评估结果",
    },
    "JUD-07": {
        "dimension": "研判结论规范性",
        "points": 3,
        "description": "第3章联动正确：判'是'→输出第3章；判'否'→不输出第3章",
    },

    # ---------------- 内容规范性 (24分) ----------------
    "CH1-01": {
        "dimension": "内容规范性",
        "points": 2,
        "description": "1.1 节表格固定9列且列名顺序正确（CVE编号/漏洞名称/CVSS/类型/软件/版本/当前版本/CNNVD/发布时间）",
    },
    "CH1-02": {
        "dimension": "内容规范性",
        "points": 2,
        "description": "1.2 节表格固定4行（远程利用/在野利用/公开POC/利用难度）",
    },
    "CH1-03": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "1.2 节利用难度为基于三维度的一句话综合总结（无 CVSS 缩写罗列）",
    },
    "CH1-04": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "第1章只有 1.1 和 1.2 两个子节，无 1.3 等额外子节",
    },
    "CH2-01": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "2.1 技术成因用专业语言描述漏洞原理，无生活类比",
    },
    "CH2-02": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "2.2 CWE 关联输出关联 CWE 编号及名称",
    },
    "CH2-03": {
        "dimension": "内容规范性",
        "points": 2,
        "description": "2.3 CVSS 3.1 维度表格固定7行（攻击向量/复杂度/权限/交互/机密性/完整性/可用性）",
    },
    "CH2-04": {
        "dimension": "内容规范性",
        "points": 3,
        "description": "2.3 仅展示中文部分，剥离 AV:/AC:/PR:/UI: 等英文缩写",
    },
    "CH2-05": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "2.3 仅输出表格，前后无说明文字/规则描述/格式提示",
    },
    "CH2-06": {
        "dimension": "内容规范性",
        "points": 2,
        "description": "2.3 末尾未追加综合评分（X.X）",
    },
    "CH2-07": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "2.4 攻击链路推演固定三步（接近目标→触发漏洞→达成目的）",
    },
    # CH2-08 已删除（原"2.5小结不出修复建议"，由 STR-06 兜底）
    "CH2-09": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "第2章只有 2.1~2.5 共5个子节，无 2.6/2.7 等额外子节",
    },
    "CH3-01": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "3.1 资产统计表格2行（受影响资产总数/公网暴露资产）；资产数与研判结论一致",
    },
    "CH3-02": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "3.2 公网暴露资产详情表7列；空时输出'无'",
    },
    "CH3-03": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "3.3 分析结论总结本章核心要点（资产数+分布特点）",
    },
    "FIX-01": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "修复建议章 N.1 修复紧迫度表格3行始终输出",
    },
    "FIX-02": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "N.2 补丁/N.3 升级路径条件性子节正确跳过，不留占位不写'无'",
    },
    "FIX-03": {
        "dimension": "内容规范性",
        "points": 1,
        "description": "长期防护编号动态压缩正确，无断档跳号",
    },

    # ---------------- 红线合规 (20分) ----------------
    "RED-01": {
        "dimension": "红线合规",
        "points": 5,
        "description": "全文无接口/规则字段名（isExposure/isPoc/inTheWild/remoteExploitation 等）",
    },
    "RED-02": {
        "dimension": "红线合规",
        "points": 5,
        "description": "全文无英文字段名（vulnCveCode/vulnName/cvssScore/attackVector 等模板变量）",
    },
    # RED-03 已删除（原"允许的英文术语正确保留"，白名单说明已合并到 RED-01/RED-02 定义中）
    "RED-04": {
        "dimension": "红线合规",
        "points": 5,
        "description": "无数据内部矛盾与明显捏造（前后一致、CVE格式合法、CVSS在0-10范围、IP格式合法、时间戳非未来）",
    },
    "RED-05": {
        "dimension": "红线合规",
        "points": 2,
        "description": "全文无联网搜索痕迹（无搜索引擎/外部网站引用/网页抓取/通用知识库口吻等文本特征）",
    },
    "RED-06": {
        "dimension": "红线合规",
        "points": 1,
        "description": "全文无图表代码与图片引用（无ECharts代码/Base64图片/img标签/canvas/svg）",
    },
    "RED-07": {
        "dimension": "红线合规",
        "points": 2,
        "description": "全文无自定义提示块（:::warning/:::info/:::tip 等）",
    },

    # ---------------- 格式完整性 (8分) ----------------
    "FMT-01": {
        "dimension": "格式完整性",
        "points": 2,
        "description": "空值填'未查询到'，无捏造无留空",
    },
    "FMT-02": {
        "dimension": "格式完整性",
        "points": 3,
        "description": "HTML 标签成对闭合（details/summary/span 无遗漏）",
    },
    "FMT-03": {
        "dimension": "格式完整性",
        "points": 2,
        "description": "URL 链接用 <a href=\"...\" target=\"_blank\"> 显示文本 </a> 格式",
    },
    # FMT-04 已删除（原"时间格式统一为YYYY-MM-DD HH:MM"，由 STR-01 标题块生成时间格式间接约束）
    "FMT-05": {
        "dimension": "格式完整性",
        "points": 1,
        "description": "无占位符（—/null/无等；3.2 节公网暴露资产为空时输出'无'除外）",
    },
}


# 维度配置
DIMENSION_MAX: Dict[str, int] = {
    "结构完整性": 20,
    "研判结论规范性": 28,
    "内容规范性": 24,
    "红线合规": 20,
    "格式完整性": 8,
}

DIMENSION_ORDER: List[str] = [
    "结构完整性",
    "研判结论规范性",
    "内容规范性",
    "红线合规",
    "格式完整性",
]


def calculate_score(violated_rules: List[str]) -> Dict:
    """
    根据违规规则列表计算得分。

    Args:
        violated_rules: 违规规则ID列表，如 ["STR-01", "RED-04"]

    Returns:
        包含总分、各维度得分、评级、每条规则评估结果的字典
    """
    violated_set = set(violated_rules or [])

    # 校验规则ID有效性
    unknown = violated_set - set(SCORING_RULES.keys())
    if unknown:
        raise ValueError(f"未知规则ID: {sorted(unknown)}")

    # 初始化维度得分
    dimension_scores: Dict[str, int] = {dim: DIMENSION_MAX[dim] for dim in DIMENSION_ORDER}
    dimension_lost: Dict[str, int] = {dim: 0 for dim in DIMENSION_ORDER}
    rule_results: List[Dict] = []

    # 按规则ID排序遍历，确保输出一致
    for rule_id in sorted(SCORING_RULES.keys()):
        info = SCORING_RULES[rule_id]
        dim = info["dimension"]
        pts = info["points"]
        desc = info["description"]
        violated = rule_id in violated_set

        if violated:
            dimension_scores[dim] -= pts
            dimension_lost[dim] += pts

        rule_results.append({
            "rule_id": rule_id,
            "dimension": dim,
            "description": desc,
            "max_points": pts,
            "violated": violated,
            "earned": 0 if violated else pts,
        })

    total = sum(dimension_scores.values())

    # 评级映射
    if total >= 90:
        rating = "完全合规"
        action = "可直接发布"
    elif total >= 60:
        rating = "局部瑕疵（需微调）"
        action = "修正后可发布"
    else:
        rating = "严重违规"
        action = "修正重新生成"

    return {
        "total_score": total,
        "max_score": 100,
        "rating": rating,
        "action": action,
        "dimension_scores": dimension_scores,
        "dimension_lost": dimension_lost,
        "dimension_max": DIMENSION_MAX,
        "rule_results": rule_results,
        "violated_count": len(violated_set),
        "violated_rules": sorted(violated_set),
    }


def format_markdown_table(result: Dict) -> str:
    """格式化为 Markdown 表格（直接嵌入审计报告）"""
    lines: List[str] = []
    lines.append("## 📈 评分详情（满分100分）")
    lines.append("")
    lines.append("| 维度 | 权重 | 得分 | 扣分 | 扣分说明 |")
    lines.append("|------|------|------|------|----------|")

    for dim in DIMENSION_ORDER:
        score = result["dimension_scores"][dim]
        lost = result["dimension_lost"][dim]
        max_score = result["dimension_max"][dim]

        # 列出本维度被扣分的规则
        dim_violated = [
            r for r in result["rule_results"]
            if r["dimension"] == dim and r["violated"]
        ]
        if dim_violated:
            reasons = "; ".join(
                f"{r['rule_id']}(-{r['max_points']})" for r in dim_violated
            )
        else:
            reasons = "无扣分"

        lines.append(
            f"| **{dim}** | {max_score}分 | {score}分 | {lost}分 | {reasons} |"
        )

    lines.append(
        f"| **合计** | **100分** | **{result['total_score']}分** | "
        f"**{100 - result['total_score']}分** | 违规{result['violated_count']}处 |"
    )
    lines.append("")
    lines.append("### 评级映射标准")
    lines.append("")
    lines.append("| 分数区间 | 评级 | 处置 |")
    lines.append("|----------|------|------|")
    lines.append("| 90-100分 | 完全合规 | 可直接发布 |")
    lines.append("| 60-89分 | 局部瑕疵（需微调） | 修正后可发布 |")
    lines.append("| 0-59分 | 严重违规 | 修正重新生成 |")

    # 得分核对公式（强制验证）
    formula = " + ".join(str(result["dimension_scores"][d]) for d in DIMENSION_ORDER)
    lines.append("")
    lines.append(f"**得分核对**：`{formula} = {result['total_score']}` ✅")

    return "\n".join(lines)


def format_text(result: Dict) -> str:
    """格式化为纯文本（便于日志查看）"""
    lines: List[str] = []
    lines.append(f"综合得分: {result['total_score']}/100 ({result['rating']})")
    lines.append(f"违规数: {result['violated_count']}")
    lines.append(f"处置: {result['action']}")
    lines.append("-" * 60)
    for dim in DIMENSION_ORDER:
        score = result["dimension_scores"][dim]
        lost = result["dimension_lost"][dim]
        max_score = result["dimension_max"][dim]
        lines.append(f"  {dim}: {score}/{max_score} (扣{lost}分)")
    lines.append("-" * 60)
    if result["violated_rules"]:
        lines.append("违规规则: " + ", ".join(result["violated_rules"]))
    return "\n".join(lines)


def format_rules_table() -> str:
    """显示所有评分规则详情（用于 --rules）"""
    lines: List[str] = []
    lines.append(f"{'规则ID':<10} {'维度':<20} {'分值':>4}  说明")
    lines.append("-" * 110)

    current_dim = None
    for rule_id in sorted(SCORING_RULES.keys()):
        info = SCORING_RULES[rule_id]
        if info["dimension"] != current_dim:
            current_dim = info["dimension"]
            lines.append(f"--- [{current_dim}] ---")
        lines.append(
            f"{rule_id:<10} {info['dimension']:<18} {info['points']:>4}  {info['description']}"
        )

    lines.append("-" * 110)
    total = sum(r["points"] for r in SCORING_RULES.values())
    lines.append(f"合计: {total}分 ({len(SCORING_RULES)}条规则)")
    return "\n".join(lines)


def selftest() -> None:
    """自检：验证总分等于100分、各维度合计正确、典型场景正确"""
    # 满分校验
    result = calculate_score([])
    assert result["total_score"] == 100, (
        "Full score should be 100, got " + str(result["total_score"])
    )

    # 维度合计校验
    for dim in DIMENSION_ORDER:
        rules_in_dim = [
            r for r in SCORING_RULES.values() if r["dimension"] == dim
        ]
        total_pts = sum(r["points"] for r in rules_in_dim)
        assert total_pts == DIMENSION_MAX[dim], (
            "Dimension " + dim + " total should be "
            + str(DIMENSION_MAX[dim]) + ", got " + str(total_pts)
        )

    # 全部违规=0分
    result_all = calculate_score(list(SCORING_RULES.keys()))
    assert result_all["total_score"] == 0, (
        "All violations should give 0, got " + str(result_all["total_score"])
    )

    # 单条违规（跨维度抽样）
    # 格式: (violations, expected_total, expected_dims...)
    # 维度顺序: 结构(20), 研判(28), 内容(24), 红线(20), 格式(8)
    test_cases = [
        (["STR-01"], 96, 16, 28, 24, 20, 8),     # STR-01 扣4分 -> 结构=16
        (["JUD-02"], 94, 20, 22, 24, 20, 8),     # JUD-02 扣6分 -> 研判=22
        (["JUD-03"], 92, 20, 20, 24, 20, 8),     # JUD-03 扣8分 -> 研判=20
        (["RED-01"], 95, 20, 28, 24, 15, 8),     # RED-01 扣5分 -> 红线=15
        (["RED-04"], 95, 20, 28, 24, 15, 8),     # RED-04 扣5分 -> 红线=15
        (["FMT-02"], 97, 20, 28, 24, 20, 5),     # FMT-02 扣3分 -> 格式=5
        (["CH2-04"], 97, 20, 28, 21, 20, 8),     # CH2-04 扣3分 -> 内容=21
        (["STR-01", "RED-01"], 91, 16, 28, 24, 15, 8),  # 跨维度 4+5=9 -> 91
        (["STR-01", "JUD-02"], 90, 16, 22, 24, 20, 8),  # 跨维度 4+6=10 -> 90
    ]
    for case in test_cases:
        v, expected, *expected_dims = case
        r = calculate_score(v)
        assert r["total_score"] == expected, (
            "Violations " + str(v) + " expected total "
            + str(expected) + ", got " + str(r["total_score"])
        )
        for i, dim in enumerate(DIMENSION_ORDER):
            assert r["dimension_scores"][dim] == expected_dims[i], (
                "Violations " + str(v) + " dimension " + dim
                + " expected " + str(expected_dims[i])
                + ", got " + str(r["dimension_scores"][dim])
            )

    # 评分稳定性：相同输入必须得到相同输出
    r1 = calculate_score(["STR-01", "RED-01"])
    r2 = calculate_score(["RED-01", "STR-01"])  # 顺序不同
    assert r1["total_score"] == r2["total_score"]
    assert r1["dimension_scores"] == r2["dimension_scores"]

    # 评级映射校验（90 / 60 阈值）
    # 100 分 -> 完全合规
    assert calculate_score([])["rating"] == "完全合规"
    # 96 分 -> 完全合规
    assert calculate_score(["STR-01"])["rating"] == "完全合规"
    # 90 分 -> 完全合规（边界）
    assert calculate_score(["STR-01", "JUD-02"])["rating"] == "完全合规"
    # 89 分 -> 局部瑕疵（需微调）
    assert (
        calculate_score(["STR-01", "JUD-02", "FMT-05"])["rating"]
        == "局部瑕疵（需微调）"
    )
    # 严重违规测试
    severe_violations = [
        "STR-01", "STR-02", "STR-04", "JUD-02", "JUD-03", "JUD-04",
        "RED-01", "RED-02", "CH1-01", "CH2-03", "CH2-04", "FMT-02",
    ]
    # 4+4+3+6+8+4+5+5+2+2+3+3 = 49 -> 51分
    assert calculate_score(severe_violations)["rating"] == "严重违规"

    # 边界值校验：恰好 90 分 -> 完全合规（扣10分）
    boundary_90 = ["STR-01", "JUD-02"]  # 4+6 = 10
    assert calculate_score(boundary_90)["total_score"] == 90
    assert calculate_score(boundary_90)["rating"] == "完全合规"

    # 边界值校验：恰好 60 分 -> 局部瑕疵（扣40分）
    boundary_60 = ["STR-01", "STR-02", "STR-04",
                   "JUD-02", "JUD-03", "JUD-04",
                   "RED-01", "RED-02"]  # 4+4+3+6+8+4+5+5 = 39? 不对
    # 重算: 4+4+3=11(STR) + 6+8+4=18(JUD) + 5+5=10(RED) = 39 -> 61
    boundary_60 = ["STR-01", "STR-02", "STR-04",
                   "JUD-02", "JUD-03", "JUD-04",
                   "RED-01", "RED-02", "FMT-05"]  # 39+1 = 40 -> 60
    assert calculate_score(boundary_60)["total_score"] == 60
    assert calculate_score(boundary_60)["rating"] == "局部瑕疵（需微调）"

    # 边界值校验：59 分 -> 严重违规（扣41分）
    boundary_59 = boundary_60 + ["CH2-05"]  # 40+1 = 41 -> 59
    assert calculate_score(boundary_59)["total_score"] == 59
    assert calculate_score(boundary_59)["rating"] == "严重违规"

    print("[OK] All self-tests passed:")
    print("  - Total score = 100 check passed")
    print("  - 5 dimensions sum = "
          + str(list(DIMENSION_MAX.values())) + " = 100")
    print("  - All violations = 0; single violation deduction correct")
    print("  - Cross-dimension deduction sum correct (9 cases)")
    print("  - Stability: same violations in different order -> same output")
    print("  - Rating mapping (90 / 60 thresholds) correct")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="漏洞解读报告审计评分计算器 (vuln_report_audit)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python score_calculator.py STR-01 RED-04   # 命令行指定违规
  python score_calculator.py --file violations.json  # 从JSON文件读取
  python score_calculator.py --rules         # 显示所有规则
  python score_calculator.py --selftest      # 自检
        """,
    )
    parser.add_argument(
        "violations", nargs="*", help="违规规则ID列表（如 STR-01 RED-04）"
    )
    parser.add_argument("--file", help="从JSON文件读取违规列表")
    parser.add_argument("--stdin", action="store_true", help="从stdin读取JSON")
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "text"],
        default="markdown",
        help="输出格式（默认markdown）",
    )
    parser.add_argument("--rules", action="store_true", help="显示所有规则详情")
    parser.add_argument("--selftest", action="store_true", help="运行自检")

    args = parser.parse_args()

    if args.selftest:
        selftest()
        return

    if args.rules:
        print(format_rules_table())
        return

    violations: List[str] = []

    if args.violations:
        violations = args.violations
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
            violations = (
                data.get("violations", data)
                if isinstance(data, list)
                else data.get("violations", [])
            )
    elif args.stdin or not sys.stdin.isatty():
        try:
            content = sys.stdin.read()
            if content.strip():
                data = json.loads(content)
                violations = (
                    data.get("violations", data)
                    if isinstance(data, list)
                    else data.get("violations", [])
                )
        except json.JSONDecodeError:
            pass

    try:
        result = calculate_score(violations)
    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.format == "text":
        print(format_text(result))
    else:
        print(format_markdown_table(result))


if __name__ == "__main__":
    main()

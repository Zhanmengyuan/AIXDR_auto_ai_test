"""
Demo 一键运行脚本

整合 Pull 模式（现有解读数据）+ Push 模式（模拟安全Copilot），
生成跨智能体统一对比报告。

使用方式:
    python run_demo.py                    # 用最新一次解读数据 + 模拟Push数据
    python run_demo.py --run-id 20261106_230002  # 指定某次解读数据

效果:
    读取解读测试的 standard_results.json（或旧格式自动补 dimension）
    + 模拟安全Copilot的 Push 数据
    → 统一 HTML 报告（第一张表横向对比各智能体准确性）
"""
import json
import os
import sys
import argparse
import glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.reporter.unified_report_generator import UnifiedReportGenerator, AGENT_INFO
from scripts.mock_push_agent import generate_mock_copilot_results


# ── Pull 智能体与对应模块的映射 ──
PULL_AGENT_MODULES = {
    "ai_interpret_alarm": "alarm",
    "ai_interpret_event": "event",
    "ai_interpret_asset": "asset",
    "ai_interpret_vuln": "vuln",
    "ai_interpret_sandbox": "sandbox",
}

# ── 旧数据补 dimension 标签的映射表 ──
METRIC_DIMENSION_MAP = {
    "first_packet_time": "performance",
    "total_response_time": "performance",
    "response_time": "performance",
    "risk_level_accuracy": "accuracy",
    "threat_determination_accuracy": "accuracy",
    "attack_result_accuracy": "accuracy",
    "chapter_structure_completeness": "accuracy",
    "dynamic_structure_completeness": "accuracy",
    "field_completeness": "accuracy",
    "sample_info_accuracy": "accuracy",
    "disposal_rationality": "accuracy",
    "recommend_question_quality": "compliance",
    "format_compliance": "compliance",
    "section_completeness": "compliance",
}


def find_latest_run_dir() -> str:
    """找到最新一次解读测试的输出目录"""
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs", "ai_test_agent")
    if not os.path.exists(base):
        return None
    dirs = sorted([
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d)) and d[0].isdigit()
    ], reverse=True)
    return os.path.join(base, dirs[0]) if dirs else None


def load_pull_results(run_dir: str, agent_filter: list = None) -> dict:
    """从解读测试目录加载 Pull 智能体的 StandardResult 数据

    优先读取 standard_results.json（新格式），
    如果没有则从 ai_interpret_test_report.json（旧格式）提取并补 dimension 标签。

    Args:
        run_dir: 解读测试输出目录
        agent_filter: 只加载这些 agent_id，None 则全部加载

    Returns:
        {agent_id: [StandardResult dict, ...]}
    """
    # 优先尝试新格式
    sr_path = os.path.join(run_dir, "standard_results.json")
    if os.path.exists(sr_path):
        with open(sr_path, "r", encoding="utf-8") as f:
            all_results = json.load(f)
        results_by_agent = {}
        for r in all_results:
            agent_id = r.get("agent_id", "")
            if agent_filter and agent_id not in agent_filter:
                continue
            results_by_agent.setdefault(agent_id, []).append(r)
        if results_by_agent:
            print(f"✅ 从新格式 standard_results.json 加载: {sum(len(v) for v in results_by_agent.values())}条")
            return results_by_agent

    # 旧格式：从 ai_interpret_test_report.json 提取
    report_path = os.path.join(run_dir, "ai_interpret_test_report.json")
    if not os.path.exists(report_path):
        print(f"⚠️ 目录中无测试数据: {run_dir}")
        return {}

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    results_by_agent = {}
    for module_key, module_data in report.get("modules", {}).items():
        agent_id = f"ai_interpret_{module_key}"
        if agent_filter and agent_id not in agent_filter:
            continue
        if agent_id not in AGENT_INFO:
            continue

        results = []
        for tc in module_data.get("test_cases", []):
            metrics = []
            for mkey, mdata in tc.get("metrics", {}).items():
                if not isinstance(mdata, dict):
                    continue
                dimension = mdata.get("dimension") or METRIC_DIMENSION_MAP.get(mkey, "accuracy")
                metrics.append({
                    "dimension": dimension,
                    "key": mkey,
                    "name_cn": mdata.get("metric_cn", mkey),
                    "value": mdata.get("ai_value", mdata.get("value")),
                    "expected": mdata.get("api_value"),
                    "accuracy": mdata.get("accuracy"),
                    "passed": mdata.get("is_passed", mdata.get("passed", False)),
                    "score": mdata.get("score"),
                    "max_score": mdata.get("max_score"),
                    "detail": mdata.get("detail", {}),
                })

            status = "valid"
            if not tc.get("success", False):
                status = "failed"
            elif tc.get("is_invalid", False):
                status = "invalid"

            # 找业务 ID
            sample_id = ""
            for k in ["alarm_id", "event_id", "asset_id", "vuln_id", "sandbox_id"]:
                if k in tc:
                    sample_id = str(tc[k])
                    break

            results.append({
                "agent_id": agent_id,
                "case_id": tc.get("case_id", ""),
                "sample_id": sample_id,
                "run_id": "",
                "status": status,
                "first_packet_time": tc.get("first_packet_time", 0),
                "total_response_time": tc.get("total_response_time", 0),
                "metrics": metrics,
                "raw_text": "",
                "error": tc.get("error", ""),
                "timestamp": "",
            })

        if results:
            results_by_agent[agent_id] = results

    print(f"✅ 从旧格式报告加载并补维度标签: {sum(len(v) for v in results_by_agent.values())}条")
    return results_by_agent


def load_push_results(run_id: str) -> list:
    """生成模拟 Push 智能体的测试结果"""
    results = generate_mock_copilot_results(run_id)
    print(f"✅ 生成模拟安全Copilot(Push)数据: {len(results)}条")
    return results


def run_demo(run_dir: str = None, demo_agents: list = None, run_id: str = None):
    """运行 Demo

    Args:
        run_dir: 解读测试目录（None 则取最新）
        demo_agents: 要展示的 agent_id 列表
        run_id: 批次ID
    """
    # 确定数据目录
    if not run_dir:
        run_dir = find_latest_run_dir()
        if not run_dir:
            print("❌ 未找到任何解读测试数据，请先运行 python run_ai_test_agent.py --mode all")
            return

    print(f"\n{'='*60}")
    print(f"🚀 AI 智能体统一测试框架 Demo")
    print(f"{'='*60}")
    print(f"📂 数据目录: {run_dir}")

    if not run_id:
        run_id = os.path.basename(run_dir)

    # 默认 Demo 智能体：3个Pull + 1个Push
    if not demo_agents:
        demo_agents = [
            "ai_interpret_alarm",
            "ai_interpret_event",
            "ai_interpret_asset",
            "xdr_copilot",
        ]

    print(f"🤖 参测智能体: {', '.join(demo_agents)}")
    print(f"{'='*60}\n")

    # 1. 加载 Pull 数据
    pull_filter = [a for a in demo_agents if a.startswith("ai_interpret_")]
    pull_results = load_pull_results(run_dir, agent_filter=pull_filter)

    # 2. 加载 Push 数据
    push_results = {}
    if "xdr_copilot" in demo_agents:
        push_results["xdr_copilot"] = load_push_results(run_id)

    # 3. 合并
    all_results = {}
    all_results.update(pull_results)
    all_results.update(push_results)

    # 过滤掉没有数据的智能体
    all_results = {k: v for k, v in all_results.items() if v}

    if not all_results:
        print("❌ 没有可用的测试数据，请先运行解读测试")
        return

    print(f"\n📊 最终参与对比的智能体:")
    for agent_id, results in all_results.items():
        info = AGENT_INFO.get(agent_id, {"name": agent_id, "mode": "?"})
        mode = info.get("mode", "?")
        print(f"   {info['name']:20s} ({mode:4s}) — {len(results)} 条结果")

    # 4. 生成统一报告
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs", "demo")
    generator = UnifiedReportGenerator(output_dir)
    html_path = generator.generate(all_results, run_id=run_id)

    print(f"\n{'='*60}")
    print(f"✅ Demo 完成！统一报告已生成:")
    print(f"   {html_path}")
    print(f"{'='*60}")

    # 尝试自动打开
    try:
        import subprocess
        subprocess.Popen(["open", html_path])
        print(f"📎 已在浏览器中打开")
    except Exception:
        pass

    return html_path


def main():
    parser = argparse.ArgumentParser(description="AI 智能体统一测试框架 Demo")
    parser.add_argument(
        "--run-id",
        help="指定解读测试的批次ID（目录名），如 20261106_230002。不指定则取最新"
    )
    parser.add_argument(
        "--agents",
        nargs="*",
        default=None,
        help="指定要展示的智能体ID（空格分隔），默认: ai_interpret_alarm ai_interpret_event ai_interpret_asset xdr_copilot"
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    run_dir = os.path.join(base_dir, "outputs", "ai_test_agent", args.run_id) if args.run_id else None

    run_demo(
        run_dir=run_dir,
        demo_agents=args.agents,
        run_id=args.run_id,
    )


if __name__ == "__main__":
    main()

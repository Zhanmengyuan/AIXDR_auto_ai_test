"""
统一报告入口脚本

读取某批次所有智能体上传的JSON，调评分引擎算分，生成HTML报告。

使用方式：
    python run_unified_report.py --run-id v190_20261117
    python run_unified_report.py --run-id v190_20261117 --output custom_report.html
"""
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.reporter.summary_reporter import (
    load_results,
    process_agent,
    calculate_overall_scores,
    generate_html_report,
)
from core.validator import ManifestRegistry


def main():
    parser = argparse.ArgumentParser(description="AI 智能体统一测试报告生成")
    parser.add_argument("--run-id", required=True, help="批次标识，如 v190_20261117")
    parser.add_argument("--output", default=None, help="输出文件名（默认自动生成）")
    args = parser.parse_args()

    run_id = args.run_id

    print(f"\n{'='*60}")
    print(f"📊 AI 智能体统一测试报告生成")
    print(f"{'='*60}")
    print(f"🏷️ 批次: {run_id}")

    # 1. 加载声明文件
    registry = ManifestRegistry.get_instance()
    print(f"📋 已加载 {len(registry.list_agents())} 个智能体声明文件")

    # 2. 读取上传的JSON
    raw_results = load_results(run_id)
    if not raw_results:
        print(f"❌ 未找到批次 {run_id} 的任何结果文件")
        print(f"   请检查 outputs/results/{run_id}/ 目录是否存在")
        print(f"   各团队需先通过 HTTP 接口上传结果")
        return

    print(f"📂 读取到 {len(raw_results)} 个智能体结果:")
    for agent_id in sorted(raw_results.keys()):
        print(f"   - {agent_id}")

    # 3. 逐个处理智能体：算分
    print(f"\n{'='*60}")
    print(f"⚙️ 开始评分...")
    agent_results = {}
    for agent_id, data in raw_results.items():
        result = process_agent(agent_id, data, registry)
        agent_results[agent_id] = result
        print(f"   {result['name']:20s} → 综合={result['agent_score']:5.1f} 评级={result['rating']}")

    # 4. 算整体综合分
    overall = calculate_overall_scores(agent_results)
    print(f"\n📊 整体综合分: {overall['overall']}（类间等权）")
    for cat, score in overall["category_means"].items():
        print(f"   {cat:10s} → {score}")

    # 5. 生成HTML报告
    print(f"\n{'='*60}")
    print(f"📄 生成报告...")
    html = generate_html_report(agent_results, run_id, overall)

    # 保存
    base_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(base_dir, "outputs", "reports", run_id)
    os.makedirs(reports_dir, exist_ok=True)

    if args.output:
        filename = args.output
    else:
        filename = f"accuracy_report_{run_id}.html"

    filepath = os.path.join(reports_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ 报告已生成: {filepath}")

    # 尝试打开
    try:
        import subprocess
        subprocess.Popen(["open", filepath])
        print(f"📎 已在浏览器中打开")
    except Exception:
        pass

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

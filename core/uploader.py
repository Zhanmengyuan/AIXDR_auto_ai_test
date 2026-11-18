"""
通用上传工具

提供 v3 JSON 组装和保存的统一入口，供解读测试和稳定性测试脚本调用。
测试跑完后生成 v3 JSON 文件，并打印 curl 上传命令（不自动上传，由人工执行）。
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# 模块 → 智能体ID + 分类
MODULE_AGENT_MAP = {
    "asset": {"agent_id": "ai_interpret_asset", "category": "generate"},
    "alarm": {"agent_id": "ai_interpret_alarm", "category": "generate"},
    "event": {"agent_id": "ai_interpret_event", "category": "generate"},
    "vuln": {"agent_id": "ai_interpret_vuln", "category": "generate"},
    "sandbox": {"agent_id": "ai_interpret_sandbox", "category": "generate"},
}

# 稳定性测试模块 → reliability 指标 key
STABILITY_METRIC_KEY = {
    "alarm": "core_conclusion_stability",       # 核心结论稳定性
    "event": "core_conclusion_stability",       # 核心结论稳定性
    "vuln": "disposal_conclusion_stability",    # 处置结论稳定性
}


def save_v3_json(
    agent_id: str,
    run_id: str,
    model: str,
    data: dict,
    server: str = "http://localhost:8080",
    suffix: str = "",
) -> str:
    """保存 v3 JSON 文件并打印 curl 上传命令（不自动上传）

    Args:
        agent_id: 智能体标识
        run_id: 批次标识
        model: 大模型型号名
        data: v3 JSON 数据（不含 model 字段）
        server: 服务地址（用于打印 curl 命令）
        suffix: 文件名后缀（区分同一 agent 的不同维度文件，如 _accuracy/_reliability）

    Returns:
        保存的文件路径
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    filename = f"{agent_id}{suffix}_v3.json"
    filepath = os.path.join(base_dir, "outputs", filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*60}")
    print(f"💾 已生成 v3 JSON 文件: {filepath}")
    print(f"{'='*60}")
    print(f"📤 上传命令（复制执行）：")
    print(f"")
    print(f"  curl -X POST \"{server}/api/v1/results?agent_id={agent_id}&run_id={run_id}&model={model}\" \\")
    print(f"    -H \"Content-Type: application/json\" \\")
    print(f"    -d @{filepath}")
    print(f"{'='*60}")

    return filepath


def build_interpret_v3_json(agent, module: str, avg_score: float) -> dict:
    """从解读测试结果组装 v3 JSON（accuracy + performance + 样本统计）

    Args:
        agent: AIInterpretAgent 实例（含 results）
        module: 解读模块（alarm/event/asset/vuln/sandbox）
        avg_score: LLM审查均分（content_compliance）

    Returns:
        v3 JSON dict
    """
    info = MODULE_AGENT_MAP[module]
    results = agent.results.get(module, [])

    # 样本统计
    total = len(results)
    valid = [r for r in results if r.success and not r.is_invalid]
    failed = [r for r in results if not r.success]
    invalid = [r for r in results if r.is_invalid]

    # 性能数据（仅有效样本）
    fp_times = [r.first_packet_time for r in valid if r.first_packet_time > 0]
    tr_times = [r.total_response_time for r in valid if r.total_response_time > 0]
    avg_fp = round(sum(fp_times) / len(fp_times), 2) if fp_times else 0
    avg_tr = round(sum(tr_times) / len(tr_times), 2) if tr_times else 0

    # 失败/失效样本
    failed_samples = [{"sample_id": r.input_id, "reason": r.error or "AI调用失败"} for r in failed]
    invalid_samples = [{"sample_id": r.input_id, "reason": r.error or "业务数据不存在"} for r in invalid]

    dimensions = {
        "accuracy": {
            "content_compliance": round(avg_score, 1)
        }
    }
    if avg_fp > 0 or avg_tr > 0:
        perf = {}
        if avg_fp > 0:
            perf["first_packet_time"] = avg_fp
        if avg_tr > 0:
            perf["avg_response_time"] = avg_tr
        dimensions["performance"] = perf

    return {
        "category": info["category"],
        "total_samples": total,
        "valid_samples": len(valid),
        "dimensions": dimensions,
        "failed_samples": failed_samples,
        "invalid_samples": invalid_samples
    }


def build_stability_v3_json(module: str, stability_result: dict) -> dict:
    """从稳定性测试结果组装 v3 JSON（reliability）

    Args:
        module: 稳定性模块（alarm/event/vuln）
        stability_result: run_stability_test 的返回值（含 pass_count/fail_count/results）

    Returns:
        v3 JSON dict
    """
    info = MODULE_AGENT_MAP[module]
    metric_key = STABILITY_METRIC_KEY.get(module, "core_conclusion_stability")

    pass_count = stability_result.get("pass_count", 0)
    fail_count = stability_result.get("fail_count", 0)
    error_count = stability_result.get("error_count", 0)

    # 有效样本（参与结论对比的）= pass + fail
    valid_count = pass_count + fail_count
    total_count = valid_count + error_count

    # 稳定性通过率 = pass / (pass + fail)
    stability_rate = round(pass_count / valid_count, 4) if valid_count > 0 else 0

    # 失败样本（结论不一致 + 结论缺失），AI平台异常的样本不计入失败
    failed_samples = []
    results = stability_result.get("results", [])
    for r in results:
        if not r.get("stability_passed", True) and not r.get("is_ai_platform_error", False):
            is_missing = r.get("is_missing_conclusion", False)
            failed_samples.append({
                "sample_id": str(r.get("id", "")),
                "reason": "结论缺失" if is_missing else "结论不一致"
            })

    return {
        "category": info["category"],
        "total_samples": total_count,
        "valid_samples": valid_count,
        "dimensions": {
            "reliability": {
                metric_key: stability_rate
            }
        },
        "failed_samples": failed_samples,
        "invalid_samples": []
    }

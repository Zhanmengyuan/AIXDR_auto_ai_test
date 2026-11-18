"""
跑解读类智能体测试 + 组装 v3 JSON + 上传到统一测试框架接口

完整流程：
  1. 跑解读测试（调内网AI接口）
  2. 跑LLM审查（拿"整体内容合规性"分数）
  3. 组装 v3 汇总JSON
  4. 上传到 HTTP 接口

使用方式：
    python scripts/run_interpret_and_upload.py --module alarm --model 190
    python scripts/run_interpret_and_upload.py --module event --model 190 --server http://localhost:8080
"""
import sys
import os
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from agents import AIInterpretAgent
from agents.test_case_manager import TestCase
from core.config_loader import ConfigLoader
from core.auditors.auto_audit_manager import AutoAuditManager


# 解读模块 → 智能体ID + 分类
MODULE_AGENT_MAP = {
    "asset": {"agent_id": "ai_interpret_asset", "category": "generate"},
    "alarm": {"agent_id": "ai_interpret_alarm", "category": "generate"},
    "event": {"agent_id": "ai_interpret_event", "category": "generate"},
    "vuln": {"agent_id": "ai_interpret_vuln", "category": "generate"},
    "sandbox": {"agent_id": "ai_interpret_sandbox", "category": "generate"},
}

# 模块 → config 属性名 + 输入字段名
MODULE_CONFIG_MAP = {
    "asset": {"config_attr": "test_assets", "id_field": "asset_id"},
    "alarm": {"config_attr": "test_alarms", "id_field": "alarm_id"},
    "event": {"config_attr": "test_events", "id_field": "event_id"},
    "vuln": {"config_attr": "test_vulns", "id_field": "vuln_id"},
    "sandbox": {"config_attr": "test_sandboxes", "id_field": "sandbox_id"},
}


def build_test_cases(module: str, ids: list, id_field: str):
    """构造测试用例"""
    test_cases = []
    for idx, id_val in enumerate(ids):
        test_cases.append(TestCase(
            case_id=f"{module}_auto_{idx+1:02d}",
            module=module,
            input_data={id_field: str(id_val)},
            expected_output={},
            description=f"{module}解读测试 - {id_val}",
            tags=["automated", module]
        ))
    return test_cases


def run_interpret(module: str) -> AIInterpretAgent:
    """跑解读测试，返回 agent（含 results）"""
    print(f"\n{'='*60}")
    print(f"🚀 跑 {module} 解读测试")
    print(f"{'='*60}")

    agent = AIInterpretAgent()
    config = ConfigLoader()

    cfg = MODULE_CONFIG_MAP[module]
    ids = getattr(config, cfg["config_attr"], [])
    if not ids:
        print(f"⚠️ 配置中没有 {module} 测试ID")
        return agent

    test_cases = build_test_cases(module, ids, cfg["id_field"])
    print(f"📋 共 {len(test_cases)} 个测试用例")

    results = agent.run_module_tests(module, test_cases)
    if results:
        agent._generate_comprehensive_report()

    return agent


def run_audit(module: str, run_date: str) -> dict:
    """跑LLM审查，返回 summary（含 avg_score）"""
    print(f"\n{'='*60}")
    print(f"🔍 跑 {module} 解读报告的LLM审查")
    print(f"{'='*60}")

    mgr = AutoAuditManager(run_date=run_date)
    result = mgr.batch_audit(module, date_str=run_date)
    return result["summary"]


def build_v3_json(agent: AIInterpretAgent, module: str, model: str, avg_score: float) -> dict:
    """从解读测试结果组装 v3 汇总JSON"""
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
    avg_fp = sum(fp_times) / len(fp_times) if fp_times else 0
    avg_tr = sum(tr_times) / len(tr_times) if tr_times else 0

    # 失败/失效样本
    failed_samples = [{"sample_id": r.input_id, "reason": r.error or "AI调用失败"} for r in failed]
    invalid_samples = [{"sample_id": r.input_id, "reason": r.error or "业务数据不存在"} for r in invalid]

    # 组装 v3 JSON
    v3 = {
        "category": info["category"],
        "total_samples": total,
        "valid_samples": len(valid),
        "dimensions": {
            "accuracy": {
                "content_compliance": round(avg_score, 1)  # LLM审查均分（0~100）
            },
            "performance": {
                "first_packet_time": round(avg_fp, 2),
                "avg_response_time": round(avg_tr, 2)
            }
        },
        "failed_samples": failed_samples,
        "invalid_samples": invalid_samples
    }

    return v3


def upload(agent_id: str, run_id: str, model: str, data: dict, server: str) -> bool:
    """上传 v3 JSON 到接口"""
    print(f"\n{'='*60}")
    print(f"📤 上传到接口")
    print(f"{'='*60}")
    print(f"  接口: {server}/api/v1/results")
    print(f"  agent_id: {agent_id}")
    print(f"  run_id: {run_id}")
    print(f"  model: {model}")

    try:
        resp = requests.post(
            f"{server}/api/v1/results",
            params={"agent_id": agent_id, "run_id": run_id, "model": model},
            json=data,
            timeout=30
        )
        print(f"  响应状态码: {resp.status_code}")
        print(f"  响应内容: {resp.json()}")

        if resp.status_code == 200 and resp.json().get("status") == "ok":
            print(f"✅ 上传成功")
            return True
        else:
            print(f"❌ 上传失败")
            return False
    except Exception as e:
        print(f"❌ 上传异常: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="跑解读类智能体测试并上传")
    parser.add_argument("--module", required=True, choices=["asset", "alarm", "event", "vuln", "sandbox"], help="解读模块")
    parser.add_argument("--model", default="190", help="大模型标识：180/190/cloud/third_party")
    parser.add_argument("--server", default="http://localhost:8080", help="服务地址")
    parser.add_argument("--run-id", default=None, help="批次ID（默认用解读的run_date）")
    parser.add_argument("--skip-upload", action="store_true", help="只生成JSON不上传")
    args = parser.parse_args()

    module = args.module
    model = args.model
    server = args.server

    # 1. 跑解读测试
    agent = run_interpret(module)
    if not agent.results.get(module):
        print(f"❌ 解读测试没有产出结果，终止")
        return

    # 2. 跑LLM审查拿 avg_score
    run_date = agent.run_date
    audit_summary = run_audit(module, run_date)
    avg_score = audit_summary.get("avg_score", 0)
    print(f"\n📊 LLM审查均分（content_compliance）: {avg_score}分")

    # 3. 组装 v3 JSON
    v3 = build_v3_json(agent, module, model, avg_score)
    print(f"\n{'='*60}")
    print(f"📦 组装的 v3 JSON:")
    print(f"{'='*60}")
    print(json.dumps(v3, ensure_ascii=False, indent=2))

    # 4. 上传（结果由服务端存储到 outputs/results/{run_id}/{agent_id}.json，本地不再额外保存）
    agent_id = MODULE_AGENT_MAP[module]["agent_id"]
    run_id = args.run_id or run_date
    if args.skip_upload:
        print(f"⏭️ 跳过上传（--skip-upload）")
    else:
        upload(agent_id, run_id, model, v3, server)


if __name__ == "__main__":
    main()

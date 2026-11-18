"""
模拟 Push 模式外部智能体的测试结果

模拟一个"安全Copilot"智能体，按 StandardResult 契约格式生成测试结果，
用于 Demo 展示 Push 接入模式的效果。

真实场景下，外部团队会按契约文档自行实现适配器，
将他们智能体的测试结果转换为 StandardResult 后 POST 给我们的接收端。
"""
import json
import os
import random
from datetime import datetime
from core.contract import StandardResult, Metric, STATUS_VALID


MOCK_AGENT_ID = "xdr_copilot"
MOCK_AGENT_NAME = "安全Copilot"
MOCK_TEAM = "平台组"

MOCK_SAMPLES = [
    "query_001", "query_002", "query_003", "query_004", "query_005",
    "query_006", "query_007", "query_008", "query_009", "query_010",
    "query_011", "query_012", "query_013", "query_014", "query_015",
    "query_016", "query_017", "query_018", "query_019", "query_020",
]


def generate_mock_copilot_results(run_id: str = None) -> list:
    """生成模拟安全Copilot的StandardResult列表

    模拟指标：
    - accuracy: factuality（事实准确性）、citation（引用准确性）
    - performance: response_time（响应时间）
    - compliance: format_compliance（格式规范）
    """
    if not run_id:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = []
    random.seed(42)

    for idx, sample_id in enumerate(MOCK_SAMPLES):
        accuracy_val = random.uniform(0.72, 0.96)
        citation_val = random.uniform(0.68, 0.95)
        response_time = random.uniform(0.8, 3.5)
        format_val = random.uniform(0.80, 1.0)

        metrics = [
            Metric(
                dimension="accuracy",
                key="factuality",
                name_cn="事实准确性",
                value="AI回答内容",
                expected="标准答案",
                accuracy=round(accuracy_val, 3),
                passed=accuracy_val >= 0.85,
                detail={"match_type": "semantic"},
            ),
            Metric(
                dimension="accuracy",
                key="citation",
                name_cn="引用准确性",
                value="引用段落",
                expected="标准引用",
                accuracy=round(citation_val, 3),
                passed=citation_val >= 0.85,
                detail={},
            ),
            Metric(
                dimension="performance",
                key="response_time",
                name_cn="响应时间",
                value=f"{response_time:.2f}s",
                expected="≤3s",
                accuracy=1.0 if response_time <= 3 else 0.5,
                passed=response_time <= 3,
                detail={"time": response_time},
            ),
            Metric(
                dimension="compliance",
                key="format_compliance",
                name_cn="格式规范性",
                value="合规",
                expected="合规",
                accuracy=round(format_val, 3),
                passed=format_val >= 0.85,
                detail={},
            ),
        ]

        sr = StandardResult(
            agent_id=MOCK_AGENT_ID,
            case_id=f"copilot_test_{idx+1:02d}",
            sample_id=sample_id,
            run_id=run_id,
            status=STATUS_VALID,
            first_packet_time=round(response_time, 2),
            total_response_time=round(response_time + random.uniform(2, 8), 2),
            metrics=metrics,
            raw_text=f"[模拟] 安全Copilot对 {sample_id} 的分析结果...",
            error="",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        results.append(sr.to_dict())

    return results


def save_mock_results(output_dir: str = None, run_id: str = None):
    """生成模拟结果并保存为JSON"""
    if not run_id:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not output_dir:
        output_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "outputs", "demo", run_id
        )
    os.makedirs(output_dir, exist_ok=True)

    results = generate_mock_copilot_results(run_id)
    filepath = os.path.join(output_dir, "mock_copilot_results.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"✅ 模拟安全Copilot结果已生成: {filepath}（{len(results)}条）")
    return filepath


if __name__ == "__main__":
    save_mock_results()

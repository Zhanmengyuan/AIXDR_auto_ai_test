"""
生成13个智能体的模拟JSON数据，用于端到端测试框架。
把数据写入 outputs/results/test_v190/ 目录。
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def gen_test_data():
    """生成13个智能体的测试数据"""
    return {
        "waf_dedup": {
            "category": "detect", "model": "190", "total_samples": 600, "valid_samples": 600,
            "dimensions": {
                "accuracy": {"f1_score": {"black_samples": 300, "black_correct": 291, "white_samples": 300, "white_correct": 295}},
                "reliability": {"stability_rate": 1.0},
                "content_quality": {"content_correctness": 0.92},
                "performance": {"avg_response_time": 9.74}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "malfile_detect": {
            "category": "detect", "model": "190", "total_samples": 1000, "valid_samples": 1000,
            "dimensions": {
                "accuracy": {"f1_score": {"black_samples": 500, "black_correct": 448, "white_samples": 500, "white_correct": 499}},
                "reliability": {"stability_rate": 0.94},
                "content_quality": {"format_compliance": 1.0, "content_correctness": 0.9174},
                "performance": {"first_packet_time": 2.01, "avg_response_time": 29.51}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "webshell_detect": {
            "category": "detect", "model": "190", "total_samples": 1000, "valid_samples": 1000,
            "dimensions": {
                "accuracy": {"f1_score": {"black_samples": 500, "black_correct": 486, "white_samples": 500, "white_correct": 497}},
                "reliability": {"repeat_stability": 0.98},
                "content_quality": {"format_compliance": 1.0, "content_correctness": 0.9258},
                "performance": {"first_packet_time": 1.68, "avg_response_time": 31.99}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "phishing_detect": {
            "category": "detect", "model": "190", "total_samples": 1200, "valid_samples": 1200,
            "dimensions": {
                "accuracy": {"f1_score": {"black_samples": 600, "black_correct": 469, "white_samples": 600, "white_correct": 494}},
                "reliability": {"repeat_stability": 0.89},
                "content_quality": {"format_compliance": 1.0, "content_correctness": 0.7671},
                "performance": {"first_packet_time": 1.93, "avg_response_time": 80.78}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "ioc_extract": {
            "category": "detect", "model": "190", "total_samples": 1000, "valid_samples": 1000,
            "dimensions": {
                "accuracy": {"f1_score": {"black_samples": 997, "black_correct": 997, "white_samples": 3, "white_correct": 2}},
                "reliability": {"stability_rate": 1.0},
                "content_quality": {"content_correctness": 1.0},
                "performance": {"avg_response_time": 638.07}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "ai_interpret_alarm": {
            "category": "generate", "model": "190", "total_samples": 50, "valid_samples": 47,
            "dimensions": {
                "accuracy": {"content_compliance": 92},
                "reliability": {"core_conclusion_stability": 0.94},
                "content_quality": {"format_compliance": 1.0},
                "performance": {"first_packet_time": 0.2, "avg_response_time": 21.2}
            },
            "failed_samples": [
                {"sample_id": "alarm_03", "reason": "AI调用超时"},
                {"sample_id": "alarm_07", "reason": "大模型连接异常"},
                {"sample_id": "alarm_19", "reason": "无AI响应内容"}
            ],
            "invalid_samples": []
        },
        "ai_interpret_event": {
            "category": "generate", "model": "190", "total_samples": 50, "valid_samples": 48,
            "dimensions": {
                "accuracy": {"content_compliance": 91},
                "reliability": {"core_conclusion_stability": 0.96},
                "content_quality": {"format_compliance": 1.0},
                "performance": {"first_packet_time": 0.2, "avg_response_time": 26.6}
            },
            "failed_samples": [
                {"sample_id": "event_05", "reason": "AI调用超时"},
                {"sample_id": "event_22", "reason": "大模型连接异常"}
            ],
            "invalid_samples": []
        },
        "ai_interpret_asset": {
            "category": "generate", "model": "190", "total_samples": 50, "valid_samples": 49,
            "dimensions": {
                "accuracy": {"content_compliance": 81},
                "content_quality": {"format_compliance": 1.0},
                "performance": {"first_packet_time": 0.3, "avg_response_time": 31.9}
            },
            "failed_samples": [
                {"sample_id": "asset_15", "reason": "AI调用超时"}
            ],
            "invalid_samples": []
        },
        "ai_interpret_vuln": {
            "category": "generate", "model": "190", "total_samples": 50, "valid_samples": 50,
            "dimensions": {
                "accuracy": {"content_compliance": 92},
                "reliability": {"disposal_conclusion_stability": 0.87},
                "content_quality": {"format_compliance": 0.75},
                "performance": {"first_packet_time": 0.3, "avg_response_time": 22.1}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "ai_interpret_sandbox": {
            "category": "generate", "model": "190", "total_samples": 50, "valid_samples": 50,
            "dimensions": {
                "accuracy": {"content_compliance": 72.7},
                "content_quality": {"format_compliance": 1.0, "section_completeness": 1.0},
                "performance": {"first_packet_time": 0.5, "avg_response_time": 51.7}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "text2sql": {
            "category": "query", "model": "190", "total_samples": 400, "valid_samples": 392,
            "dimensions": {
                "accuracy": {"result_accuracy": 0.848},
                "reliability": {"execution_success_rate": 0.98},
                "performance": {"avg_response_time": 18.6}
            },
            "failed_samples": [
                {"sample_id": "query_003", "reason": "SQL执行超时"},
                {"sample_id": "query_017", "reason": "SQL语法错误"},
                {"sample_id": "query_045", "reason": "SQL执行超时"},
                {"sample_id": "query_089", "reason": "SQL语法错误"},
                {"sample_id": "query_102", "reason": "SQL执行超时"},
                {"sample_id": "query_156", "reason": "SQL语法错误"},
                {"sample_id": "query_203", "reason": "SQL执行超时"},
                {"sample_id": "query_288", "reason": "SQL语法错误"}
            ],
            "invalid_samples": []
        },
        "digital_human": {
            "category": "query", "model": "190", "total_samples": 100, "valid_samples": 100,
            "dimensions": {
                "accuracy": {"fixed_answer_accuracy": 0.931},
                "reliability": {"repeat_stability": 0.98},
                "content_quality": {"content_accuracy": 0.70},
                "performance": {"first_packet_time": 1.27, "avg_response_time": 23.37}
            },
            "failed_samples": [], "invalid_samples": []
        },
        "rag_search": {
            "category": "qa", "model": "190", "total_samples": 430, "valid_samples": 430,
            "dimensions": {
                "accuracy": {"answer_correctness": 0.840},
                "content_quality": {"answer_relevancy": 0.834, "context_precision": 0.857, "context_recall": 0.734},
                "performance": {"first_packet_time": 2.04, "avg_response_time": 18.58}
            },
            "failed_samples": [], "invalid_samples": []
        },
    }


def save_test_data(run_id="test_v190"):
    """生成测试数据并保存到 outputs/results/{run_id}/ 目录"""
    data = gen_test_data()
    run_dir = os.path.join(BASE_DIR, "outputs", "results", run_id)
    os.makedirs(run_dir, exist_ok=True)

    for agent_id, agent_data in data.items():
        filepath = os.path.join(run_dir, f"{agent_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(agent_data, f, ensure_ascii=False, indent=2)

    print(f"✅ 生成 {len(data)} 个智能体测试数据到 {run_dir}")


if __name__ == "__main__":
    save_test_data()

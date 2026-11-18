"""
汇总报告生成器

读取 outputs/results/{run_id}/ 目录下所有JSON，
调评分引擎算分，生成准确性专项HTML报告。
"""
import os
import sys
import json
import glob
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scoring_engine import (
    calculate_f1_from_samples,
    normalize_higher_better,
    normalize_score_based,
    normalize_pass_fail,
    aggregate_dimension_scores,
    calculate_agent_score,
    calculate_rating,
    WEIGHT_PROFILES,
)
from core.validator import ManifestRegistry


def load_results(run_id: str) -> Dict[str, Dict[str, Any]]:
    """读取某批次所有智能体的JSON结果

    返回 {agent_id: data}
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    run_dir = os.path.join(base_dir, "outputs", "results", run_id)
    if not os.path.exists(run_dir):
        print(f"❌ 批次目录不存在: {run_dir}")
        return {}

    results = {}
    for json_path in glob.glob(os.path.join(run_dir, "*.json")):
        agent_id = os.path.basename(json_path).replace(".json", "")
        with open(json_path, "r", encoding="utf-8") as f:
            results[agent_id] = json.load(f)
    return results


def process_agent(agent_id: str, data: Dict[str, Any], registry: ManifestRegistry) -> Dict[str, Any]:
    """处理单个智能体：从原始数据计算维度分和综合分

    返回:
    {
        "agent_id": ...,
        "name": ...,
        "category": ...,
        "model": ...,
        "total_samples": ...,
        "valid_samples": ...,
        "dimension_scores": {dim: score},
        "agent_score": float,
        "rating": str,
        "failed_samples": [...],
        "invalid_samples": [...],
        "metric_details": {dim: {key: {raw, score, detail}}},
        "performance_raw": {key: value},  # 性能原始值，不算分
    }
    """
    manifest = registry.get_manifest(agent_id)
    category = data.get("category", "generate")
    model = data.get("model", "unknown")
    total = data.get("total_samples", 0)
    valid = data.get("valid_samples", 0)
    dimensions = data.get("dimensions", {})

    metric_details = {}
    dimension_scores = {}
    performance_raw = {}

    for dim_name, dim_data in dimensions.items():
        # v3最简结构：{key: value}
        metrics_in_dim = dim_data
        if "metrics" in dim_data:
            metrics_in_dim = dim_data["metrics"]

        if isinstance(metrics_in_dim, list):
            # 列表形式：[{key, value, ...}]
            for m in metrics_in_dim:
                key = m.get("key", "")
                value = m.get("value")
                _process_metric(key, value, dim_name, manifest, metric_details, dimension_scores, performance_raw)
        elif isinstance(metrics_in_dim, dict):
            # v3最简结构：{key: value}
            for key, value in metrics_in_dim.items():
                _process_metric(key, value, dim_name, manifest, metric_details, dimension_scores, performance_raw)

    # 维度归并：list → 均值
    dim_scores_flat = {}
    for dim, scores in dimension_scores.items():
        if isinstance(scores, list) and scores:
            dim_scores_flat[dim] = sum(scores) / len(scores)
        elif isinstance(scores, (int, float)):
            dim_scores_flat[dim] = scores

    # 算综合分
    agent_score, _ = calculate_agent_score(dim_scores_flat, category)
    rating = calculate_rating(agent_score, dim_scores_flat)

    return {
        "agent_id": agent_id,
        "name": manifest.name if manifest else agent_id,
        "category": category,
        "model": model,
        "total_samples": total,
        "valid_samples": valid,
        "dimension_scores": dimension_scores,
        "agent_score": agent_score,
        "rating": rating,
        "failed_samples": data.get("failed_samples", []),
        "invalid_samples": data.get("invalid_samples", []),
        "metric_details": metric_details,
        "performance_raw": performance_raw,
    }


def _process_metric(key, value, dim_name, manifest, metric_details, dimension_scores, performance_raw):
    """处理单个指标"""
    metric = manifest.get_metric_by_key(key) if manifest else None
    if metric is None:
        return

    metric_type = metric.get("type", "higher_better")

    if metric_type == "f1":
        # F1：从黑白样本数量计算
        if isinstance(value, dict):
            result = calculate_f1_from_samples(
                value.get("black_samples", 0),
                value.get("black_correct", 0),
                value.get("white_samples", 0),
                value.get("white_correct", 0),
            )
            score = normalize_higher_better(result["f1_score"], 1.0, 0.0)
            metric_details.setdefault(dim_name, {})[key] = {
                "raw_value": value,
                "score": score,
                "detail": result,
            }
            dimension_scores.setdefault(dim_name, []).append(score)

    elif metric_type == "display_only":
        # 性能：只展示，不算分
        performance_raw[key] = value

    elif metric_type == "higher_better":
        score = normalize_higher_better(value, 1.0, 0.0)
        metric_details.setdefault(dim_name, {})[key] = {"raw_value": value, "score": score}
        dimension_scores.setdefault(dim_name, []).append(score)

    elif metric_type == "score_based":
        score = normalize_score_based(value, 100)
        metric_details.setdefault(dim_name, {})[key] = {"raw_value": value, "score": score}
        dimension_scores.setdefault(dim_name, []).append(score)

    elif metric_type == "pass_fail":
        score = normalize_pass_fail(int(value * 1000), 1000) if isinstance(value, float) else value * 100
        metric_details.setdefault(dim_name, {})[key] = {"raw_value": value, "score": score}
        dimension_scores.setdefault(dim_name, []).append(score)


def calculate_overall_scores(agent_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """计算整体综合分（类间等权法）"""
    category_agents = defaultdict(list)
    for agent_id, result in agent_results.items():
        category_agents[result["category"]].append(result["agent_score"])

    category_means = {}
    for cat, scores in category_agents.items():
        if scores:
            category_means[cat] = round(sum(scores) / len(scores), 1)

    if category_means:
        overall = round(sum(category_means.values()) / len(category_means), 1)
    else:
        overall = 0.0

    return {"overall": overall, "category_means": category_means}


def generate_html_report(
    agent_results: Dict[str, Dict[str, Any]],
    run_id: str,
    overall: Dict[str, Any],
) -> str:
    """生成HTML报告"""
    from core.reporter.report_templates import (
        build_accuracy_report_html,
    )
    return build_accuracy_report_html(agent_results, run_id, overall)

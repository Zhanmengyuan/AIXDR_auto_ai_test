"""
聚合模块 (Aggregator)

按指标类型把同一 run_id + agent_id 的多批上传结果聚合成一份。
聚合规则满足结合律与交换律：同一批样本无论拆成几批、按什么顺序上传，结果一致。

聚合规则：
- total_samples / valid_samples：跨批累加
- f1 类型指标：黑白样本计数逐字段累加（F1 由评分引擎按合并后的计数重算）
- 标量指标（score_based / higher_better / pass_fail / display_only）：按 valid_samples 加权平均
- failed_samples / invalid_samples：按 sample_id 去重并集

注意：标量加权平均要求每批的标量是"该批自身的真实均值"。若每批先四舍五入再加权，
结果在小数位可能有与分片数相关的微小漂移；如需精确一致，应让每批上传 sum+count。
"""
from typing import Any, Dict, List


def merge_result(existing: Dict[str, Any], new: Dict[str, Any], manifest) -> Dict[str, Any]:
    """合并已累计结果 existing 与新一批 new，返回合并后的完整结果。

    Args:
        existing: 已累计的结果（首次上传时不存在，直接写 new 即可）
        new: 新一批上传的数据（含 model / _uploaded_at 等，合并后以 new 为准）
        manifest: AgentManifest 实例（用于查每个指标的 type）

    Returns:
        合并后的结果 dict
    """
    merged = dict(new)

    # 样本数：累加
    merged["total_samples"] = existing.get("total_samples", 0) + new.get("total_samples", 0)
    merged["valid_samples"] = existing.get("valid_samples", 0) + new.get("valid_samples", 0)

    # 各维度指标：按类型聚合
    merged["dimensions"] = _merge_dimensions(
        existing.get("dimensions", {}),
        new.get("dimensions", {}),
        manifest,
        existing.get("valid_samples", 0),
        new.get("valid_samples", 0),
    )

    # 失败/失效样本：并集去重
    merged["failed_samples"] = _union_samples(existing.get("failed_samples"), new.get("failed_samples"))
    merged["invalid_samples"] = _union_samples(existing.get("invalid_samples"), new.get("invalid_samples"))

    return merged


def _merge_dimensions(existing_dims, new_dims, manifest, existing_weight, new_weight):
    merged = {}
    for dim_name in set(existing_dims) | set(new_dims):
        merged[dim_name] = _merge_dim(
            existing_dims.get(dim_name),
            new_dims.get(dim_name),
            manifest,
            existing_weight,
            new_weight,
        )
    return merged


def _merge_dim(existing_dim, new_dim, manifest, existing_weight, new_weight):
    # 一侧缺失：直接取另一侧
    if existing_dim is None:
        return new_dim
    if new_dim is None:
        return existing_dim

    # 非 v3 最简结构（如带 metrics 列表的旧格式）：退化为 last-write-wins，不聚合
    if not isinstance(existing_dim, dict) or not isinstance(new_dim, dict):
        return new_dim
    if "metrics" in existing_dim or "metrics" in new_dim:
        merged = dict(existing_dim)
        merged.update(new_dim)
        return merged

    merged = {}
    for key in set(existing_dim) | set(new_dim):
        existing_val = existing_dim.get(key)
        new_val = new_dim.get(key)
        if existing_val is None:
            merged[key] = new_val
        elif new_val is None:
            merged[key] = existing_val
        else:
            metric = manifest.get_metric_by_key(key) if manifest else None
            merged[key] = _merge_metric_value(existing_val, new_val, metric, existing_weight, new_weight)
    return merged


def _merge_metric_value(existing_val, new_val, metric, existing_weight, new_weight):
    metric_type = (metric or {}).get("type")

    # f1：计数对象，逐字段累加
    if metric_type == "f1" and isinstance(existing_val, dict) and isinstance(new_val, dict):
        return _sum_counts(existing_val, new_val)

    # 标量：按 valid_samples 加权平均
    total_weight = existing_weight + new_weight
    if total_weight <= 0:
        return (existing_val + new_val) / 2.0
    return (existing_val * existing_weight + new_val * new_weight) / total_weight


def _sum_counts(a: Dict, b: Dict) -> Dict:
    result = {}
    for k in set(a) | set(b):
        result[k] = a.get(k, 0) + b.get(k, 0)
    return result


def _union_samples(existing: List, new: List) -> List:
    """按 sample_id 去重合并两个样本列表（existing 在前，new 追加）。"""
    result = list(existing) if isinstance(existing, list) else []
    seen = {s.get("sample_id") for s in result if isinstance(s, dict) and s.get("sample_id")}
    for s in (new or []):
        if isinstance(s, dict) and s.get("sample_id") and s.get("sample_id") not in seen:
            result.append(s)
            seen.add(s.get("sample_id"))
    return result

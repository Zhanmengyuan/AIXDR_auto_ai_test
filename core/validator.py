"""
校验模块 (Validator)

读取13个声明文件，校验各团队上传的JSON是否符合声明文件的指标定义。
"""
import os
import glob
import yaml
from typing import Any, Dict, List, Tuple, Optional


class AgentManifest:
    """单个智能体的声明文件"""

    def __init__(self, yaml_path: str):
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.agent_id = data["agent"]["id"]
        self.name = data["agent"]["name"]
        self.category = data["agent"]["category"]
        self.metrics: List[Dict[str, Any]] = data.get("metrics", [])

    def get_metric_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        for m in self.metrics:
            if m["key"] == key:
                return m
        return None

    def get_metrics_by_dimension(self, dimension: str) -> List[Dict[str, Any]]:
        return [m for m in self.metrics if m["dimension"] == dimension]


class ManifestRegistry:
    """声明文件注册表，加载所有声明文件"""

    _instance = None

    def __init__(self):
        self._manifests: Dict[str, AgentManifest] = {}
        self._load_all()

    @classmethod
    def get_instance(cls) -> "ManifestRegistry":
        if cls._instance is None:
            cls._instance = ManifestRegistry()
        return cls._instance

    def _load_all(self):
        agents_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config", "agents"
        )
        for yaml_path in glob.glob(os.path.join(agents_dir, "*.yaml")):
            manifest = AgentManifest(yaml_path)
            self._manifests[manifest.agent_id] = manifest

    def get_manifest(self, agent_id: str) -> Optional[AgentManifest]:
        return self._manifests.get(agent_id)

    def list_agents(self) -> List[str]:
        return list(self._manifests.keys())


def validate_result(
    agent_id: str,
    data: Dict[str, Any],
    manifest: AgentManifest,
) -> Tuple[bool, str]:
    """校验上传的JSON是否符合声明文件

    返回 (是否通过, 错误信息)
    """
    # 1. category 校验
    category = data.get("category")
    if not category:
        return False, "缺少 category 字段"
    if category != manifest.category:
        return False, f"category 不匹配：期望 {manifest.category}，实际 {category}"

    # 2. total_samples / valid_samples 校验
    total = data.get("total_samples")
    valid = data.get("valid_samples")
    if total is None:
        return False, "缺少 total_samples 字段"
    if valid is None:
        return False, "缺少 valid_samples 字段"
    if not isinstance(total, int) or total < 0:
        return False, f"total_samples 必须是非负整数，实际：{total}"
    if not isinstance(valid, int) or valid < 0:
        return False, f"valid_samples 必须是非负整数，实际：{valid}"
    if valid > total:
        return False, f"valid_samples({valid}) 不能大于 total_samples({total})"

    # 4. dimensions 校验
    dimensions = data.get("dimensions")
    if not dimensions or not isinstance(dimensions, dict):
        return False, "缺少 dimensions 字段或为空"

    # 5. 逐指标校验
    for dim_name, dim_data in dimensions.items():
        if not isinstance(dim_data, dict):
            return False, f"dimensions.{dim_name} 必须是对象"

        metrics_in_dim = dim_data.get("metrics", dim_data)

        # 如果是 {key: value} 形式（v3最简结构），metrics_in_dim 就是 dim_data 本身
        if "metrics" in dim_data:
            metrics_in_dim = dim_data["metrics"]
            # 如果是列表形式
            if isinstance(metrics_in_dim, list):
                for m in metrics_in_dim:
                    if not isinstance(m, dict):
                        return False, f"dimensions.{dim_name}.metrics 元素必须是对象"
                    key = m.get("key")
                    if not key:
                        return False, f"dimensions.{dim_name}.metrics 元素缺少 key"
                    value = m.get("value")
                    _validate_metric_value(agent_id, dim_name, key, value, manifest)
            continue

        # v3最简结构：{key: value}
        for key, value in metrics_in_dim.items():
            ok, msg = _validate_metric_value(agent_id, dim_name, key, value, manifest)
            if not ok:
                return False, msg

    # 6. 检查声明文件里有但数据里没有的指标（可选，不报错只警告）
    # 这里不强制，因为允许部分参测

    # 7. failed_samples / invalid_samples 校验
    for field in ["failed_samples", "invalid_samples"]:
        samples = data.get(field, [])
        if samples is None:
            samples = []
        if not isinstance(samples, list):
            return False, f"{field} 必须是数组"
        for i, s in enumerate(samples):
            if not isinstance(s, dict):
                return False, f"{field}[{i}] 必须是对象"
            if not s.get("sample_id"):
                return False, f"{field}[{i}] 缺少 sample_id"
            if not s.get("reason"):
                return False, f"{field}[{i}] 缺少 reason"

    return True, ""


def _validate_metric_value(
    agent_id: str,
    dim_name: str,
    key: str,
    value: Any,
    manifest: AgentManifest,
) -> Tuple[bool, str]:
    """校验单个指标的值是否符合声明文件"""

    metric = manifest.get_metric_by_key(key)
    if metric is None:
        return False, f"dimensions.{dim_name}.{key} 不在 {agent_id} 的声明文件中"

    # 声明的维度必须一致
    if metric["dimension"] != dim_name:
        return False, f"dimensions.{dim_name}.{key} 维度不匹配：声明为 {metric['dimension']}，实际为 {dim_name}"

    metric_type = metric.get("type", "higher_better")
    required_fields = metric.get("required_fields", [])

    # F1 类型：值必须是对象，包含4个黑白样本字段
    if metric_type == "f1":
        if not isinstance(value, dict):
            return False, f"dimensions.{dim_name}.{key} 必须是对象（含黑白样本数量）"
        for rf in required_fields:
            if rf not in value:
                return False, f"dimensions.{dim_name}.{key} 缺少 {rf} 字段"
            if not isinstance(value[rf], int) or value[rf] < 0:
                return False, f"dimensions.{dim_name}.{key}.{rf} 必须是非负整数"
        # black_correct 不能超过 black_samples
        bs = value.get("black_samples", 0)
        bc = value.get("black_correct", 0)
        ws = value.get("white_samples", 0)
        wc = value.get("white_correct", 0)
        if bc > bs:
            return False, f"dimensions.{dim_name}.{key}.black_correct({bc}) 不能超过 black_samples({bs})"
        if wc > ws:
            return False, f"dimensions.{dim_name}.{key}.white_correct({wc}) 不能超过 white_samples({ws})"
        return True, ""

    # display_only 类型：值必须是数字
    if metric_type == "display_only":
        if not isinstance(value, (int, float)):
            return False, f"dimensions.{dim_name}.{key} 必须是数字"
        return True, ""

    # higher_better / pass_fail / score_based：值必须是数字
    if not isinstance(value, (int, float)):
        return False, f"dimensions.{dim_name}.{key} 必须是数字"

    # score_based 类型：值应该是0~100
    if metric_type == "score_based":
        if value < 0 or value > 100:
            return False, f"dimensions.{dim_name}.{key} score_based类型值应在0~100，实际：{value}"

    # higher_better / pass_fail：值应该是0~1
    if metric_type in ("higher_better", "pass_fail"):
        if value < 0 or value > 1:
            return False, f"dimensions.{dim_name}.{key} {metric_type}类型值应在0~1，实际：{value}"

    return True, ""

"""
聚合逻辑单测

验证核心性质：同一批样本无论拆成 2 批还是 5 批（或任意顺序），聚合结果一致，
且各指标类型（样本数累加 / f1 计数累加 / 标量加权平均 / 样本并集）都正确。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aggregator import merge_result


class FakeManifest:
    METRICS = {
        "f1_score": {"type": "f1"},
        "content_compliance": {"type": "score_based"},
        "first_packet_time": {"type": "display_only"},
        "core_conclusion_stability": {"type": "pass_fail"},
    }

    def get_metric_by_key(self, key):
        return self.METRICS.get(key)


def _batch(total, valid, black, black_correct, cc, fp, failed=None, invalid=None):
    return {
        "category": "detect",
        "total_samples": total,
        "valid_samples": valid,
        "dimensions": {
            "accuracy": {
                "f1_score": {
                    "black_samples": black,
                    "black_correct": black_correct,
                    "white_samples": 0,
                    "white_correct": 0,
                },
                "content_compliance": cc,
            },
            "performance": {"first_packet_time": fp},
        },
        "failed_samples": failed or [],
        "invalid_samples": invalid or [],
    }


def _merge_all(batches):
    manifest = FakeManifest()
    result = batches[0]
    for b in batches[1:]:
        result = merge_result(result, b, manifest)
    return result


def test_sample_counts_accumulate():
    r = _merge_all([_batch(250, 250, 250, 240, 90, 1.0), _batch(250, 250, 250, 250, 92, 0.8)])
    assert r["total_samples"] == 500
    assert r["valid_samples"] == 500


def test_f1_counts_sum():
    r = _merge_all([_batch(250, 250, 250, 240, 90, 1.0), _batch(250, 250, 250, 250, 92, 0.8)])
    f1 = r["dimensions"]["accuracy"]["f1_score"]
    assert f1["black_samples"] == 500
    assert f1["black_correct"] == 490


def test_scalar_weighted_average():
    r = _merge_all([_batch(250, 250, 250, 240, 90, 1.0), _batch(250, 250, 250, 250, 92, 0.8)])
    assert r["dimensions"]["accuracy"]["content_compliance"] == 91.0
    assert r["dimensions"]["performance"]["first_packet_time"] == 0.9


def test_failed_samples_union_dedup():
    a = _batch(250, 250, 250, 240, 90, 1.0, failed=[{"sample_id": "s1", "reason": "x"}])
    b = _batch(250, 250, 250, 240, 90, 1.0, failed=[{"sample_id": "s1", "reason": "x"}, {"sample_id": "s2", "reason": "y"}])
    r = _merge_all([a, b])
    assert [s["sample_id"] for s in r["failed_samples"]] == ["s1", "s2"]


def test_two_batches_equals_five_batches():
    """核心性质：500 样本拆 2 批 vs 拆 5 批，聚合结果完全一致。"""
    two = _merge_all([
        _batch(250, 250, 250, 240, 90, 1.0),
        _batch(250, 250, 250, 250, 92, 0.8),
    ])
    five = _merge_all([
        _batch(100, 100, 100, 98, 88, 1.0),
        _batch(100, 100, 100, 98, 90, 0.8),
        _batch(100, 100, 100, 98, 92, 0.9),
        _batch(100, 100, 100, 98, 94, 0.9),
        _batch(100, 100, 100, 98, 91, 0.9),
    ])
    assert two["total_samples"] == five["total_samples"] == 500
    assert two["valid_samples"] == five["valid_samples"] == 500
    assert two["dimensions"]["accuracy"]["f1_score"] == five["dimensions"]["accuracy"]["f1_score"]
    assert two["dimensions"]["accuracy"]["content_compliance"] == five["dimensions"]["accuracy"]["content_compliance"] == 91.0
    assert two["dimensions"]["performance"]["first_packet_time"] == five["dimensions"]["performance"]["first_packet_time"] == 0.9


def test_order_independent():
    """上传顺序无关：先传后传结果一致。"""
    a = _batch(250, 250, 250, 240, 90, 1.0)
    b = _batch(250, 250, 250, 250, 92, 0.8)
    m = FakeManifest()
    assert merge_result(a, b, m)["dimensions"] == merge_result(b, a, m)["dimensions"]
    assert merge_result(a, b, m)["total_samples"] == merge_result(b, a, m)["total_samples"]


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])

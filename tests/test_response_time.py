"""
响应时间测量脚本（多资产批量）
===============================

测量AI接口的首包响应时间和平均响应时间

抽样规则：从配置文件 test_assets 中随机抽取指定数量（默认10个）不同资产
计算方式：对抽样资产分别测量响应时间，计算平均值

输入：配置文件中的 test_assets 列表
输出：宏平均首包时间、宏平均总响应时间

使用方式：
  python tests/test_response_time.py                    # 随机抽样10个资产
  python tests/test_response_time.py --count 20          # 随机抽样20个资产
  python tests/test_response_time.py --seed 42          # 指定随机种子复现
  python tests/test_response_time.py --assets "id1,id2" # 指定资产ID列表
"""
import os
import sys
import argparse
import json
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.config_loader import ConfigLoader
from core.calculators import ResponseTimeCalculator


def get_asset_pool_from_config(config: ConfigLoader) -> list:
    """从配置文件获取资产池

    Args:
        config: 配置加载器

    Returns:
        资产ID列表
    """
    return config.test_assets


def sample_assets(asset_pool: list, count: int) -> list:
    """随机抽样资产

    Args:
        asset_pool: 资产池
        count: 抽样数量

    Returns:
        抽样的资产ID列表
    """
    unique_assets = list(set(asset_pool))

    if len(unique_assets) <= count:
        print(f"资产池中只有 {len(unique_assets)} 个资产，全部使用")
        return unique_assets

    sampled = random.sample(unique_assets, count)
    return sampled


def main():
    parser = argparse.ArgumentParser(description='AI接口响应时间测量')
    parser.add_argument('--assets', type=str, help='资产ID列表，逗号分隔（优先使用）')
    parser.add_argument('--count', type=int, default=10, help='抽样数量（默认10）')
    parser.add_argument('--seed', type=int, default=None, help='随机种子（用于复现）')
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f"随机种子: {args.seed}")

    config = ConfigLoader()

    if args.assets:
        asset_ids = [a.strip() for a in args.assets.split(',')]
        print(f"使用命令行指定的 {len(asset_ids)} 个资产ID")
    else:
        asset_pool = get_asset_pool_from_config(config)
        asset_ids = sample_assets(asset_pool, args.count)
        print(f"从配置文件随机抽样 {len(asset_ids)} 个资产")

    print("\n" + "=" * 60)
    print("⏱️  AI接口响应时间测量")
    print("=" * 60)
    print(f"📋 测量资产数量: {len(asset_ids)}")
    print(f"📋 资产列表: {asset_ids}")
    print("=" * 60)

    calculator = ResponseTimeCalculator(config)

    print("\n开始测量...")
    result = calculator.measure_multiple_assets(asset_ids)

    fp_metric = calculator.calculate_first_packet_metric(result)
    avg_metric = calculator.calculate_avg_time_metric(result)

    print("\n" + "=" * 60)
    print("📊 测量结果")
    print("=" * 60)
    print(f"成功测量: {result['successful_count']}/{result['asset_count']}")
    print(f"平均首包时间: {result['avg_first_packet_time']:.2f}秒")
    print(f"平均总响应时间: {result['avg_total_time']:.2f}秒")
    print("-" * 60)
    print(f"首包响应时间得分: {fp_metric.score:.1f}/{fp_metric.max_score} (准确率: {fp_metric.accuracy*100:.1f}%)")
    print(f"平均响应时间得分: {avg_metric.score:.1f}/{avg_metric.max_score} (准确率: {avg_metric.accuracy*100:.1f}%)")
    print("=" * 60)

    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    result_file = os.path.join(output_dir, "response_time_result.json")

    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump({
            "result": result,
            "first_packet_metric": fp_metric.to_dict(),
            "avg_time_metric": avg_metric.to_dict()
        }, f, ensure_ascii=False, indent=2)

    print(f"\n📄 结果已保存: {result_file}")


if __name__ == "__main__":
    main()

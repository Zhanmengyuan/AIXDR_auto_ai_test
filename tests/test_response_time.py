"""
响应时间测量脚本
测量AI接口的首包响应时间和平均响应时间
抽样10个不同资产进行测量
"""
import os
import sys
import argparse
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.config_loader import ConfigLoader
from core.calculators import ResponseTimeCalculator


def main():
    parser = argparse.ArgumentParser(description='AI接口响应时间测量')
    parser.add_argument('--assets', type=str, help='资产ID列表，逗号分隔')
    parser.add_argument('--count', type=int, default=10, help='抽样数量（默认10）')
    args = parser.parse_args()

    config = ConfigLoader()

    if args.assets:
        asset_ids = [a.strip() for a in args.assets.split(',')]
    else:
        asset_ids = config.test_assets[:args.count]

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

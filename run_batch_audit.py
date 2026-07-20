"""
批量审查所有解读报告，生成综合HTML总结报告
"""
import sys
sys.path.insert(0, '.')
from core.auditors.auto_audit_manager import AutoAuditManager


def main():
    from datetime import datetime
    run_date = datetime.now().strftime('%Y%m%d_%H%M%S')
    mgr = AutoAuditManager(run_date=run_date)

    all_results = {}
    for report_type in ['asset', 'alarm', 'event', 'vuln']:
        print(f"\n{'='*70}")
        print(f"开始批量审查: {report_type}")
        print(f"{'='*70}")
        result = mgr.batch_audit(report_type)
        all_results[report_type] = result
        summary = result['summary']
        print(f"  总报告: {summary['total']}, 成功: {summary['success_count']}, 失败: {summary['failed_count']}, 平均分: {summary['avg_score']}")

    # 生成综合HTML报告
    html_path = mgr.generate_comprehensive_html()
    if html_path:
        print(f"\nHTML报告: {html_path}")

    # 总体统计
    print(f"\n总体统计:")
    for rt, result in all_results.items():
        s = result['summary']
        print(f"  {mgr.REPORT_TYPE_NAME_MAP[rt]}: {s['total']}份, 成功{s['success_count']}, 失败{s['failed_count']}, 均分{s['avg_score']}")

    print("\n全部审查完成！")


if __name__ == '__main__':
    main()

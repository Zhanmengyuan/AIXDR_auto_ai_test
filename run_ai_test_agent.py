"""
AI 解读自动化测试智能体运行脚本
支持单模块或全模块测试
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(__file__))
from agents import AIInterpretAgent, TestCaseManager


def run_batch_audit_after_interpret(modules: list = None, run_date: str = None, agent=None):
    """解读完成后自动触发批量审查，完成后发飞书通知（含解读指标+审查结果）

    Args:
        modules: 本次解读的模块列表
        run_date: 本次解读的时间戳目录
        agent: AIInterpretAgent实例，用于提取解读指标
    """
    import time
    start_time = time.time()

    if modules is None:
        modules = ['asset', 'alert', 'event', 'vuln']

    # 提取解读各模块指标（从 agent.results）
    interpret_lines = []
    total_valid = total_failed = total_invalid = 0
    all_fp_times = []
    all_tr_times = []
    if agent and hasattr(agent, 'results') and agent.results:
        module_names_cn = {'asset': '资产解读', 'alert': '告警解读', 'event': '事件解读', 'vuln': '漏洞解读'}
        metric_labels = {
            'chapter_structure_completeness': '结构完整率',
            'risk_level_accuracy': '风险等级',
            'threat_determination_accuracy': '威胁定性',
            'attack_result_accuracy': '攻击结果',
            'dynamic_structure_completeness': '动态结构',
        }
        for mod_key in modules:
            mod_results = agent.results.get(mod_key)
            if not mod_results:
                continue
            name = module_names_cn.get(mod_key, mod_key)
            valid = sum(1 for r in mod_results if r.success and not r.is_invalid)
            failed = sum(1 for r in mod_results if not r.success)
            invalid = sum(1 for r in mod_results if r.is_invalid)
            total_valid += valid; total_failed += failed; total_invalid += invalid

            # 响应时间（仅有效样本）
            fp_times = [r.first_packet_time for r in mod_results if r.success and not r.is_invalid]
            tr_times = [r.total_response_time for r in mod_results if r.success and not r.is_invalid]
            avg_fp = sum(fp_times)/len(fp_times) if fp_times else 0
            avg_tr = sum(tr_times)/len(tr_times) if tr_times else 0
            all_fp_times.extend(fp_times)
            all_tr_times.extend(tr_times)

            # 指标准确率
            stats = agent._calculate_multi_sample_stats(mod_key, mod_results)
            acc_str = ""
            if stats.get('avg_accuracies'):
                acc_parts = []
                for mk, mv in stats['avg_accuracies'].items():
                    label = metric_labels.get(mk, mk)
                    acc_parts.append(f"{label}{mv['avg_accuracy']:.1%}")
                acc_str = ' '.join(acc_parts)

            # 推荐问题合格率（alert/event 模块）
            rq_str = ""
            if mod_key in ('alert', 'event'):
                rq_list = [
                    r.metrics["recommend_question_quality"]
                    for r in mod_results
                    if r.success and not r.is_invalid
                    and r.metrics and "recommend_question_quality" in r.metrics
                    and r.metrics["recommend_question_quality"].get("accuracy") is not None
                ]
                if rq_list:
                    qualified = sum(1 for rq in rq_list if rq.get("is_qualified"))
                    rq_str = f" | 推荐问题合格{qualified}/{len(rq_list)}"

            line = f"  {name}: 有效{valid} 失败{failed} 失效{invalid} | 首包{avg_fp:.1f}s 总时长{avg_tr:.1f}s"
            if acc_str:
                line += f" | {acc_str}"
            if rq_str:
                line += rq_str
            interpret_lines.append(line)

    date_hint = f"（{run_date}）" if run_date else "（最新日期）"
    print(f"\n{'='*60}")
    print(f"🔍 解读完成，开始批量审查 {date_hint}（模块: {', '.join(modules)}）...")
    print(f"{'='*60}")
    from core.auditors.auto_audit_manager import AutoAuditManager
    mgr = AutoAuditManager(run_date=run_date)
    all_results = {}
    audit_lines = []
    for report_type in modules:
        result = mgr.batch_audit(report_type, date_str=run_date)
        all_results[report_type] = result
        s = result['summary']
        print(f"  {mgr.REPORT_TYPE_NAME_MAP[report_type]}: 总{s['total']}份, 成功{s['success_count']}, 失败{s['failed_count']}, 均分{s['avg_score']}")
        if s['total'] > 0:
            audit_lines.append(
                f"  {mgr.REPORT_TYPE_NAME_MAP[report_type]}: {s['success_count']}/{s['total']}份, 均分{s['avg_score']}"
            )

    html_path = mgr.generate_comprehensive_html()
    if html_path:
        print(f"\n📄 综合审查报告: {html_path}")
    print(f"{'='*60}")
    print(f"✅ 批量审查完成")
    print(f"{'='*60}")

    # 飞书通知（解读指标 + 审查结果，与终端统计格式一致）
    duration_sec = int(time.time() - start_time)
    hours = duration_sec // 3600
    minutes = (duration_sec % 3600) // 60
    seconds = duration_sec % 60
    if hours > 0:
        duration_str = f"{hours}h{minutes}m{seconds}s"
    elif minutes > 0:
        duration_str = f"{minutes}m{seconds}s"
    else:
        duration_str = f"{seconds}s"

    try:
        from core.notify.feishu_notify import send_feishu_message
        module_names = {'asset': '资产', 'alert': '告警', 'event': '事件', 'vuln': '漏洞'}
        mod_str = '+'.join(module_names.get(m, m) for m in modules)
        total_cases = total_valid + total_failed + total_invalid
        overall_fp = sum(all_fp_times)/len(all_fp_times) if all_fp_times else 0
        overall_tr = sum(all_tr_times)/len(all_tr_times) if all_tr_times else 0

        # 解读结果统计
        lines = [
            f"📊 全模块解读测试结果统计",
            f"  总测试数: {total_cases}",
            f"  有效样本: {total_valid}（参与指标计算）",
            f"  失败样本: {total_failed}（AI调用失败）",
            f"  失效样本: {total_invalid}（API查不到业务数据）",
            f"  平均首包响应: {overall_fp:.1f}s | 平均总报告时长: {overall_tr:.1f}s",
        ]
        if interpret_lines:
            lines.append("  各模块明细:")
            lines.extend(interpret_lines)
        else:
            lines.append("  各模块明细: 无解读数据")

        # 审查结果统计（所有模块都展示，无报告的显示0）
        lines.append(f"🔍 批量审查 (耗时{duration_str}):")
        audit_type_names = {'asset': '资产', 'alert': '告警', 'event': '事件', 'vuln': '漏洞'}
        for rt in modules:
            result = all_results.get(rt, {})
            s = result.get('summary', {})
            t = s.get('total', 0)
            sc = s.get('success_count', 0)
            fc = s.get('failed_count', 0)
            nc = s.get('not_auditable_count', 0)
            avg = s.get('avg_score', 0)
            if t > 0:
                extra = f", 不可审查{nc}份" if nc > 0 else ""
                lines.append(f"  {audit_type_names.get(rt, rt)}: {sc}/{t}份审查成功, 均分{avg}{extra}")
            else:
                lines.append(f"  {audit_type_names.get(rt, rt)}: 0份（无解读报告）")

        send_feishu_message('AIXDR自动化解读测试报告', lines)
    except Exception as e:
        print(f"[飞书通知] 发送失败: {e}")


def init_sample_test_cases():
    """初始化示例测试用例"""
    print("初始化示例测试用例...")
    manager = TestCaseManager()

    for module in ["asset", "vuln", "alert"]:
        sample = manager.create_sample_test_case(module)
        filepath = manager.save_test_case(module, sample)
        print(f"  - 创建 {module} 模块示例用例: {filepath}")


def run_asset_test():
    """运行资产解读模块测试（使用现有资产 ID）"""
    print("\n" + "="*60)
    print("运行资产解读模块测试")
    print("="*60)

    agent = AIInterpretAgent()

    from core.config_loader import ConfigLoader
    config = ConfigLoader()
    asset_ids = config.test_assets

    if not asset_ids:
        print("⚠️ 配置文件中没有配置测试资产 ID")
        return

    from agents.test_case_manager import TestCase
    test_cases = []
    for idx, asset_id in enumerate(asset_ids):
        test_case = TestCase(
            case_id=f"asset_test_{idx+1:02d}",
            module="asset",
            input_data={"asset_id": asset_id},
            expected_output={},
            description=f"资产解读测试 - {asset_id}",
            tags=["automated", "asset"]
        )
        test_cases.append(test_case)

    print(f"\n准备执行 {len(test_cases)} 个资产解读测试用例...")
    results = agent.run_module_tests("asset", test_cases)

    if results:
        print(f"\n{'='*60}")
        print(f"📄 生成综合测试报告...")
        print(f"{'='*60}")
        agent._generate_comprehensive_report()

    return agent


def run_alert_test():
    """运行安全告警解读模块测试"""
    print("\n" + "="*60)
    print("运行安全告警解读模块测试")
    print("="*60)

    agent = AIInterpretAgent()

    from core.config_loader import ConfigLoader
    config = ConfigLoader()
    alert_ids = config.test_alerts

    if not alert_ids:
        print("⚠️ 配置文件中没有配置测试告警 ID")
        return

    from agents.test_case_manager import TestCase
    test_cases = []
    for idx, alert_id in enumerate(alert_ids):
        test_case = TestCase(
            case_id=f"alert_test_{idx+1:02d}",
            module="alert",
            input_data={"alert_id": alert_id},
            expected_output={},
            description=f"告警解读测试 - {alert_id}",
            tags=["automated", "alert"]
        )
        test_cases.append(test_case)

    print(f"\n准备执行 {len(test_cases)} 个告警解读测试用例...")
    results = agent.run_module_tests("alert", test_cases)

    if results:
        print(f"\n{'='*60}")
        print(f"📄 生成综合测试报告...")
        print(f"{'='*60}")
        agent._generate_comprehensive_report()

    return agent


def main():
    parser = argparse.ArgumentParser(description="AI 解读自动化测试智能体")
    parser.add_argument(
        "--mode",
        choices=["init", "asset", "alert", "all"],
        default="asset",
        help="运行模式: init=初始化示例用例, asset=资产解读测试, alert=告警解读测试, all=全模块测试"
    )
    parser.add_argument(
        "--module",
        choices=["asset", "vuln", "alert", "event"],
        help="指定模块测试（优先级高于--mode）"
    )

    args = parser.parse_args()

    print("="*60)
    print("AI 解读自动化测试智能体")
    print("="*60)

    if args.module:
        if args.module == "asset":
            agent = run_asset_test()
        elif args.module == "alert":
            agent = run_alert_test()
        elif args.module == "vuln":
            print("\n" + "="*60)
            print("运行漏洞解读模块测试")
            print("="*60)

            agent = AIInterpretAgent()
            from core.config_loader import ConfigLoader
            config = ConfigLoader()
            vuln_ids = config.test_vulns if hasattr(config, 'test_vulns') else []

            if not vuln_ids:
                print("⚠️ 配置文件中没有配置测试漏洞 ID")
            else:
                from agents.test_case_manager import TestCase
                test_cases = []
                for idx, vuln_id in enumerate(vuln_ids):
                    test_case = TestCase(
                        case_id=f"vuln_test_{idx+1:02d}",
                        module="vuln",
                        input_data={"vuln_id": vuln_id},
                        expected_output={},
                        description=f"漏洞解读测试 - {vuln_id}",
                        tags=["automated", "vuln"]
                    )
                    test_cases.append(test_case)

                print(f"\n准备执行 {len(test_cases)} 个漏洞解读测试用例...")
                results = agent.run_module_tests("vuln", test_cases)

                if results:
                    print(f"\n{'='*60}")
                    print(f"📄 生成综合测试报告...")
                    print(f"{'='*60}")
                    agent._generate_comprehensive_report()
        elif args.module == "event":
            # event 模块直接从配置文件读取
            print("\n" + "="*60)
            print("运行安全事件解读模块测试")
            print("="*60)

            agent = AIInterpretAgent()
            from core.config_loader import ConfigLoader
            config = ConfigLoader()
            event_ids = config.test_events if hasattr(config, 'test_events') else []

            if not event_ids:
                print("⚠️ 配置文件中没有配置测试事件 ID")
            else:
                from agents.test_case_manager import TestCase
                test_cases = []
                for idx, event_id in enumerate(event_ids):
                    test_case = TestCase(
                        case_id=f"event_test_{idx+1:02d}",
                        module="event",
                        input_data={"event_id": event_id},
                        expected_output={},
                        description=f"事件解读测试 - {event_id}",
                        tags=["automated", "event"]
                    )
                    test_cases.append(test_case)

                print(f"\n准备执行 {len(test_cases)} 个事件解读测试用例...")
                results = agent.run_module_tests("event", test_cases)

                if results:
                    print(f"\n{'='*60}")
                    print(f"📄 生成综合测试报告...")
                    print(f"{'='*60}")
                    agent._generate_comprehensive_report()
        # --module 模式：解读完只审查本模块，用启动时日期精确定位
        from datetime import datetime
        run_batch_audit_after_interpret([args.module], run_date=agent.run_date, agent=agent)
        return
    elif args.mode == "init":
        init_sample_test_cases()
        return  # init 模式不触发审查
    elif args.mode == "asset":
        agent = run_asset_test()
        run_batch_audit_after_interpret(['asset'], run_date=agent.run_date, agent=agent)
        return
    elif args.mode == "alert":
        agent = run_alert_test()
        run_batch_audit_after_interpret(['alert'], run_date=agent.run_date, agent=agent)
        return
    elif args.mode == "all":
        agent = AIInterpretAgent()
        agent.run_all_tests()
        # 用 agent.run_date（启动时日期），确保跨午夜时审查和解读读同一目录
        run_batch_audit_after_interpret(['asset', 'alert', 'event', 'vuln'], run_date=agent.run_date, agent=agent)
        return
    else:
        print(f"❌ 未知模式: {args.mode}")
        return


if __name__ == "__main__":
    main()

"""
AI 解读自动化测试智能体运行脚本
支持单模块或全模块测试
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(__file__))
from agents import AIInterpretAgent, TestCaseManager


def run_batch_audit_after_interpret(modules: list = None, run_date: str = None, agent=None,
                                    model: str = "190", server: str = "http://localhost:8080"):
    """解读完成后自动触发批量审查，完成后发飞书通知（含解读指标+审查结果）

    Args:
        modules: 本次解读的模块列表
        run_date: 本次解读的时间戳目录
        agent: AIInterpretAgent实例，用于提取解读指标
        model: 大模型型号名（生成v3 JSON用）
        server: 服务地址（打印curl上传命令用）
    """
    import time
    start_time = time.time()

    if modules is None:
        modules = ['asset', 'alarm', 'event', 'vuln']

    # 提取解读各模块指标（从 agent.results）
    interpret_lines = []
    total_valid = total_failed = total_invalid = 0
    all_fp_times = []
    all_tr_times = []
    if agent and hasattr(agent, 'results') and agent.results:
        module_names_cn = {'asset': '资产解读', 'alarm': '告警解读', 'event': '事件解读', 'vuln': '漏洞解读', 'sandbox': '沙箱解读'}
        metric_labels = {
            'chapter_structure_completeness': '结构完整率',
            'risk_level_accuracy': '风险等级',
            'threat_determination_accuracy': '威胁定性',
            'attack_result_accuracy': '攻击结果',
            'dynamic_structure_completeness': '动态结构',
            'sample_info_accuracy': '样本信息提取',
            'disposal_rationality': '处置建议合理性',
            'format_compliance': '格式规范性',
            'section_completeness': '章节完整性',
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

            line = f"  {name}: 有效{valid} 失败{failed} 失效{invalid} | 首包{avg_fp:.1f}s 总时长{avg_tr:.1f}s"
            if acc_str:
                line += f" | {acc_str}"
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
        if report_type == 'sandbox':
            continue
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

    # 生成 v3 JSON 文件（供上传框架接口，不自动上传）
    try:
        from core.uploader import build_interpret_v3_json, save_v3_json, MODULE_AGENT_MAP
        for module in modules:
            if module == 'sandbox':
                continue
            result = all_results.get(module, {})
            avg_score = result.get('summary', {}).get('avg_score', 0)
            if agent and agent.results.get(module):
                v3 = build_interpret_v3_json(agent, module, avg_score)
                agent_id = MODULE_AGENT_MAP[module]['agent_id']
                save_v3_json(agent_id, run_date or agent.run_date, model, v3, server=server, suffix='_accuracy')
    except Exception as e:
        print(f"[v3 JSON生成] 失败: {e}")

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
        module_names = {'asset': '资产', 'alarm': '告警', 'event': '事件', 'vuln': '漏洞'}
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
        audit_type_names = {'asset': '资产', 'alarm': '告警', 'event': '事件', 'vuln': '漏洞'}
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

    for module in ["asset", "vuln", "alarm"]:
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


def run_alarm_test():
    """运行安全告警解读模块测试"""
    print("\n" + "="*60)
    print("运行安全告警解读模块测试")
    print("="*60)

    agent = AIInterpretAgent()

    from core.config_loader import ConfigLoader
    config = ConfigLoader()
    alarm_ids = config.test_alarms

    if not alarm_ids:
        print("⚠️ 配置文件中没有配置测试告警 ID")
        return

    from agents.test_case_manager import TestCase
    test_cases = []
    for idx, alarm_id in enumerate(alarm_ids):
        test_case = TestCase(
            case_id=f"alarm_test_{idx+1:02d}",
            module="alarm",
            input_data={"alarm_id": alarm_id},
            expected_output={},
            description=f"告警解读测试 - {alarm_id}",
            tags=["automated", "alarm"]
        )
        test_cases.append(test_case)

    print(f"\n准备执行 {len(test_cases)} 个告警解读测试用例...")
    results = agent.run_module_tests("alarm", test_cases)

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
        choices=["init", "asset", "alarm", "all"],
        default="asset",
        help="运行模式: init=初始化示例用例, asset=资产解读测试, alarm=告警解读测试, all=全模块测试"
    )
    parser.add_argument(
        "--module",
        choices=["asset", "vuln", "alarm", "event", "sandbox"],
        help="指定模块测试（优先级高于--mode）"
    )
    parser.add_argument(
        "--model",
        default="190",
        help="大模型型号名（生成v3 JSON用，如 190/180/cloud/kimi-2.6）"
    )
    parser.add_argument(
        "--server",
        default="http://localhost:8080",
        help="服务地址（打印curl上传命令用）"
    )

    args = parser.parse_args()

    print("="*60)
    print("AI 解读自动化测试智能体")
    print("="*60)

    if args.module:
        if args.module == "asset":
            agent = run_asset_test()
        elif args.module == "alarm":
            agent = run_alarm_test()
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
        elif args.module == "sandbox":
            print("\n" + "="*60)
            print("运行沙箱报告解读模块测试")
            print("="*60)

            agent = AIInterpretAgent()
            from core.config_loader import ConfigLoader
            config = ConfigLoader()
            sandbox_ids = config.test_sandboxes if hasattr(config, 'test_sandboxes') else []

            if not sandbox_ids:
                print("⚠️ 配置文件中没有配置测试沙箱样本 ID")
            else:
                from agents.test_case_manager import TestCase
                test_cases = []
                for idx, sandbox_id in enumerate(sandbox_ids):
                    test_case = TestCase(
                        case_id=f"sandbox_test_{idx+1:02d}",
                        module="sandbox",
                        input_data={"sandbox_id": sandbox_id},
                        expected_output={},
                        description=f"沙箱解读测试 - {sandbox_id}",
                        tags=["automated", "sandbox"]
                    )
                    test_cases.append(test_case)

                print(f"\n准备执行 {len(test_cases)} 个沙箱解读测试用例...")
                results = agent.run_module_tests("sandbox", test_cases)

                if results:
                    print(f"\n{'='*60}")
                    print(f"📄 生成综合测试报告...")
                    print(f"{'='*60}")
                    agent._generate_comprehensive_report()
        # --module 模式：解读完只审查本模块，用启动时日期精确定位
        from datetime import datetime
        run_batch_audit_after_interpret([args.module], run_date=agent.run_date, agent=agent, model=args.model, server=args.server)
        return
    elif args.mode == "init":
        init_sample_test_cases()
        return  # init 模式不触发审查
    elif args.mode == "asset":
        agent = run_asset_test()
        run_batch_audit_after_interpret(['asset'], run_date=agent.run_date, agent=agent, model=args.model, server=args.server)
        return
    elif args.mode == "alarm":
        agent = run_alarm_test()
        run_batch_audit_after_interpret(['alarm'], run_date=agent.run_date, agent=agent, model=args.model, server=args.server)
        return
    elif args.mode == "all":
        agent = AIInterpretAgent()
        agent.run_all_tests()
        # 用 agent.run_date（启动时日期），确保跨午夜时审查和解读读同一目录
        run_batch_audit_after_interpret(['asset', 'alarm', 'event', 'vuln'], run_date=agent.run_date, agent=agent, model=args.model, server=args.server)
        return
    else:
        print(f"❌ 未知模式: {args.mode}")
        return


if __name__ == "__main__":
    main()

"""
AI 解读自动化测试智能体运行脚本
支持单模块或全模块测试
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(__file__))
from agents import AIInterpretAgent, TestCaseManager


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

    return results


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

    return results


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
            run_asset_test()
        elif args.module == "alert":
            run_alert_test()
        elif args.module == "vuln":
            # vuln 模块直接从配置文件读取
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
    elif args.mode == "init":
        init_sample_test_cases()
    elif args.mode == "asset":
        run_asset_test()
    elif args.mode == "alert":
        run_alert_test()
    elif args.mode == "all":
        agent = AIInterpretAgent()
        agent.run_all_tests()
    else:
        print(f"❌ 未知模式: {args.mode}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
核心结论稳定性测试专用脚本
测试告警、事件和漏洞模块的核心结论稳定性指标
- 告警/事件：核心结论稳定性（一句话总结的三维度一致性）
- 漏洞：是否立即处置结论稳定性（两次解读的处置建议一致性）
"""
import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(__file__))
from core.config_loader import ConfigLoader
from agents.ai_interpret_agent import AIInterpretAgent
from core.api_clients.alarm_client import AlarmAPIClient
from core.api_clients.event_client import EventAPIClient


def run_stability_test(module_type: str, run_id: str = None):
    """运行稳定性测试

    Args:
        module_type: 模块类型，'alarm'、'event' 或 'vuln'
        run_id: 本次执行的时间戳，同一次 all 执行共用同一个 run_id
    """
    if run_id is None:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("\n" + "="*70)

    # 根据模块类型设置标题和测试参数
    if module_type == "alarm":
        print(f"📋 核心结论稳定性测试 - 安全告警")
        test_ids = ConfigLoader().stability_test_alarms
        id_field = "alarm_id"
        module_name = "安全告警"
    elif module_type == "event":
        print(f"📋 核心结论稳定性测试 - 安全事件")
        test_ids = ConfigLoader().stability_test_events
        id_field = "event_id"
        module_name = "安全事件"
    elif module_type == "vuln":
        print(f"📋 是否立即处置结论稳定性测试 - 漏洞")
        test_ids = ConfigLoader().stability_test_vulns
        id_field = "vuln_id"
        module_name = "漏洞"
    else:
        print(f"❌ 不支持的模块类型: {module_type}")
        print("   支持的类型: alarm, event, vuln")
        return

    print("="*70)

    config = ConfigLoader()
    agent = AIInterpretAgent()

    if not test_ids:
        print(f"⚠️ 配置文件中没有配置 {module_name} 稳定性测试ID")
        print(f"   请在 config_api.yaml 中配置 stability_test_{module_type}s")
        return

    print(f"\n准备测试 {len(test_ids)} 个{module_name}的稳定性...")
    print(f"测试ID列表: {test_ids}")

    results = []
    pass_count = 0
    fail_count = 0
    fail_inconsistent_count = 0  # Fail（结论不一致）
    fail_missing_count = 0       # Fail（结论缺失，AI异常导致）
    error_count = 0  # 执行错误（AI调用失败），不计入Pass率

    for idx, test_id in enumerate(test_ids):
        print(f"\n{'='*70}")
        print(f"测试用例 {idx+1}/{len(test_ids)}: {id_field} = {test_id}")
        print(f"{'='*70}")

        # 第一次解读
        print(f"\n🔄 第一次解读...")
        result1 = agent.call_ai_with_timing(module_type, test_id)

        if not result1.get("success"):
            err1 = result1.get("error", "第一次解读失败")
            print(f"  ❌ 第一次解读失败: {err1}")
            # 判断是否是AI平台异常
            is_platform_err = "AI平台异常" in err1 or "AI大模型" in err1
            results.append({
                "id": test_id,
                "module": module_type,
                "success": False,
                "error": err1,
                "stability_passed": False,
                "is_error": True,
                "is_ai_platform_error": is_platform_err
            })
            error_count += 1
            continue

        first_packet_time1 = result1.get("first_packet_time", 0)
        total_response_time1 = result1.get("total_time", 0)
        raw_text1 = result1.get("raw_text", "")

        print(f"  ✅ 第一次解读成功")
        print(f"  ⏱️ 首包响应: {first_packet_time1:.2f}s, 总响应: {total_response_time1:.2f}s")

        # 保存第一次原始markdown
        save_stability_raw_md(module_type, test_id, 1, raw_text1, run_id)

        # 漏洞模块提取"是否需要立即处置"
        if module_type == "vuln":
            need_fix1 = agent._extract_need_immediate_fix(raw_text1)
            print(f"  📝 是否需要立即处置(第1次): {need_fix1}")
        else:
            # 告警/事件模块提取一句话总结
            summary1 = agent._extract_one_sentence_summary(raw_text1)
            print(f"  📝 总结1: {summary1[:100]}...")

        # 第二次解读
        print(f"\n🔄 第二次解读...")
        result2 = agent.call_ai_with_timing(module_type, test_id)

        if not result2.get("success"):
            err2 = result2.get("error", "第二次解读失败")
            is_platform_err2 = "AI平台异常" in err2 or "AI大模型" in err2
            if is_platform_err2:
                # 第2次AI平台异常 → 平台故障，归为error，不计入Pass率
                print(f"  ❌ 第二次AI平台异常: {err2}")
                results.append({
                    "id": test_id,
                    "module": module_type,
                    "success": False,
                    "stability_passed": False,
                    "is_error": True,
                    "is_ai_platform_error": True,
                    "error": f"第二次{err2}"
                })
                error_count += 1
            else:
                # 第2次普通失败（超时等）→ fail，计入Pass率
                fail_reason = f"第二次解读失败（{err2}），与第一次结果不一致，计为Fail"
                print(f"  ❌ 稳定性: Fail（{fail_reason}）")
                results.append({
                    "id": test_id,
                    "module": module_type,
                    "success": True,
                    "stability_passed": False,
                    "is_error": False,
                    "inconsistencies": [fail_reason],
                })
                fail_count += 1
                fail_inconsistent_count += 1
            continue

        first_packet_time2 = result2.get("first_packet_time", 0)
        total_response_time2 = result2.get("total_time", 0)
        raw_text2 = result2.get("raw_text", "")

        print(f"  ✅ 第二次解读成功")
        print(f"  ⏱️ 首包响应: {first_packet_time2:.2f}s, 总响应: {total_response_time2:.2f}s")

        # 保存第二次原始markdown
        save_stability_raw_md(module_type, test_id, 2, raw_text2, run_id)

        # 漏洞模块判断稳定性
        if module_type == "vuln":
            need_fix2 = agent._extract_need_immediate_fix(raw_text2)
            print(f"  📝 是否需要立即处置(第2次): {need_fix2}")

            # 检查是否提取失败（解读报告未展示「是否需要立即处置」结论）
            if need_fix1 == "无法判断" or need_fix2 == "无法判断":
                failed_rounds = []
                if need_fix1 == "无法判断":
                    failed_rounds.append("第1次")
                if need_fix2 == "无法判断":
                    failed_rounds.append("第2次")
                failed_round_str = "、".join(failed_rounds)
                fail_reason = f"{failed_round_str}解读报告未展示「是否需要立即处置」结论，计为Fail"
                print(f"  ❌ 稳定性: Fail（{fail_reason}）")
                results.append({
                    "id": test_id,
                    "module": module_type,
                    "success": True,
                    "stability_passed": False,
                    "is_error": False,
                    "is_missing_conclusion": True,  # 标识为结论缺失，区别于普通Fail
                    "inconsistencies": [fail_reason],
                    "need_fix1": need_fix1,
                    "need_fix2": need_fix2,
                    "first_packet_time_avg": (first_packet_time1 + first_packet_time2) / 2,
                    "total_response_time_avg": (total_response_time1 + total_response_time2) / 2
                })
                fail_count += 1
                fail_missing_count += 1
                continue

            # 直接比较两次结论（不需要LLM裁判）
            print(f"\n📊 判断稳定性...")
            stability_result = agent._check_vuln_stability(need_fix1, need_fix2)

            passed = stability_result.get("passed", False)
            inconsistencies = stability_result.get("inconsistencies", [])

            if passed:
                print(f"  ✅ 是否立即处置结论稳定性: Pass")
                pass_count += 1
            else:
                print(f"  ❌ 是否立即处置结论稳定性: Fail（结论不一致）")
                if inconsistencies:
                    print(f"  ⚠️ 不一致之处: {inconsistencies[0]}")
                fail_count += 1
                fail_inconsistent_count += 1

            # 记录结果
            results.append({
                "id": test_id,
                "module": module_type,
                "success": True,
                "stability_passed": passed,
                "need_fix1": need_fix1,
                "need_fix2": need_fix2,
                "inconsistencies": inconsistencies,
                "first_packet_time_avg": (first_packet_time1 + first_packet_time2) / 2,
                "total_response_time_avg": (total_response_time1 + total_response_time2) / 2
            })

        else:
            # 告警/事件模块判断稳定性（使用LLM裁判）
            summary2 = agent._extract_one_sentence_summary(raw_text2)
            print(f"  📝 总结2: {summary2[:100]}...")

            # 获取原始告警/事件描述
            if module_type == "alarm":
                api_client = AlarmAPIClient(config)
                api_detail = api_client.get_alarm_detail(test_id)
                alarm_description = api_detail.get("description", "") or api_detail.get("title", "") or test_id
            else:  # event
                api_client = EventAPIClient(config)
                api_detail = api_client.get_event_detail_by_id(test_id)
                alarm_description = api_detail.get("description", "") or api_detail.get("title", "") or test_id

            # LLM裁判判断
            print(f"\n🤖 LLM裁判判断稳定性...")
            stability_result = agent._check_stability_with_llm_judge(summary1, summary2, alarm_description)

            passed = stability_result.get("passed", False)
            inconsistencies = stability_result.get("inconsistencies", [])
            judge_response = stability_result.get("judge_response", "")

            if passed:
                print(f"  ✅ 核心结论稳定性: Pass")
                pass_count += 1
            else:
                print(f"  ❌ 核心结论稳定性: Fail（结论不一致）")
                if inconsistencies:
                    print(f"  ⚠️ 不一致之处: {inconsistencies[0][:200]}")
                fail_count += 1
                fail_inconsistent_count += 1

            # 记录结果
            results.append({
                "id": test_id,
                "module": module_type,
                "success": True,
                "stability_passed": passed,
                "summary1": summary1,
                "summary2": summary2,
                "inconsistencies": inconsistencies,
                "judge_response": judge_response,
                "first_packet_time_avg": (first_packet_time1 + first_packet_time2) / 2,
                "total_response_time_avg": (total_response_time1 + total_response_time2) / 2
            })

    # 生成稳定性测试报告
    valid_count = pass_count + fail_count
    pass_rate = (pass_count / valid_count * 100) if valid_count > 0 else 0

    print(f"\n{'='*70}")
    print(f"📊 稳定性测试结果统计")
    print(f"{'='*70}")
    # AI平台异常计数（归在error里）
    ai_platform_error_count = sum(1 for r in results if r.get('is_ai_platform_error'))
    ai_call_fail_count = error_count - ai_platform_error_count  # 普通AI调用失败（超时等）

    print(f"  总测试数: {len(test_ids)}")
    print(f"  执行错误: {error_count}（不计入Pass率）")
    if ai_platform_error_count > 0:
        print(f"    ├─ AI平台异常: {ai_platform_error_count}（大模型连接失败）")
    if ai_call_fail_count > 0:
        print(f"    └─ AI调用失败: {ai_call_fail_count}（超时/SSE断开）")
    print(f"  有效测试: {valid_count}（可进行结论对比的样本）")
    print(f"  Pass数量: {pass_count}")
    print(f"  Fail数量: {fail_count}")
    if fail_inconsistent_count > 0:
        print(f"    ├─ Fail（结论不一致）: {fail_inconsistent_count}")
    if fail_missing_count > 0:
        print(f"    └─ Fail（结论缺失/AI异常）: {fail_missing_count}")
    print(f"  Pass率: {pass_rate:.1f}%（基于{valid_count}个有效测试）")

    # 保存稳定性测试报告
    save_stability_report(module_type, results, pass_count, fail_count, error_count, run_id,
                          fail_inconsistent_count=fail_inconsistent_count,
                          fail_missing_count=fail_missing_count)

    return {
        "results": results,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "fail_inconsistent_count": fail_inconsistent_count,
        "fail_missing_count": fail_missing_count,
        "error_count": error_count,
        "ai_platform_error_count": ai_platform_error_count
    }


def _build_stability_html_css() -> str:
    """构建稳定性测试报告CSS样式"""
    return """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: #333; line-height: 1.6; padding: 20px; min-height: 100vh;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    .header {
        background: white; border-radius: 12px; padding: 30px; margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .header h1 { font-size: 28px; color: #667eea; margin-bottom: 10px; }
    .header-meta { display: flex; gap: 20px; color: #666; font-size: 14px; flex-wrap: wrap; }
    .summary-grid {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px; margin-bottom: 20px;
    }
    .summary-card {
        background: white; border-radius: 12px; padding: 25px;
        text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: transform 0.3s;
    }
    .summary-card:hover { transform: translateY(-5px); }
    .summary-card .value { font-size: 36px; font-weight: bold; margin: 10px 0; }
    .summary-card.pass .value { color: #48bb78; }
    .summary-card.fail .value { color: #f56565; }
    .summary-card.neutral .value { color: #667eea; }
    .summary-card .label { color: #666; font-size: 14px; }
    .module-section {
        background: white; border-radius: 12px; padding: 25px;
        margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .module-header {
        display: flex; justify-content: space-between; align-items: center;
        margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #eee;
    }
    .module-title { font-size: 22px; font-weight: bold; color: #333; }
    .module-stats { display: flex; gap: 15px; }
    .stat-badge {
        padding: 5px 12px; border-radius: 20px; font-size: 13px; font-weight: 500;
    }
    .stat-badge.success { background: #c6f6d5; color: #22543d; }
    .stat-badge.error { background: #fed7d7; color: #742a2a; }
    .stat-badge.info { background: #bee3f8; color: #2a4365; }
    .test-case {
        margin-bottom: 20px; border: 1px solid #e2e8f0;
        border-radius: 8px; overflow: hidden;
    }
    .test-case-header {
        background: #f7fafc; padding: 15px 20px;
        display: flex; justify-content: space-between; align-items: center; cursor: pointer;
    }
    .test-case-header:hover { background: #edf2f7; }
    .test-case-title { display: flex; align-items: center; gap: 10px; }
    .status-icon { font-size: 24px; }
    .test-case-body { padding: 20px; display: none; }
    .test-case-body.open { display: block; }
    .comparison-box {
        background: #f7fafc; border-radius: 8px; padding: 15px;
        margin-bottom: 15px; border-left: 4px solid #667eea;
    }
    .comparison-box .label {
        font-size: 13px; color: #667eea; font-weight: 600;
        margin-bottom: 8px;
    }
    .comparison-box .content {
        font-size: 14px; color: #333; line-height: 1.8;
        word-break: break-all;
    }
    .comparison-box.first { border-left-color: #4299e1; }
    .comparison-box.first .label { color: #4299e1; }
    .comparison-box.second { border-left-color: #48bb78; }
    .comparison-box.second .label { color: #48bb78; }
    .inconsistency-box {
        background: #fff5f5; border-radius: 8px; padding: 15px;
        border-left: 4px solid #f56565; margin-top: 15px;
    }
    .inconsistency-box .label {
        font-size: 13px; color: #f56565; font-weight: 600;
        margin-bottom: 8px;
    }
    .inconsistency-box .content {
        font-size: 14px; color: #742a2a; line-height: 1.8;
    }
    .time-info {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 10px; margin-bottom: 15px;
    }
    .time-card {
        background: #f7fafc; padding: 12px; border-radius: 6px; text-align: center;
    }
    .time-value { font-size: 20px; font-weight: bold; color: #667eea; }
    .time-label { font-size: 12px; color: #666; }
    .error-box {
        background: #fff5f5; border-radius: 8px; padding: 15px;
        border-left: 4px solid #f56565;
    }
    .error-box .content { color: #742a2a; font-size: 14px; }
    .raw-data-toggle {
        margin-top: 15px; text-align: right;
    }
    .raw-data {
        background: #1a1a2e; color: #16c79a; padding: 15px;
        border-radius: 8px; font-family: 'Courier New', monospace;
        font-size: 12px; overflow-x: auto; margin-top: 10px; display: none;
    }
    .raw-data.open { display: block; }
    .collapse-toggle {
        background: #667eea; color: white; border: none;
        padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px;
    }
    .collapse-toggle:hover { background: #5a67d8; }
    """


def _build_stability_html_js() -> str:
    """构建稳定性测试报告JS"""
    return """
    function toggleTestCase(element) {
        const body = element.nextElementSibling;
        body.classList.toggle('open');
    }
    function toggleRawData(element) {
        const rawData = element.nextElementSibling;
        rawData.classList.toggle('open');
        element.textContent = rawData.classList.contains('open') ? '隐藏原始数据' : '显示原始数据';
    }
    document.addEventListener('DOMContentLoaded', function() {
        console.log('稳定性测试报告已加载');
    });
    """


def _build_stability_test_case_html(result: Dict, idx: int, module_type: str) -> str:
    """构建单个稳定性测试用例的HTML"""
    is_pass = result.get('stability_passed', False)
    is_error = result.get('is_error', False)
    is_missing_conclusion = result.get('is_missing_conclusion', False)
    is_ai_platform_error = result.get('is_ai_platform_error', False)

    if is_error:
        if is_ai_platform_error:
            status_icon = "🔴"
            status_class = "error"
            status_text = "AI平台异常（大模型连接失败）"
        else:
            status_icon = "⚠️"
            status_class = "info"
            status_text = "执行错误"
    elif is_pass:
        status_icon = "✅"
        status_class = "success"
        status_text = "Pass"
    elif is_missing_conclusion:
        status_icon = "❌"
        status_class = "error"
        status_text = "Fail（结论缺失）"
    else:
        status_icon = "❌"
        status_class = "error"
        status_text = "Fail"

    # 时间信息
    time_html = ""
    if result.get("first_packet_time_avg"):
        time_html = f"""
        <div class="time-info">
            <div class="time-card">
                <div class="time-value">{result.get('first_packet_time_avg', 0):.2f}s</div>
                <div class="time-label">平均首包响应</div>
            </div>
            <div class="time-card">
                <div class="time-value">{result.get('total_response_time_avg', 0):.2f}s</div>
                <div class="time-label">平均总响应</div>
            </div>
        </div>
        """

    # 对比内容（根据模块类型）
    comparison_html = ""
    if result.get("success"):
        if module_type == "vuln":
            # 漏洞模块：展示两次"是否需要立即处置"结论
            need_fix1 = result.get('need_fix1', '未提取到')
            need_fix2 = result.get('need_fix2', '未提取到')
            comparison_html = f"""
            <div class="comparison-box first">
                <div class="label">🔵 第一次解读 - 是否需要立即处置</div>
                <div class="content">{need_fix1}</div>
            </div>
            <div class="comparison-box second">
                <div class="label">🟢 第二次解读 - 是否需要立即处置</div>
                <div class="content">{need_fix2}</div>
            </div>
            """
        else:
            # 告警/事件模块：展示两次一句话总结
            summary1 = result.get('summary1', '')
            summary2 = result.get('summary2', '')
            comparison_html = f"""
            <div class="comparison-box first">
                <div class="label">🔵 第一次解读 - 一句话总结</div>
                <div class="content">{summary1}</div>
            </div>
            <div class="comparison-box second">
                <div class="label">🟢 第二次解读 - 一句话总结</div>
                <div class="content">{summary2}</div>
            </div>
            """

        # 不一致之处 / 执行错误 / 结论缺失 提示
        inconsistencies = result.get('inconsistencies', [])
        if is_error:
            if is_ai_platform_error:
                inconsistency_html = f"""
                <div class="inconsistency-box" style="border-left-color:#e53e3e;background:#fff5f5;">
                    <div class="label" style="color:#e53e3e;">🔴 AI平台异常（大模型连接失败，不计入Pass率）</div>
                    <div class="content">{result.get('error', '未知错误')}</div>
                </div>
                """
            else:
                inconsistency_html = f"""
                <div class="inconsistency-box" style="border-left-color:#e2e8f0;">
                    <div class="label" style="color:#718096;">⚠️ 执行错误（不计入Pass率）</div>
                    <div class="content">{result.get('error', '未知错误')}</div>
                </div>
                """
        elif is_missing_conclusion:
            inconsistency_html = f"""
            <div class="inconsistency-box" style="border-left-color:#dd6b20;">
                <div class="label" style="color:#dd6b20;">📋 解读报告结论缺失（计为Fail）</div>
                <div class="content">{inconsistencies[0] if inconsistencies else '解读报告未展示「是否需要立即处置」结论'}</div>
            </div>
            """
        elif not is_pass and inconsistencies:
            inconsistency_html = f"""
            <div class="inconsistency-box">
                <div class="label">⚠️ 不一致之处</div>
                <div class="content">{inconsistencies[0]}</div>
            </div>
            """
        else:
            inconsistency_html = ""
    else:
        # 解读失败
        comparison_html = f"""
        <div class="error-box">
            <div class="content">❌ {result.get('error', '未知错误')}</div>
        </div>
        """
        inconsistency_html = ""

    # 原始数据（LLM裁判响应）
    raw_data_html = ""
    if result.get("judge_response"):
        raw_data_html = f"""
        <div class="raw-data-toggle">
            <button class="collapse-toggle" onclick="toggleRawData(this)">显示裁判原始响应</button>
        </div>
        <div class="raw-data">{result.get('judge_response', '')}</div>
        """

    return f"""
    <div class="test-case">
        <div class="test-case-header" onclick="toggleTestCase(this)">
            <div class="test-case-title">
                <span class="status-icon">{status_icon}</span>
                <span><strong>测试用例 {idx+1}</strong> - ID: {result['id']}</span>
            </div>
            <span class="stat-badge {status_class}">{status_text}</span>
        </div>
        <div class="test-case-body">
            {time_html}
            {comparison_html}
            {inconsistency_html}
            {raw_data_html}
        </div>
    </div>
    """


MODULE_FILE_NAMES = {
    "alarm": "告警",
    "event": "事件",
    "vuln": "漏洞",
}


def save_stability_raw_md(module_type: str, test_id: str, round_num: int, raw_text: str, run_id: str = None):
    """保存稳定性测试的原始markdown，按执行时间戳归档便于溯源

    Args:
        run_id: 本次执行的时间戳（YYYYMMDD_HHMMSS），None 则用当前时间
    """
    if run_id is None:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(os.path.dirname(__file__), "outputs", "stability_test", "stability_md", run_id, module_type)
    os.makedirs(report_dir, exist_ok=True)

    module_name = MODULE_FILE_NAMES.get(module_type, module_type)
    md_file = os.path.join(report_dir, f"stability_{module_type}_{test_id}_round{round_num}.md")
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(f"# AI 稳定性测试 - {module_name}解读报告\n\n")
        f.write(f"**{module_type}_id**: {test_id}\n\n")
        f.write(f"**轮次**: 第{round_num}次解读\n\n")
        f.write(f"**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        f.write(raw_text)


def save_stability_report(module_type: str, results: List[Dict], pass_count: int, fail_count: int, error_count: int = 0, run_id: str = None,
                          fail_inconsistent_count: int = 0, fail_missing_count: int = 0):
    """保存稳定性测试报告（HTML），按 run_id 归档，与 stability_md 对应"""
    if run_id is None:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_dir = os.path.join(os.path.dirname(__file__), "outputs", "stability_test", "stability_reports", run_id)
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)

    # 根据模块类型设置报告标题
    if module_type == "vuln":
        report_title = "是否立即处置结论稳定性测试报告"
        module_name = "漏洞解读"
    elif module_type == "alarm":
        report_title = "核心结论稳定性测试报告"
        module_name = "安全告警解读"
    elif module_type == "event":
        report_title = "核心结论稳定性测试报告"
        module_name = "安全事件解读"
    else:
        report_title = "稳定性测试报告"
        module_name = module_type

    total = len(results)
    valid_count = pass_count + fail_count
    pass_rate = (pass_count / valid_count * 100) if valid_count > 0 else 0

    # 生成HTML报告（固定文件名，在 run_id 目录下）
    html_file = os.path.join(report_dir, f"stability_test_{module_type}.html")
    # 原始MD目录（溯源用）
    md_dir = os.path.join(os.path.dirname(__file__), "outputs", "stability_test", "stability_md", run_id, module_type)

    # 构建测试用例HTML
    test_cases_html = ""
    for idx, result in enumerate(results):
        test_cases_html += _build_stability_test_case_html(result, idx, module_type)

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>{_build_stability_html_css()}</style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1>🎯 {report_title}</h1>
            <div class="header-meta">
                <span>📅 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span>🗂️ 执行ID: {run_id}</span>
                <span>📋 总测试数: {total}</span>
                <span>✅ Pass: {pass_count}</span>
                <span>❌ Fail: {fail_count}</span>
                <span>⚠️ 执行错误: {error_count}</span>
            </div>
            <div style="margin-top:8px;font-size:12px;opacity:0.8;">
                📁 原始解读MD: stability_md/{run_id}/{module_type}/
            </div>
        </div>

        <!-- 统计摘要 -->
        <div class="summary-grid">
            <div class="summary-card pass">
                <div class="value">{pass_rate:.1f}%</div>
                <div class="label">Pass率（基于{valid_count}个有效测试）</div>
            </div>
            <div class="summary-card pass">
                <div class="value">{pass_count}</div>
                <div class="label">Pass数量</div>
            </div>
            <div class="summary-card fail">
                <div class="value">{fail_count}</div>
                <div class="label">Fail总数</div>
            </div>
            <div class="summary-card fail">
                <div class="value">{fail_inconsistent_count}</div>
                <div class="label">Fail（结论不一致）</div>
            </div>
            <div class="summary-card fail">
                <div class="value">{fail_missing_count}</div>
                <div class="label">Fail（结论缺失/AI异常）</div>
            </div>
            <div class="summary-card neutral">
                <div class="value">{error_count}</div>
                <div class="label">执行错误（不计入Pass率）</div>
            </div>
        </div>

        <!-- 测试用例详情 -->
        <div class="module-section">
            <div class="module-header">
                <div class="module-title">📦 {module_name} - 稳定性测试结果</div>
                <div class="module-stats">
                    <span class="stat-badge info">总数: {total}</span>
                    <span class="stat-badge success">Pass: {pass_count}</span>
                    <span class="stat-badge error">Fail(不一致): {fail_inconsistent_count}</span>
                    <span class="stat-badge error">Fail(缺失): {fail_missing_count}</span>
                    <span class="stat-badge info">错误: {error_count}</span>
                </div>
            </div>
            {test_cases_html}
        </div>

        <div style="text-align:center;padding:20px;color:#999;font-size:13px;">
            AI 解读自动化测试 - 稳定性测试报告
        </div>
    </div>
    <script>{_build_stability_html_js()}</script>
</body>
</html>"""

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n📄 稳定性测试报告已保存:")
    print(f"   执行ID: {run_id}")
    print(f"   HTML: {html_file}")
    print(f"   原始MD: {md_dir}")


MODULE_NAMES = {
    "alarm": "安全告警解读",
    "event": "安全事件解读",
    "vuln": "漏洞解读",
}


def save_combined_stability_report(all_results: Dict[str, Dict], run_id: str = None):
    """生成综合稳定性测试报告（HTML），按 run_id 归档，与各模块报告和 stability_md 对应"""
    if run_id is None:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_dir = os.path.join(os.path.dirname(__file__), "outputs", "stability_test", "stability_reports", run_id)
    os.makedirs(report_dir, exist_ok=True)

    # 聚合总体统计
    total_all = 0
    pass_all = 0
    fail_all = 0
    fail_inconsistent_all = 0
    fail_missing_all = 0
    error_all = 0

    modules_data = {}
    for mod in ["alarm", "event", "vuln"]:
        mod_result = all_results.get(mod)
        if mod_result is None:
            continue
        results = mod_result.get("results", [])
        pc = mod_result.get("pass_count", 0)
        fc = mod_result.get("fail_count", 0)
        ec = mod_result.get("error_count", 0)
        fic = mod_result.get("fail_inconsistent_count", 0)
        fmc = mod_result.get("fail_missing_count", 0)
        tc = len(results)
        total_all += tc
        pass_all += pc
        fail_all += fc
        fail_inconsistent_all += fic
        fail_missing_all += fmc
        error_all += ec
        valid_count = pc + fc
        pr = (pc / valid_count * 100) if valid_count > 0 else 0
        modules_data[mod] = {
            "module_name": MODULE_NAMES.get(mod, mod),
            "total": tc,
            "pass": pc,
            "fail": fc,
            "fail_inconsistent": fic,
            "fail_missing": fmc,
            "error": ec,
            "valid_count": valid_count,
            "pass_rate": pr,
            "results": results
        }

    overall_valid = pass_all + fail_all
    overall_pass_rate = (pass_all / overall_valid * 100) if overall_valid > 0 else 0

    # 生成 HTML 报告（固定文件名，在 run_id 目录下）
    html_file = os.path.join(report_dir, "stability_test_combined.html")

    # 概览卡片
    overview_cards = ""
    for mod in ["alarm", "event", "vuln"]:
        md = modules_data.get(mod)
        if md is None:
            continue
        card_class = "pass" if md["pass_rate"] >= 80 else "fail"
        overview_cards += f"""
        <div class="summary-card {card_class}">
            <div style="font-size:16px;font-weight:600;margin-bottom:8px;">{md['module_name']}</div>
            <div class="value">{md['pass_rate']:.1f}%</div>
            <div class="label">✅{md['pass']} / ❌不一致{md['fail_inconsistent']} / ❌缺失{md['fail_missing']} / ⚠️错误{md['error']} ｜共{md['total']}</div>
        </div>"""

    # 各模块测试用例详情
    module_sections = ""
    for mod in ["alarm", "event", "vuln"]:
        md = modules_data.get(mod)
        if md is None:
            continue
        mod_pass_rate = md["pass_rate"]
        status_icon = "✅" if mod_pass_rate >= 80 else "⚠️"
        test_cases_html = ""
        for idx, result in enumerate(md["results"]):
            test_cases_html += _build_stability_test_case_html(result, idx, mod)

        module_sections += f"""
        <div class="module-section">
            <div class="module-header">
                <div class="module-title">{status_icon} {md['module_name']} - 稳定性测试结果</div>
                <div class="module-stats">
                    <span class="stat-badge info">总数: {md['total']}</span>
                    <span class="stat-badge success">Pass: {md['pass']}</span>
                    <span class="stat-badge error">Fail: {md['fail']}</span>
                    <span class="stat-badge info">错误: {md['error']}</span>
                    <span class="stat-badge {'success' if mod_pass_rate >= 80 else 'error'}" style="font-weight:bold;">通过率: {mod_pass_rate:.1f}%</span>
                </div>
            </div>
            {test_cases_html}
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>综合稳定性测试报告</title>
    <style>{_build_stability_html_css()}</style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1>🎯 AI解读 - 综合稳定性测试报告</h1>
            <div class="header-meta">
                <span>📅 生成时间: {now_str}</span>
                <span>🗂️ 执行ID: {run_id}</span>
                <span>📋 总测试数: {total_all}</span>
                <span>✅ 总Pass: {pass_all}</span>
                <span>❌ 总Fail: {fail_all}</span>
                <span>⚠️ 执行错误: {error_all}</span>
                <span style="font-weight:bold;color:#667eea;">📊 总通过率: {overall_pass_rate:.1f}%（基于{overall_valid}个有效测试）</span>
            </div>
            <div style="margin-top:8px;font-size:12px;opacity:0.8;">
                📁 原始解读MD: stability_md/{run_id}/{{alarm|event|vuln}}/
            </div>
        </div>

        <!-- 模块概览 -->
        <div class="summary-grid">
            {overview_cards}
        </div>

        <!-- 各模块详情 -->
        {module_sections}

        <div style="text-align:center;padding:20px;color:#999;font-size:13px;">
            AI 解读自动化测试 - 综合稳定性测试报告
        </div>
    </div>
    <script>{_build_stability_html_js()}</script>
</body>
</html>"""

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n📄 综合稳定性测试报告已保存:")
    print(f"   执行ID: {run_id}")
    print(f"   HTML: {html_file}")
    print(f"   原始MD: stability_md/{run_id}/{{alarm|event|vuln}}/")
    print(f"\n{'='*70}")
    print(f"📊 综合稳定性测试统计")
    print(f"{'='*70}")
    print(f"  总测试数: {total_all}")
    print(f"  总Pass数: {pass_all}")
    print(f"  总Fail数: {fail_all}")
    print(f"  执行错误: {error_all}（不计入Pass率）")
    print(f"  有效测试: {overall_valid}")
    print(f"  总通过率: {overall_pass_rate:.1f}%")
    for mod in ["alarm", "event", "vuln"]:
        md = modules_data.get(mod)
        if md:
            print(f"  {md['module_name']}: {md['pass_rate']:.1f}% ({md['pass']}/{md['valid_count']}有效, 错误{md['error']})")
    print(f"{'='*70}")


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("\n用法:")
        print("  python3 run_stability_test.py <模块类型>")
        print("")
        print("模块类型:")
        print("  alarm  - 测试告警核心结论稳定性")
        print("  event  - 测试事件核心结论稳定性")
        print("  vuln   - 测试漏洞是否立即处置结论稳定性")
        print("  all    - 测试所有模块稳定性")
        print("")
        print("示例:")
        print("  python3 run_stability_test.py alarm")
        print("  python3 run_stability_test.py event")
        print("  python3 run_stability_test.py vuln")
        print("  python3 run_stability_test.py all")
        sys.exit(1)

    module_type = sys.argv[1].lower()
    # 生成本次执行的唯一 run_id，所有模块共用，便于 stability_md 和 HTML 报告对应
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"\n📌 本次执行ID: {run_id}")

    if module_type == "all":
        print("\n🔄 测试所有模块的稳定性...")
        all_results = {}
        all_results["alarm"] = run_stability_test("alarm", run_id=run_id)
        all_results["event"] = run_stability_test("event", run_id=run_id)
        all_results["vuln"] = run_stability_test("vuln", run_id=run_id)
        save_combined_stability_report(all_results, run_id=run_id)

        # 飞书通知（综合结果，与终端统计格式一致）
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from core.notify.feishu_notify import send_feishu_message
            mod_names = {"alarm": "安全告警解读", "event": "安全事件解读", "vuln": "漏洞解读"}
            total_pass = total_fail = total_error = total_valid = 0
            total_fic = total_fmc = 0
            mod_stats = []
            for mod in ["alarm", "event", "vuln"]:
                res = all_results.get(mod)
                if res is None:
                    continue
                pc = res.get("pass_count", 0)
                fc = res.get("fail_count", 0)
                ec = res.get("error_count", 0)
                fic = res.get("fail_inconsistent_count", 0)
                fmc = res.get("fail_missing_count", 0)
                vc = pc + fc
                pr = (pc / vc * 100) if vc > 0 else 0
                total_pass += pc; total_fail += fc; total_error += ec; total_valid += vc
                total_fic += fic; total_fmc += fmc
                # 统计AI平台异常数
                ai_pe = sum(1 for r in res.get('results', []) if r.get('is_ai_platform_error'))
                mod_stats.append((mod_names.get(mod, mod), pc, fc, ec, vc, pr, ai_pe, fic))
            overall = (total_pass / total_valid * 100) if total_valid > 0 else 0
            total_ai_platform_err = sum(s[6] for s in mod_stats)

            total_ai_call_fail = total_error - total_ai_platform_err
            total_tests = sum(len(r.get('results',[])) for r in all_results.values() if r)

            lines = [
                f"📊 稳定性测试结果统计（总{total_tests}个样本）",
                f"  总通过率: {total_pass}/{total_valid} {overall:.1f}%（有效测试）",
                f"  ├─ ✅ 通过（结论一致）: {total_pass}",
                f"  ├─ ❌ 不一致（结论变化）: {total_fic}",
                f"  └─ ⚠️ 不计入（AI平台异常）: {total_ai_platform_err}",
            ]
            if total_ai_call_fail > 0:
                lines.append(f"       + AI调用失败（超时）: {total_ai_call_fail}")
            lines.append(f"  各模块稳定性:")
            for name, pc, fc, ec, vc, pr, ai_pe, fic_mod in mod_stats:
                if vc > 0:
                    lines.append(f"  {name}: {pc}/{vc} {pr:.1f}% | ✅{pc} ❌不一致{fic_mod} ⚠️平台异常{ai_pe}")
                else:
                    lines.append(f"  {name}: N/A（全部AI平台异常{ai_pe}，无有效样本）")
            send_feishu_message("AIXDR自动化解读稳定性报告", lines)
        except Exception as e:
            print(f"[飞书通知] 发送失败: {e}")

    elif module_type in ["alarm", "event", "vuln"]:
        result = run_stability_test(module_type, run_id=run_id)

        # 飞书通知（单模块结果，与终端统计格式一致）
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from core.notify.feishu_notify import send_feishu_message
            mod_names = {"alarm": "安全告警", "event": "安全事件", "vuln": "漏洞"}
            pc = result.get("pass_count", 0)
            fc = result.get("fail_count", 0)
            ec = result.get("error_count", 0)
            fic = result.get("fail_inconsistent_count", 0)
            ai_pe = result.get("ai_platform_error_count", 0)
            ai_cf = ec - ai_pe
            vc = pc + fc
            pr = (pc / vc * 100) if vc > 0 else 0
            total = pc + fc + ec
            name = mod_names.get(module_type, module_type)
            lines = [
                f"📊 {name}稳定性测试结果（总{total}个样本）",
                f"  通过率: {pc}/{vc} {pr:.1f}%（有效测试）",
                f"  ├─ ✅ 通过（结论一致）: {pc}",
                f"  ├─ ❌ 不一致（结论变化）: {fic}",
                f"  └─ ⚠️ 不计入（AI平台异常）: {ai_pe}",
            ]
            if ai_cf > 0:
                lines.append(f"       + AI调用失败（超时）: {ai_cf}")
            send_feishu_message("AIXDR自动化解读稳定性报告", lines)
        except Exception as e:
            print(f"[飞书通知] 发送失败: {e}")

    else:
        print(f"\n❌ 不支持的模块类型: {module_type}")
        print("可用类型: alarm, event, vuln, all")
        sys.exit(1)


if __name__ == "__main__":
    main()
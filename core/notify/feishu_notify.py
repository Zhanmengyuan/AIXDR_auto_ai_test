"""
飞书通知模块
通过 Webhook 机器人发送测试结果通知（卡片消息，橙色标题）
"""
import json
import sys
import os
import requests
from typing import Dict, Any


FEISHU_WEBHOOK_URL = "https://open.feishu.cn/open-apis/bot/v2/hook/87f8185f-d92d-4ec5-8679-dd40ea0b6446"


def get_trigger_mode() -> str:
    """判断当前触发方式：手动 or 自动（cron）

    判断依据：
    - sys.stdin.isatty()：终端交互式执行为 True，cron 后台执行为 False
    - 也检查 TERM 环境变量作为辅助
    """
    try:
        is_tty = sys.stdin.isatty()
    except Exception:
        is_tty = False

    has_term = bool(os.environ.get("TERM") or os.environ.get("TERM_PROGRAM"))

    if is_tty or has_term:
        return "🖐️ 手动执行"
    else:
        return "🤖 自动执行(cron)"


def send_feishu_message(title: str, content_lines: list) -> bool:
    """发送飞书卡片消息（橙色加粗标题）

    Args:
        title: 消息标题（显示为橙色标题栏）
        content_lines: 内容行列表

    Returns:
        是否发送成功
    """
    trigger = get_trigger_mode()

    # 将内容行转为 lark_md 格式（每行一个 div 元素）
    # 以 📊/🔍/📈/📋 开头的行视为小标题，加粗显示
    elements = []
    for line in content_lines:
        is_subheading = any(line.strip().startswith(prefix) for prefix in ["📊", "🔍", "📈", "📋", "📁"])
        if is_subheading:
            text = f"**{line}**"
        else:
            text = line
        elements.append({
            "tag": "div",
            "text": {"tag": "lark_md", "content": text}
        })

    # 触发方式放在第一个元素
    elements.insert(0, {
        "tag": "div",
        "text": {"tag": "lark_md", "content": f"**触发方式:** {trigger}"}
    })

    # 加一条分割线
    elements.insert(1, {"tag": "hr"})

    payload = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": title
                },
                "template": "orange"
            },
            "elements": elements
        }
    }

    try:
        resp = requests.post(FEISHU_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("StatusCode") == 0 or result.get("code") == 0:
                print(f"[飞书] ✅ 通知发送成功: {title}")
                return True
            else:
                print(f"[飞书] ❌ 通知发送失败: {result}")
                return False
        else:
            print(f"[飞书] ❌ HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"[飞书] ❌ 通知异常: {e}")
        return False


def send_test_result_notify(module_name: str, exit_code: int, log_file: str, duration: str = "") -> bool:
    """发送测试结果通知

    Args:
        module_name: 模块名称（如"全模块解读测试"）
        exit_code: 退出码（0=成功）
        log_file: 日志文件路径
        duration: 执行耗时描述
    """
    status = "✅ 成功" if exit_code == 0 else "❌ 失败"

    lines = [
        f"模块: {module_name}",
        f"状态: {status} (exit={exit_code})",
    ]
    if duration:
        lines.append(f"耗时: {duration}")
    lines.append(f"日志: {log_file}")

    return send_feishu_message("AIXDR自动化测试", lines)


def send_summary_notify(stats: Dict[str, Any]) -> bool:
    """发送汇总通知（从测试报告中提取关键指标）

    Args:
        stats: 包含各模块统计信息的字典
    """
    lines = []
    for module, data in stats.items():
        total = data.get("total", 0)
        valid = data.get("valid", 0)
        failed = data.get("failed", 0)
        invalid = data.get("invalid", 0)
        lines.append(f"📊 {module}: 总{total} | 有效{valid} | 失败{failed} | 失效{invalid}")

    return send_feishu_message("AIXDR自动化测试汇总", lines)

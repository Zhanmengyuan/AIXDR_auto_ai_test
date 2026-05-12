import requests
import urllib3
import json
import os
import sys
import yaml
from datetime import datetime

# 关闭SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== 从配置文件加载 =====================
def load_config():
    """加载配置文件"""
    config_path = os.path.join(os.path.dirname(__file__), "config", "config_api.yaml")
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

config = load_config()

# AI接口专用配置
AI_CONFIG = {
    "base_url": "https://10.21.19.99:8686",
    "sse_endpoint": "/maxs/szr/chat/connect",
    "chat_endpoint": "/maxs/szr/chat"
}

# 从配置文件加载Headers
headers = config.get('headers', {})
headers['Cookie'] = config.get('cookie', '')
COMMON_HEADERS = headers

SESSION_ID = "-1@" + datetime.now().strftime("%Y%m%d%H%M%S") + "-0000-000000000000"

BASE_URL = AI_CONFIG["base_url"]
# ==================================================================

# 初始化变量
raw_text = ""
stream_completed = False

try:
    # --------------------------
    # 步骤1：先调用connect建立SSE连接
    # --------------------------
    print("步骤1：建立SSE连接...")
    connect_url = f"{BASE_URL}/maxs/szr/chat/connect"
    connect_params = {"sessionId": SESSION_ID}

    # 先发起GET请求建立连接（注意：这里会一直挂着，所以我们用线程处理，避免阻塞）
    import threading
    def listen_sse():
        global raw_text, stream_completed
        try:
            with requests.get(
                connect_url,
                params=connect_params,
                headers={**COMMON_HEADERS, "Accept": "text/event-stream"},
                stream=True,
                verify=False,
                timeout=300
            ) as resp:
                print(f"连接建立成功，状态码：{resp.status_code}")
                for line in resp.iter_lines():
                    if not line:
                        continue
                    # 手动解码，避免decode_unicode的自动推断问题
                    try:
                        line_str = line.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            line_str = line.decode('gbk')
                        except:
                            line_str = line.decode('latin-1', errors='replace')
                    print(f"[SSE] {line_str[:200]}")  # 调试：打印所有SSE行
                    # 处理 data: 或 data: 开头的数据（兼容有无空格）
                    if line_str.startswith("data:") or line_str.startswith("data :"):
                        data_str = line_str.lstrip().replace("data:", "").replace("data :", "").strip()
                        if data_str == "[DONE]":
                            print("\n流结束")
                            stream_completed = True
                            break
                        try:
                            json_data = json.loads(data_str)
                            code = json_data.get("code")
                            answer_type = json_data.get("answerType")
                            chunk = json_data.get("data", "")
                            print(f"[DEBUG] code={repr(code)}, answer_type={repr(answer_type)}, chunk={repr(chunk[:30])}")
                            if str(code) == "200" and str(answer_type) == "text":
                                print(f"[拼接] {chunk}", end="", flush=True)
                                raw_text += chunk
                            else:
                                print(f"[跳过] code={code}, answer_type={answer_type}")
                        except json.JSONDecodeError as e:
                            print(f"[JSON解析失败] {e}, data={data_str[:100]}")
                            continue
        except Exception as e:
            print(f"SSE连接异常: {e}")

    # 启动线程监听SSE流
    sse_thread = threading.Thread(target=listen_sse, daemon=True)
    sse_thread.start()

    # --------------------------
    # 步骤2：调用chat接口发送问题，触发流式回答
    # --------------------------
    print("\n步骤2：发送提问请求...")
    chat_url = f"{BASE_URL}/maxs/szr/chat/chat"

    # 从配置文件读取测试资产ID
    test_asset_id = config.get('test_assets', ['2035435203429482500'])[0]
    print(f"📋 使用资产ID: {test_asset_id}")

    chat_payload = {
        "question": f"请为我调查这个资产,资产ID: {test_asset_id}",
        "agent": "asset",
        "bizId": test_asset_id,
        "bizType": 4,
        "fileId": [],
        "network": False,
        "recommend": False,
        "sessionId": SESSION_ID,
        "tag": "id"
    }

    chat_resp = requests.post(
        chat_url,
        headers=COMMON_HEADERS,
        json=chat_payload,
        verify=False,
        timeout=30
    )
    print(f"chat接口响应状态码：{chat_resp.status_code}")
    if chat_resp.status_code != 200:
        print(f"chat接口返回错误：{chat_resp.text}")
        exit(1)

    # 等待SSE流接收完成（增加超时时间）
    sse_thread.join(timeout=300)  # 等待5分钟

except Exception as e:
    print(f"\n执行出错：{str(e)}")

# 最终结果
print("\n\n✅ 流程执行完成！")
print("=" * 60)
print(f"流式接收状态: {'✅ 正常结束' if stream_completed else '⚠️ 被中断'}")
print(f"raw_text长度: {len(raw_text)} 字符")
print("=" * 60)
if not stream_completed:
    print("⚠️ 警告: 流式数据可能被截断，建议增加超时时间")
print("=" * 60)


def parse_asset_report(text: str) -> dict:
    """从AI响应文本中提取资产解读关键字段
    对应评价指标：
    1. 风险等级准确率
    2. 资产风险评分准确率
    3. 资产关键字完整率
    支持普通文本和表格格式
    """
    import re

    parsed = {
        "risk_level": None,
        "risk_score": None,
        "asset_id": None,
        "ip_address": None,
        "mac_address": None,
        "hostname": None,
        "asset_type": None,
        "cve_list": None,  # CVE编号列表
        "vuln_list": None,  # 漏洞ID列表 (AVE-xxx格式)
        "alert_list": None,  # 告警ID列表 (纯数字格式)
        "os_name": None,
        "asset_level": None,
        "asset_status_name": None,
        "last_online_time": None,
        "organization": None,
        "is_exposed": None,
        "missing_fields": []
    }

    if not text:
        parsed["missing_fields"] = list(parsed.keys())[:-1]
        return parsed

    # 表格格式字段提取（如 | **资产ID** | 2035435203429482500 |）
    table_patterns = {
        "asset_id": r'\|\s*[*]*\s*资产ID[*]*\s*\|\s*([^\s|]+)\s*\|',
        "ip_address": r'\|\s*[*]*\s*IP地址[*]*\s*\|\s*([^\s|]+)\s*\|',
        "mac_address": r'\|\s*[*]*\s*MAC地址[*]*\s*\|\s*([^\s|]+)\s*\|',
        "hostname": r'\|\s*[*]*\s*主机名[*]*\s*\|\s*([^\s|]+)\s*\|',
        "asset_type": r'\|\s*[*]*\s*资产类型[*]*\s*\|\s*([^\s|]+)\s*\|',
        "os_name": r'\|\s*[*]*\s*操作系统[*]*\s*\|\s*([^\|]+)\s*\|',
        "asset_level": r'\|\s*[*]*\s*资产等级[*]*\s*\|\s*([^\s|]+)\s*\|',
        "asset_status_name": r'\|\s*[*]*\s*资产状态[*]*\s*\|\s*([^\s|]+)\s*\|',
        "risk_level": r'\|\s*[*]*\s*资产风险等级[*]*\s*\|\s*([^\|]+)\s*\|',
        "risk_score": r'\|\s*[*]*\s*资产评分[*]*\s*\|\s*(\d+)\s*\|',
        "last_online_time": r'\|\s*[*]*\s*最后上线时间[*]*\s*\|\s*([^\|]+)\s*\|',
        "organization": r'\|\s*[*]*\s*所属组织[*]*\s*\|\s*([^\s|]+)\s*\|',
        "is_exposed": r'\|\s*[*]*\s*是否暴露面[*]*\s*\|\s*([^\s|]+)\s*\|'
    }

    for field, pattern in table_patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            if field == "risk_score":
                parsed[field] = int(value) if value.isdigit() else value
            else:
                parsed[field] = value

    # 普通文本格式字段提取（兜底）
    if not parsed.get("risk_level"):
        risk_level_patterns = [
            r'\*\*风险等级[：:]\*\*\s*([^\n*]+)',
            r'风险等级[：:]\s*([^\n,，。}]+)',
            r'风险[：:]?\s*(高危|中危|低危|严重)',
            r'风险级别[：:]\s*([^\n,，。}]+)'
        ]
        for pattern in risk_level_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["risk_level"] = match.group(1).strip()
                break

    if not parsed.get("risk_score"):
        score_match = re.search(r'(?:风险评分|资产评分|风险分)[：:]\s*(\d+)', text)
        if score_match:
            parsed["risk_score"] = int(score_match.group(1))
        else:
            score_match2 = re.search(r'[评分|风险分][：:\s]*(\d+)（严重|高危|中危|低危）', text)
            if score_match2:
                parsed["risk_score"] = int(score_match2.group(1))

    if not parsed.get("asset_id"):
        asset_id_patterns = [
            r'资产ID[：:]\s*([A-Z0-9_]+)',
            r'资产[Ii][Dd][：:]\s*([A-Z0-9_]+)',
        ]
        for pattern in asset_id_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["asset_id"] = match.group(1).strip()
                break

    if not parsed.get("ip_address"):
        ip_patterns = [
            r'IP(?:地址)?[：:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'IP地址[：:]\s*([^\n,，}]+)',
        ]
        for pattern in ip_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["ip_address"] = match.group(1).strip()
                break

    if not parsed.get("hostname"):
        hostname_patterns = [
            r'主机名[：:]\s*([^\n,，}]+)',
            r'主机名称[：:]\s*([^\n,，}]+)',
        ]
        for pattern in hostname_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["hostname"] = match.group(1).strip()
                break

    if not parsed.get("asset_type"):
        asset_type_patterns = [
            r'资产类型[：:]\s*([^\n,，}]+)',
            r'类型[：:]\s*([^\n,，}]+)',
        ]
        for pattern in asset_type_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["asset_type"] = match.group(1).strip()
                break

    if not parsed.get("os_name"):
        os_patterns = [
            r'(?:操作系统|OS)[：:]\s*([^\n,，}]+)',
        ]
        for pattern in os_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["os_name"] = match.group(1).strip()
                break

    if not parsed.get("asset_level"):
        asset_level_patterns = [
            r'资产等级[：:]\s*([^\n,，}]+)',
            r'重要程度[：:]\s*([^\n,，}]+)',
        ]
        for pattern in asset_level_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["asset_level"] = match.group(1).strip()
                break

    if not parsed.get("asset_status_name"):
        status_patterns = [
            r'资产状态[：:]\s*([^\n,，}]+)',
            r'状态[：:]\s*(在线|离线|禁用|异常|正常)',
        ]
        for pattern in status_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["asset_status_name"] = match.group(1).strip()
                break

    if not parsed.get("last_online_time"):
        last_online_patterns = [
            r'最后?[\s-]*(?:上线|登录|访问)[时时间]+[：:]\s*([^\n,，}]+)',
            r'(?:最后上线|最后登录|最近上线)[时时间]*[：:]\s*([^\n,，}]+)',
        ]
        for pattern in last_online_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["last_online_time"] = match.group(1).strip()
                break

    if not parsed.get("mac_address"):
        mac_patterns = [
            r'MAC(?:地址)?[：:]\s*([0-9A-Fa-f:]{17}|[0-9A-Fa-f-]{17})',
            r'(?:物理地址|MAC)[：:]\s*([^\n,，}]+)',
        ]
        for pattern in mac_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["mac_address"] = match.group(1).strip()
                break

    if not parsed.get("organization"):
        org_patterns = [
            r'所属组织[：:]\s*([^\n,，}]+)',
            r'组织[：:]\s*([^\n,，}]+)',
        ]
        for pattern in org_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["organization"] = match.group(1).strip()
                break

    if not parsed.get("is_exposed"):
        exposed_patterns = [
            r'是否暴露面[：:]\s*([^\n,，}]+)',
            r'暴露面[：:]\s*([^\n,，}]+)',
        ]
        for pattern in exposed_patterns:
            match = re.search(pattern, text)
            if match:
                parsed["is_exposed"] = match.group(1).strip()
                break

    # 提取CVE编号列表
    cve_pattern = r'CVE[-\s]?(\d{4})[-\s]?(\d{4,})'
    cve_matches = re.findall(cve_pattern, text, re.IGNORECASE)
    if cve_matches:
        cve_list = [f"CVE-{m[0]}-{m[1]}" for m in cve_matches]
        parsed["cve_list"] = list(set(cve_list))
        print(f"🔧 提取到CVE列表: {parsed['cve_list']}")

    # 提取漏洞ID列表 (AVE-xxx格式)
    vuln_pattern = r'AVE[-\s]?(\d{4})[-\s]?(\d+)'
    vuln_matches = re.findall(vuln_pattern, text, re.IGNORECASE)
    if vuln_matches:
        vuln_list = [f"AVE-{m[0]}-{m[1]}" for m in vuln_matches]
        parsed["vuln_list"] = list(set(vuln_list))
        print(f"🔧 提取到漏洞ID列表: {parsed['vuln_list']}")

    # 提取告警ID列表 (纯数字格式)
    # 直接用章节标题作为边界
    alert_start = text.find('## 4、关联告警分析')
    alert_end = text.find('## 5、关联事件分析')
    if alert_start >= 0 and alert_end > alert_start:
        alert_text = text[alert_start:alert_end]
        alert_id_pattern = r'\|\s*(\d{13,})\s*\|'
        alert_matches = re.findall(alert_id_pattern, alert_text)
        if alert_matches:
            parsed["alert_list"] = list(set(alert_matches))
            print(f"🔧 提取到告警ID列表: {parsed['alert_list']}")

    # 提取事件ID列表 (纯数字格式)
    # 直接用章节标题作为边界
    event_start = text.find('## 5、关联事件分析')
    event_end = text.find('## 6、修复建议') if text.find('## 6、修复建议') > 0 else len(text)
    if event_start >= 0 and event_end > event_start:
        event_text = text[event_start:event_end]
        event_id_pattern = r'\|\s*(\d{13,})\s*\|'
        event_matches = re.findall(event_id_pattern, event_text)
        if event_matches:
            parsed["event_list"] = list(set(event_matches))
            print(f"🔧 提取到事件ID列表: {parsed['event_list']}")

    required_fields = ["risk_level", "risk_score"]
    complete_fields = ["asset_id", "ip_address", "mac_address", "hostname", "asset_type", "os_name", "asset_level", "organization", "is_exposed", "last_online_time"]

    for field in required_fields:
        if not parsed.get(field):
            if field not in parsed["missing_fields"]:
                parsed["missing_fields"].append(field)

    for field in complete_fields:
        if not parsed.get(field):
            if field not in parsed["missing_fields"]:
                parsed["missing_fields"].append(field)

    return parsed


# 保存为Markdown文档
if raw_text:
    asset_id = chat_payload.get("bizId", "unknown")

    # 输出目录
    output_dir = os.path.join(os.path.dirname(__file__), "outputs")
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, f"asset_report_{asset_id}.md")

    # 解析结构化字段
    parsed_data = parse_asset_report(raw_text)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# AI 智能体响应 - 资产分析报告\n\n")
        f.write(f"**资产ID**: {asset_id}\n\n")
        f.write(f"**会话ID**: {SESSION_ID}\n\n")
        f.write(f"**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        f.write(raw_text)
    print(f"\n📄 Markdown已保存到: {output_file}")

    # 保存结构化数据为JSON
    json_file = os.path.join(output_dir, f"asset_data_{asset_id}.json")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({
            "asset_id": asset_id,
            "session_id": SESSION_ID,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "parsed_fields": parsed_data
        }, f, ensure_ascii=False, indent=2)
    print(f"📊 结构化数据已保存到: {json_file}")

    # 打印提取的关键字段
    print("\n" + "=" * 60)
    print("📋 提取的资产关键字段：")
    print("=" * 60)
    print(f"资产ID: {parsed_data.get('asset_id') or '❌ 未识别'}")
    print(f"IP地址: {parsed_data.get('ip_address') or '❌ 未识别'}")
    print(f"MAC地址: {parsed_data.get('mac_address') or '❌ 未识别'}")
    print(f"主机名: {parsed_data.get('hostname') or '❌ 未识别'}")
    print(f"资产类型: {parsed_data.get('asset_type') or '❌ 未识别'}")
    print(f"操作系统: {parsed_data.get('os_name') or '❌ 未识别'}")
    print(f"资产等级: {parsed_data.get('asset_level') or '❌ 未识别'}")
    print(f"所属组织: {parsed_data.get('organization') or '❌ 未识别'}")
    print(f"是否暴露面: {parsed_data.get('is_exposed') or '❌ 未识别'}")
    print(f"最后上线时间: {parsed_data.get('last_online_time') or '❌ 未识别'}")
    print("-" * 60)
    print(f"✅ 风险等级: {parsed_data.get('risk_level') or '❌ 未识别'}")
    print(f"✅ 风险评分: {parsed_data.get('risk_score') or '❌ 未识别'}")
    print("=" * 60)

    # 计算指标得分
    print("\n📊 指标得分计算：")
    print("-" * 60)

    # 1. 风险等级准确率 (满分10分)
    if parsed_data.get('risk_level'):
        print(f"✅ 风险等级准确率: 10/10 (已识别)")
    else:
        print(f"❌ 风险等级准确率: 0/10 (未识别)")

    # 2. 资产风险评分准确率 (满分10分)
    if parsed_data.get('risk_score') is not None:
        print(f"✅ 资产风险评分准确率: 10/10 (已识别)")
    else:
        print(f"❌ 资产风险评分准确率: 0/10 (未识别)")

    # 3. 资产关键字完整率 (满分10分，共10个字段)
    complete_fields_count = sum([
        1 if parsed_data.get('asset_id') else 0,
        1 if parsed_data.get('ip_address') else 0,
        1 if parsed_data.get('hostname') else 0,
        1 if parsed_data.get('asset_type') else 0,
        1 if parsed_data.get('os_name') else 0,
        1 if parsed_data.get('asset_level') else 0,
        1 if parsed_data.get('risk_level') else 0,
        1 if parsed_data.get('risk_score') is not None else 0,
        1 if parsed_data.get('last_online_time') else 0,
        1 if parsed_data.get('asset_status_name') else 0
    ])
    completeness_score = (complete_fields_count / 10) * 10
    print(f"📝 资产关键字完整率: {complete_fields_count}/10 ({completeness_score:.1f}/10)")

    total_score = 0
    if parsed_data.get('risk_level'):
        total_score += 10
    if parsed_data.get('risk_score') is not None:
        total_score += 10
    total_score += completeness_score

    print("-" * 60)
    print(f"🎯 综合得分: {total_score:.1f}/30")
    print("=" * 60)

    print("\n💡 提示：可单独运行 fetch_asset_api.py 进行API数据获取和对比")

else:
    print("\n⚠️ 没有内容需要保存")
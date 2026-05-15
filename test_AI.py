import requests
import urllib3
import json
import os
import sys
import re
import yaml
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config", "config_api.yaml")
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

config = load_config()

AI_CONFIG = {
    "base_url": "https://10.21.19.99:8686",
    "sse_endpoint": "/maxs/szr/chat/connect",
    "chat_endpoint": "/maxs/szr/chat"
}

headers = config.get('headers', {})
headers['Cookie'] = config.get('cookie', '')
COMMON_HEADERS = headers

SESSION_ID = "-1@" + datetime.now().strftime("%Y%m%d%H%M%S") + "-0000-000000000000"

BASE_URL = AI_CONFIG["base_url"]

raw_text = ""
stream_completed = False

try:
    print("步骤1：建立SSE连接...")
    connect_url = f"{BASE_URL}/maxs/szr/chat/connect"
    connect_params = {"sessionId": SESSION_ID}

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
                    try:
                        line_str = line.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            line_str = line.decode('gbk')
                        except:
                            line_str = line.decode('latin-1', errors='replace')
                    print(f"[SSE] {line_str[:200]}")
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

    sse_thread = threading.Thread(target=listen_sse, daemon=True)
    sse_thread.start()

    print("\n步骤2：发送提问请求...")
    chat_url = f"{BASE_URL}/maxs/szr/chat/chat"

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

    sse_thread.join(timeout=300)

except Exception as e:
    print(f"\n执行出错：{str(e)}")

print("\n\n✅ 流程执行完成！")
print("=" * 60)
print(f"流式接收状态: {'✅ 正常结束' if stream_completed else '⚠️ 被中断'}")
print(f"raw_text长度: {len(raw_text)} 字符")
print("=" * 60)
if not stream_completed:
    print("⚠️ 警告: 流式数据可能被截断，建议增加超时时间")
print("=" * 60)


def parse_asset_report(text):
    """从AI响应文本中提取资产解读关键字段"""
    parsed = {
        "risk_level": None,
        "risk_score": None,
        "asset_id": None,
        "ip_address": None,
        "mac_address": None,
        "hostname": None,
        "asset_type": None,
        "cve_list": None,
        "vuln_list": None,
        "alert_list": None,
        "os_name": None,
        "asset_level": None,
        "asset_status_name": None,
        "last_online_time": None,
        "organization": None,
        "is_exposed": None,
        "missing_fields": []
    }

    if not text:
        parsed["missing_fields"] = [k for k in parsed if k != "missing_fields"]
        return parsed

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

    if not parsed.get("risk_level"):
        table_risk_patterns = [
            r'\|\s*[*]*\s*资产风险等级[*]*\s*\|\s*([^\|]+)\s*\|',
            r'\|\s*[*]*\s*风险等级[*]*\s*\|\s*([^\|]+)\s*\|',
        ]
        for pattern in table_risk_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["risk_level"] = match.group(1).strip()
                break

    if not parsed.get("risk_level"):
        risk_level_patterns = [
            r'(?:资产风险等级|风险等级|风险级别)[：:为]?\s*\*{0,2}(严重|高危|中危|低危)',
            r'风险[：:]\s*(严重|高危|中危|低危)',
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

    if not parsed.get("asset_id"):
        for pattern in [r'资产ID[：:]\s*([A-Z0-9_]+)', r'资产[Ii][Dd][：:]\s*([A-Z0-9_]+)']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["asset_id"] = match.group(1).strip()
                break

    if not parsed.get("ip_address"):
        for pattern in [r'IP(?:地址)?[：:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r'IP地址[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["ip_address"] = match.group(1).strip()
                break

    if not parsed.get("hostname"):
        for pattern in [r'主机名[：:]\s*([^\n,，}]+)', r'主机名称[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["hostname"] = match.group(1).strip()
                break

    if not parsed.get("asset_type"):
        for pattern in [r'资产类型[：:]\s*([^\n,，}]+)', r'类型[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text)
            if match:
                parsed["asset_type"] = match.group(1).strip()
                break

    if not parsed.get("os_name"):
        match = re.search(r'(?:操作系统|OS)[：:]\s*([^\n,，}]+)', text, re.IGNORECASE)
        if match:
            parsed["os_name"] = match.group(1).strip()

    if not parsed.get("asset_level"):
        for pattern in [r'资产等级[：:]\s*([^\n,，}]+)', r'重要程度[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text)
            if match:
                parsed["asset_level"] = match.group(1).strip()
                break

    if not parsed.get("asset_status_name"):
        match = re.search(r'资产状态[：:]\s*([^\n,，}]+)', text)
        if match:
            parsed["asset_status_name"] = match.group(1).strip()

    if not parsed.get("last_online_time"):
        for pattern in [r'最后?[\s-]*(?:上线|登录|访问)[时时间]+[：:]\s*([^\n,，}]+)', r'(?:最后上线|最后登录|最近上线)[时时间]*[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text)
            if match:
                parsed["last_online_time"] = match.group(1).strip()
                break

    if not parsed.get("mac_address"):
        for pattern in [r'MAC(?:地址)?[：:]\s*([0-9A-Fa-f:]{17}|[0-9A-Fa-f-]{17})', r'(?:物理地址|MAC)[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                parsed["mac_address"] = match.group(1).strip()
                break

    if not parsed.get("organization"):
        for pattern in [r'所属组织[：:]\s*([^\n,，}]+)', r'组织[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text)
            if match:
                parsed["organization"] = match.group(1).strip()
                break

    if not parsed.get("is_exposed"):
        for pattern in [r'是否暴露面[：:]\s*([^\n,，}]+)', r'暴露面[：:]\s*([^\n,，}]+)']:
            match = re.search(pattern, text)
            if match:
                parsed["is_exposed"] = match.group(1).strip()
                break

    cve_pattern = r'CVE[-\s]?(\d{4})[-\s]?(\d{4,})'
    cve_matches = re.findall(cve_pattern, text, re.IGNORECASE)
    if cve_matches:
        parsed["cve_list"] = list(set([f"CVE-{m[0]}-{m[1]}" for m in cve_matches]))

    vuln_pattern = r'AVE[-\s]?(\d{4})[-\s]?(\d+)'
    vuln_matches = re.findall(vuln_pattern, text, re.IGNORECASE)
    if vuln_matches:
        parsed["vuln_list"] = list(set([f"AVE-{m[0]}-{m[1]}" for m in vuln_matches]))

    alert_start = text.find('## 4、关联告警分析')
    alert_end = text.find('## 5、关联事件分析')
    if alert_start >= 0 and alert_end > alert_start:
        alert_text = text[alert_start:alert_end]
        alert_matches = re.findall(r'\|\s*(\d{13,})\s*\|', alert_text)
        if alert_matches:
            parsed["alert_list"] = list(set(alert_matches))

    event_start = text.find('## 5、关联事件分析')
    event_end = text.find('## 6、修复建议') if text.find('## 6、修复建议') > 0 else len(text)
    if event_start >= 0 and event_end > event_start:
        event_text = text[event_start:event_end]
        event_matches = re.findall(r'\|\s*(\d{13,})\s*\|', event_text)
        if event_matches:
            parsed["event_list"] = list(set(event_matches))

    required_fields = ["risk_level", "risk_score"]
    complete_fields = ["asset_id", "ip_address", "mac_address", "hostname", "asset_type", "os_name", "asset_level", "organization", "is_exposed", "last_online_time"]
    for field in required_fields + complete_fields:
        if not parsed.get(field):
            if field not in parsed["missing_fields"]:
                parsed["missing_fields"].append(field)

    return parsed


if raw_text:
    asset_id = chat_payload.get("bizId", "unknown")

    project_root = os.path.dirname(__file__)
    outputs_dir = os.path.join(project_root, "outputs")

    md_dir = os.path.join(outputs_dir, "raw_md")
    json_dir = os.path.join(outputs_dir, "raw_json")

    os.makedirs(md_dir, exist_ok=True)
    os.makedirs(json_dir, exist_ok=True)

    md_file = os.path.join(md_dir, f"asset_report_{asset_id}.md")
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write("# AI 智能体响应 - 资产分析报告\n\n")
        f.write(f"**资产ID**: {asset_id}\n\n")
        f.write(f"**会话ID**: {SESSION_ID}\n\n")
        f.write(f"**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        f.write(raw_text)
    print(f"\n📄 Markdown已保存到: {md_file}")

    parsed_data = parse_asset_report(raw_text)

    json_file = os.path.join(json_dir, f"asset_data_{asset_id}.json")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({
            "asset_id": asset_id,
            "session_id": SESSION_ID,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "raw_text_length": len(raw_text),
            "parsed_fields": parsed_data
        }, f, ensure_ascii=False, indent=2)
    print(f"📊 结构化数据已保存到: {json_file}")

    print("\n💡 提示：可运行 tests/test_asset_metrics.py 进行指标评测")

else:
    print("\n⚠️ 没有内容需要保存")


"""
批量生成AI资产解读 & 多资产综合评测
============================================

1. 为配置文件中的所有资产ID生成AI解析结果
2. 自动记录每个资产的首包响应时间和总响应时间
3. 获取API标准数据计算风险等级宏平均F1
4. 生成综合评测报告
"""
import sys
import os
import time
import requests
import urllib3
import threading
import json
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

sys.path.insert(0, os.path.dirname(__file__))
from core.config_loader import ConfigLoader
from core.extractors import AIExtractor
from core.api_clients import AssetAPIClient
from core.calculators import RiskLevelCalculator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def call_ai_and_measure(asset_id: str, config: ConfigLoader, headers: Dict[str, str]) -> Dict[str, Any]:
    """调用AI接口获取资产解读数据，同时测量响应时间

    Returns:
        {
            "success": bool,
            "raw_text": str,
            "parsed_fields": dict,
            "first_packet_time": float,
            "total_time": float,
            "error": str
        }
    """
    base_url = config.base_url
    session_id = f"-1@{datetime.now().strftime('%Y%m%d%H%M%S')}-{asset_id[-8:]}"

    connect_url = f"{base_url}/maxs/szr/chat/connect"
    chat_url = f"{base_url}/maxs/szr/chat/chat"

    raw_text = ""
    stream_completed = False
    first_packet_time = None
    total_time = None
    start_time = time.time()

    def listen_sse():
        nonlocal raw_text, stream_completed, first_packet_time, total_time
        try:
            with requests.get(
                connect_url,
                params={"sessionId": session_id},
                headers={**headers, "Accept": "text/event-stream"},
                stream=True,
                verify=False,
                timeout=300
            ) as resp:
                for line in resp.iter_lines():
                    elapsed = time.time() - start_time

                    if first_packet_time is None and line:
                        first_packet_time = elapsed

                    if not line:
                        continue
                    try:
                        line_str = line.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            line_str = line.decode('gbk')
                        except:
                            line_str = line.decode('latin-1', errors='replace')

                    if line_str.startswith("data:") or line_str.startswith("data :"):
                        data_str = line_str.lstrip().replace("data:", "").replace("data :", "").strip()
                        if data_str == "[DONE]":
                            stream_completed = True
                            total_time = time.time() - start_time
                            return
                        try:
                            json_data = json.loads(data_str)
                            code = json_data.get("code")
                            answer_type = json_data.get("answerType")
                            chunk = json_data.get("data", "")
                            if str(code) == "200" and str(answer_type) == "text":
                                raw_text += chunk
                        except:
                            continue
        except Exception as e:
            print(f"  [SSE异常] {e}")

    sse_thread = threading.Thread(target=listen_sse, daemon=True)
    sse_thread.start()

    try:
        chat_payload = {
            "question": f"请为我调查这个资产,资产ID: {asset_id}",
            "agent": "asset",
            "bizId": asset_id,
            "bizType": 4,
            "fileId": [],
            "network": False,
            "recommend": False,
            "sessionId": session_id,
            "tag": "id"
        }

        resp = requests.post(
            chat_url,
            headers=headers,
            json=chat_payload,
            verify=False,
            timeout=30
        )
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    sse_thread.join(timeout=300)

    if not raw_text:
        return {"success": False, "error": "无AI响应内容"}

    if total_time is None:
        total_time = time.time() - start_time

    extractor = AIExtractor()
    parsed_fields = extractor.extract_from_markdown(raw_text)

    return {
        "success": True,
        "raw_text": raw_text,
        "parsed_fields": parsed_fields,
        "first_packet_time": first_packet_time or 0,
        "total_time": total_time or 0,
        "session_id": session_id
    }


def measure_timing_only(asset_id: str, config: ConfigLoader, headers: Dict[str, str]) -> Dict[str, float]:
    """仅测量资产的响应时间（不保存结果）

    Returns:
        {"first_packet_time": float, "total_time": float}
    """
    result = call_ai_and_measure(asset_id, config, headers)
    return {
        "first_packet_time": result.get("first_packet_time", 0),
        "total_time": result.get("total_time", 0)
    }


def save_results(asset_id: str, raw_text: str, parsed_fields: Dict[str, Any]) -> None:
    """保存解析结果到文件"""
    output_dir = os.path.join(os.path.dirname(__file__), "outputs")
    md_dir = os.path.join(output_dir, "raw_md")
    json_dir = os.path.join(output_dir, "raw_json")

    os.makedirs(md_dir, exist_ok=True)
    os.makedirs(json_dir, exist_ok=True)

    md_file = os.path.join(md_dir, f"asset_report_{asset_id}.md")
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write("# AI 智能体响应 - 资产分析报告\n\n")
        f.write(f"**资产ID**: {asset_id}\n\n")
        f.write(f"**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        f.write(raw_text)

    json_file = os.path.join(json_dir, f"asset_data_{asset_id}.json")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({
            "asset_id": asset_id,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "parsed_fields": parsed_fields
        }, f, ensure_ascii=False, indent=2)


def generate_report(
    asset_ids: List[str],
    timing_results: Dict[str, Dict[str, float]],
    risk_level_f1_result: Any,
    success_count: int,
    failed_list: List[Tuple[str, str]]
) -> Dict[str, Any]:
    """生成多资产综合评测报告"""
    first_packet_times = []
    total_times = []

    for asset_id in asset_ids:
        if asset_id in timing_results and timing_results[asset_id]["total_time"] > 0:
            first_packet_times.append(timing_results[asset_id]["first_packet_time"])
            total_times.append(timing_results[asset_id]["total_time"])

    avg_first_packet = sum(first_packet_times) / len(first_packet_times) if first_packet_times else 0
    avg_total = sum(total_times) / len(total_times) if total_times else 0

    report = {
        "report_title": "多资产综合评测报告",
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "total_assets": len(asset_ids),
        "successful_count": success_count,
        "failed_count": len(failed_list),
        "asset_ids": asset_ids,
        "failed_assets": [{"asset_id": a, "error": e} for a, e in failed_list],
        "timing_metrics": {
            "first_packet_times": first_packet_times,
            "total_times": total_times,
            "avg_first_packet_time": round(avg_first_packet, 2),
            "avg_total_time": round(avg_total, 2),
            "first_packet_score": 5.0 if avg_first_packet < 3 else (4.0 if avg_first_packet < 5 else 3.0),
            "first_packet_threshold": "<3秒",
            "total_time_score": 5.0 if avg_total < 30 else (4.0 if avg_total < 60 else 3.0),
            "total_time_threshold": "<30秒"
        },
        "risk_level_metrics": None,
        "summary": None
    }

    if risk_level_f1_result is not None:
        report["risk_level_metrics"] = {
            "macro_f1": round(risk_level_f1_result.accuracy, 4),
            "expected_f1": risk_level_f1_result.detail.get("expected_f1", 0.95),
            "score": round(risk_level_f1_result.score, 1),
            "max_score": risk_level_f1_result.max_score,
            "is_passed": risk_level_f1_result.is_passed,
            "total_samples": risk_level_f1_result.detail.get("total_samples", 0),
            "detail_comparison": [
                {
                    "asset_id": asset_ids[i] if i < len(asset_ids) else "unknown",
                    "ai_risk": risk_level_f1_result.detail["ai_risks"][i] if i < len(risk_level_f1_result.detail["ai_risks"]) else None,
                    "api_risk": risk_level_f1_result.detail["api_risks"][i] if i < len(risk_level_f1_result.detail["api_risks"]) else None,
                    "match": risk_level_f1_result.detail["y_true"][i] == risk_level_f1_result.detail["y_pred"][i] if i < len(risk_level_f1_result.detail["y_true"]) else False
                }
                for i in range(risk_level_f1_result.detail.get("total_samples", 0))
            ]
        }

    report["summary"] = {
        "first_packet_time": f"{avg_first_packet:.2f}秒",
        "avg_response_time": f"{avg_total:.2f}秒",
        "risk_level_macro_f1": round(risk_level_f1_result.accuracy, 4) if risk_level_f1_result is not None else "N/A",
        "total_score": 0
    }

    total = 0
    if risk_level_f1_result is not None:
        total += risk_level_f1_result.score
    total += report["timing_metrics"]["first_packet_score"]
    total += report["timing_metrics"]["total_time_score"]
    report["summary"]["total_score"] = round(total, 1)
    report["summary"]["max_total_score"] = 30

    output_dir = os.path.join(os.path.dirname(__file__), "outputs")
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, "multi_asset_report.json")
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report, report_file


def print_report(report: Dict[str, Any], report_file: str) -> None:
    """打印综合报告"""
    print("\n" + "=" * 60)
    print("📊 多资产综合评测报告")
    print("=" * 60)
    print(f"资产数量: {report['total_assets']}")
    print(f"成功: {report['successful_count']} / 失败: {report['failed_count']}")
    print("-" * 60)

    timing = report["timing_metrics"]
    print(f"⏱️  响应时间")
    print(f"   平均首包响应时间: {timing['avg_first_packet_time']}秒 (阈值: {timing['first_packet_threshold']}, 得分: {timing['first_packet_score']}/5)")
    print(f"   平均总响应时间: {timing['avg_total_time']}秒 (阈值: {timing['total_time_threshold']}, 得分: {timing['total_time_score']}/5)")

    if report["risk_level_metrics"]:
        rl = report["risk_level_metrics"]
        print(f"\n🎯  风险等级准确率")
        print(f"   宏平均F1: {rl['macro_f1']} (期望: {rl['expected_f1']}, 得分: {rl['score']}/{rl['max_score']})")
        pass_str = "✅ 通过" if rl["is_passed"] else "❌ 未达标"
        print(f"   状态: {pass_str}")
        print(f"\n   详细对比:")
        print(f"   {'资产ID':<22} {'AI风险等级':<10} {'API风险等级':<10} {'匹配'}")
        print(f"   " + "-" * 55)
        for item in rl["detail_comparison"]:
            aid = item["asset_id"][:20]
            match_mark = "✅" if item["match"] else "❌"
            ai_r = str(item["ai_risk"] or "None")
            api_r = str(item["api_risk"] or "None")
            print(f"   {aid:<22} {ai_r:<10} {api_r:<10} {match_mark}")

    print("-" * 60)
    summary = report["summary"]
    print(f"🎯 综合得分: {summary['total_score']}/{summary['max_total_score']}")
    print("=" * 60)
    print(f"\n📄 报告已保存: {report_file}")


def main() -> None:
    print("=" * 60)
    print("🚀 批量AI资产解读 & 多资产综合评测")
    print("=" * 60)

    config = ConfigLoader()
    asset_ids: List[str] = config.test_assets
    headers: Dict[str, str] = config.headers

    print(f"\n📋 资产数量: {len(asset_ids)}")
    print(f"📋 资产列表: {asset_ids}")

    success_count = 0
    failed_count = 0
    failed_list: List[Tuple[str, str]] = []
    timing_results: Dict[str, Dict[str, float]] = {}

    print("\n🚀 开始处理（自动记录首包时间和响应时间）...")

    for idx, asset_id in enumerate(asset_ids):
        print(f"\n[{idx+1}/{len(asset_ids)}] 资产ID: {asset_id}")
        print("-" * 40)

        output_dir = os.path.join(os.path.dirname(__file__), "outputs")
        json_dir = os.path.join(output_dir, "raw_json")
        json_file = os.path.join(json_dir, f"asset_data_{asset_id}.json")
        is_cached = os.path.exists(json_file)

        if is_cached:
            print("  ⏭️ 已有缓存数据，仅测量响应时间...")
            timing = measure_timing_only(asset_id, config, headers)
            if timing["total_time"] > 0:
                timing_results[asset_id] = timing
                print(f"    首包: {timing['first_packet_time']:.2f}秒, 总时间: {timing['total_time']:.2f}秒")
                success_count += 1
            else:
                print(f"  ⚠️ 响应时间测量失败，使用已有缓存数据")
                timing_results[asset_id] = {"first_packet_time": 0, "total_time": 0}
                success_count += 1
        else:
            print("  调用AI接口并测量响应时间...")
            result = call_ai_and_measure(asset_id, config, headers)
            if result['success']:
                save_results(asset_id, result['raw_text'], result['parsed_fields'])
                timing_results[asset_id] = {
                    "first_packet_time": result["first_packet_time"],
                    "total_time": result["total_time"]
                }
                risk_level = result['parsed_fields'].get('risk_level', '未识别')
                print(f"  ✅ 成功，风险等级: {risk_level}")
                print(f"    首包: {result['first_packet_time']:.2f}秒, 总时间: {result['total_time']:.2f}秒")
                success_count += 1
            else:
                error_msg = result.get('error', '未知错误')
                print(f"  ❌ 失败: {error_msg}")
                failed_count += 1
                failed_list.append((asset_id, error_msg))

        if idx < len(asset_ids) - 1:
            time.sleep(2)

    print("\n" + "=" * 60)
    print(f"📈 AI资产解读完成")
    print(f"   成功: {success_count} / 失败: {failed_count}")
    print("=" * 60)

    print("\n📥 获取API标准数据，计算风险等级宏平均F1...")

    asset_client = AssetAPIClient(config)
    risk_level_calc = RiskLevelCalculator()
    f1_pairs = []
    f1_failed = []

    for asset_id in asset_ids:
        json_dir = os.path.join(os.path.dirname(__file__), "outputs", "raw_json")
        json_file = os.path.join(json_dir, f"asset_data_{asset_id}.json")
        if not os.path.exists(json_file):
            f1_failed.append(asset_id)
            continue

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        ai_data = data.get('parsed_fields', {})

        api_data = asset_client.get_asset_detail(asset_id)
        if "error" in api_data:
            f1_failed.append(asset_id)
            continue

        f1_pairs.append((ai_data, api_data))

    risk_level_f1_result = None
    if len(f1_pairs) >= 2:
        risk_level_f1_result = risk_level_calc.calculate_batch(f1_pairs)
        print(f"   宏平均F1: {risk_level_f1_result.accuracy:.4f} (得分: {risk_level_f1_result.score:.1f}/{risk_level_f1_result.max_score})")
    else:
        print(f"   ⚠️ 有效数据不足（{len(f1_pairs)}个），无法计算宏平均F1")

    report, report_file = generate_report(
        asset_ids=asset_ids,
        timing_results=timing_results,
        risk_level_f1_result=risk_level_f1_result,
        success_count=success_count,
        failed_list=failed_list
    )

    print_report(report, report_file)

    return report


if __name__ == "__main__":
    main()

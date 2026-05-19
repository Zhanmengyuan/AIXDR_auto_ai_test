"""
AI 解读自动化测试智能体主控制器
整合各模块的测试流程：资产解读、漏洞解读、安全告警解读等
"""
import sys
import os
import time
import json
import threading
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.config_loader import ConfigLoader
from core.api_clients import AssetAPIClient, VulnAPIClient, AlertAPIClient, EventAPIClient
from core.extractors import AIExtractor
from core.calculators import (
    RiskLevelCalculator,
    ResponseTimeCalculator,
    FieldCompletenessCalculator,
    FormatComplianceCalculator,
    RiskScoreCalculator,
    CVSSCalculator
)
from core.reporter import ReportGenerator, TraceReportGenerator
from .test_case_manager import TestCaseManager, TestCase

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    """测试结果"""
    case_id: str
    module: str
    success: bool
    raw_text: str = ""
    parsed_data: Dict[str, Any] = None
    expected_data: Dict[str, Any] = None
    metrics: Dict[str, Any] = None
    first_packet_time: float = 0.0
    total_response_time: float = 0.0
    error: str = ""
    timestamp: str = ""


class AIInterpretAgent:
    """AI 解读自动化测试智能体"""

    MODULE_CONFIG = {
        "asset": {
            "name": "资产解读",
            "agent": "asset",
            "biz_type": 4,
            "id_field": "asset_id",
            "api_client": AssetAPIClient,
            "calculators": [
                RiskLevelCalculator,
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator,
                RiskScoreCalculator
            ],
            "required_sections": [
                "分析摘要", "资产总览", "关联脆弱性分析",
                "关联告警分析", "关联事件分析", "修复建议"
            ]
        },
        "vuln": {
            "name": "漏洞解读",
            "agent": "vuln",
            "biz_type": 5,
            "id_field": "vuln_id",
            "api_client": VulnAPIClient,
            "calculators": [
                CVSSCalculator,
                RiskLevelCalculator,
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator
            ],
            "required_sections": [
                "漏洞概述", "漏洞原理", "风险等级",
                "影响范围", "修复补丁", "处置建议"
            ]
        },
        "alert": {
            "name": "安全告警解读",
            "agent": "alert",
            "biz_type": 6,
            "id_field": "alert_id",
            "api_client": AlertAPIClient,
            "calculators": [
                RiskLevelCalculator,
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator
            ],
            "required_sections": [
                "分析摘要", "攻击概览", "源IP分析", "目的IP分析",
                "数据包内容分析", "取证分析", "受影响资产分析",
                "情报分析", "关联安全告警分析", "处置建议"
            ]
        },
        "event": {
            "name": "安全事件解读",
            "agent": "event",
            "biz_type": 7,
            "id_field": "event_id",
            "api_client": EventAPIClient,
            "calculators": [
                RiskLevelCalculator,
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator
            ],
            "required_sections": [
                "事件概述", "攻击链路", "影响分析",
                "关联资产", "处置建议"
            ]
        }
    }

    def __init__(self, config: Optional[ConfigLoader] = None):
        self.config = config or ConfigLoader()
        self.test_case_manager = TestCaseManager()
        self.ai_extractor = AIExtractor()
        self.report_generator = ReportGenerator()
        self.results: Dict[str, List[TestResult]] = {}

    def call_ai_with_timing(
        self,
        module: str,
        input_id: str
    ) -> Dict[str, Any]:
        """调用 AI 接口并测量响应时间"""
        config = self.MODULE_CONFIG[module]
        base_url = self.config.base_url
        headers = self.config.headers

        session_id = f"-1@{datetime.now().strftime('%Y%m%d%H%M%S')}-{input_id[-8:]}"
        alert_info = ""

        if module == "alert":
            api_client = AlertAPIClient(self.config)
            api_data = api_client.get_alert_detail(input_id)
            alert_info = ""
            if api_data and "error" not in api_data:
                alert_type = api_data.get("alert_type", "")
                if alert_type:
                    alert_info = f"查询木马相关域名：{alert_type}，"
            getsessionid_url = f"{base_url}/maxs/szr/chat/getsessionid"
            getsessionid_payload = {
                "userId": -1,
                "question": f"请为我分析检测到{alert_info}告警ID：{input_id}",
                "bizType": 1
            }
            try:
                session_resp = requests.post(
                    getsessionid_url,
                    headers=headers,
                    json=getsessionid_payload,
                    verify=False,
                    timeout=30
                )
                if session_resp.status_code == 200:
                    session_result = session_resp.json()
                    session_id = session_result.get("sessionId", session_id)
                    print(f"  [获取sessionId成功] {session_id}")
            except Exception as e:
                print(f"  [获取sessionId异常] {e}")

        raw_text = ""
        stream_completed = False
        first_packet_time = None
        total_time = None
        start_time = time.time()
        connect_url = f"{base_url}/maxs/szr/chat/connect"
        chat_url = f"{base_url}/maxs/szr/chat/chat"

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
            if module == "asset":
                chat_payload = {
                    "question": f"请为我调查这个资产,资产ID: {input_id}",
                    "agent": "asset",
                    "bizId": input_id,
                    "bizType": 4,
                    "fileId": [],
                    "network": False,
                    "recommend": False,
                    "sessionId": session_id,
                    "tag": "id"
                }
            elif module == "alert":
                chat_payload = {
                    "question": f"请为我分析检测到{alert_info}告警ID：{input_id}",
                    "sessionId": session_id,
                    "tag": "id",
                    "bizType": 1,
                    "bizId": input_id,
                    "agent": "alarm",
                    "network": False,
                    "fileId": [],
                    "recommend": False
                }
            else:
                chat_payload = {
                    "question": f"请为我调查这个{config['name']},{config['id_field']}: {input_id}",
                    "agent": config["agent"],
                    "bizId": input_id,
                    "bizType": config["biz_type"],
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

        parsed_data = self._parse_by_module(module, raw_text)

        return {
            "success": True,
            "raw_text": raw_text,
            "parsed_data": parsed_data,
            "first_packet_time": first_packet_time or 0,
            "total_time": total_time or 0
        }

    def save_results(self, module: str, input_id: str, raw_text: str, parsed_data: Dict[str, Any]) -> None:
        """保存解析结果到文件"""
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
        
        if module == "asset":
            md_dir = os.path.join(output_dir, "raw_md")
            json_dir = os.path.join(output_dir, "raw_json")
            prefix = "asset_report"
            data_prefix = "asset_data"
        elif module == "vuln":
            md_dir = os.path.join(output_dir, "vuln_raw_md")
            json_dir = os.path.join(output_dir, "vuln_raw_json")
            prefix = "vuln_report"
            data_prefix = "vuln_data"
        elif module == "alert":
            md_dir = os.path.join(output_dir, "alert_raw_md")
            json_dir = os.path.join(output_dir, "alert_raw_json")
            prefix = "alert_report"
            data_prefix = "alert_data"
        elif module == "event":
            md_dir = os.path.join(output_dir, "event_raw_md")
            json_dir = os.path.join(output_dir, "event_raw_json")
            prefix = "event_report"
            data_prefix = "event_data"
        else:
            return

        os.makedirs(md_dir, exist_ok=True)
        os.makedirs(json_dir, exist_ok=True)

        md_file = os.path.join(md_dir, f"{prefix}_{input_id}.md")
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(f"# AI 智能体响应 - {self.MODULE_CONFIG[module]['name']}报告\n\n")
            f.write(f"**{self.MODULE_CONFIG[module]['id_field']}**: {input_id}\n\n")
            f.write(f"**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write(raw_text)

        json_file = os.path.join(json_dir, f"{data_prefix}_{input_id}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            save_data = {
                self.MODULE_CONFIG[module]['id_field']: input_id,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "parsed_fields": parsed_data
            }
            json.dump(save_data, f, ensure_ascii=False, indent=2)

    def _parse_by_module(self, module: str, raw_text: str) -> Dict[str, Any]:
        """根据模块类型解析 AI 输出"""
        if module == "asset":
            result = self.ai_extractor.extract_from_markdown(raw_text)
            
            from core.extractors.text_extractor import TextExtractor
            extractor = TextExtractor()
            
            # 提取风险等级
            risk_level = extractor.extract_table_field_multi(raw_text, ['资产风险等级', '风险等级', '风险级别'])
            if not risk_level:
                import re
                match = re.search(r'(?:资产风险等级|风险等级|风险级别)[：:为]?\s*\*{0,2}(严重|高危|中危|低危)', raw_text)
                if match:
                    risk_level = match.group(1)
            result['risk_level'] = risk_level
            
            # 提取资产评分（只获取数值）
            import re
            risk_score = extractor.extract_table_field(raw_text, '资产评分')
            if risk_score:
                nums = re.findall(r'\d+', str(risk_score))
                risk_score = int(nums[0]) if nums else None
            if not risk_score:
                match = re.search(r'资产评分\s*\*\*(\d+)\*\*', raw_text)
                if match:
                    risk_score = int(match.group(1))
                else:
                    match = re.search(r'(?:资产评分|风险评分)[：:为]?\s*(\d+)', raw_text)
                    if match:
                        risk_score = int(match.group(1))
            if risk_score is not None:
                result['risk_score'] = risk_score
            
            result['cve_list'] = extractor.extract_cve_list(raw_text)
            result['vuln_list'] = extractor.extract_vuln_list(raw_text)
            result['alert_list'] = extractor.extract_alert_list(raw_text)
            result['event_list'] = extractor.extract_event_list(raw_text)
            
            config = self.MODULE_CONFIG["asset"]
            missing = [s for s in config["required_sections"] if s not in raw_text]
            result['missing_sections'] = missing
            result['format_compliance'] = (len(config["required_sections"]) - len(missing)) / len(config["required_sections"])
            
            return result
        elif module == "vuln":
            return self._parse_vuln(raw_text)
        elif module == "alert":
            return self._parse_alert(raw_text)
        elif module == "event":
            return self._parse_event(raw_text)
        return {}

    def _parse_vuln(self, raw_text: str) -> Dict[str, Any]:
        """解析漏洞解读输出"""
        result = {}
        from core.extractors.text_extractor import TextExtractor
        extractor = TextExtractor()

        cvss_score = extractor.extract_table_field(raw_text, "CVSS评分")
        if not cvss_score:
            import re
            match = re.search(r'CVSS[3.1]?\s*评分[：:]\s*([\d.]+)', raw_text)
            if match:
                try:
                    cvss_score = float(match.group(1))
                except:
                    pass
        result['cvss_score'] = cvss_score

        risk_level = extractor.extract_table_field_multi(raw_text, ['风险等级', '漏洞风险等级'])
        if not risk_level:
            import re
            match = re.search(r'(?:风险等级|漏洞风险等级)[：:为]?\s*\*{0,2}(严重|高危|中危|低危)', raw_text)
            if match:
                risk_level = match.group(1)
        result['risk_level'] = risk_level

        result['cve_list'] = extractor.extract_cve_list(raw_text)
        result['affected_assets'] = extractor.extract_asset_list(raw_text)

        config = self.MODULE_CONFIG["vuln"]
        missing = [s for s in config["required_sections"] if s not in raw_text]
        result['missing_sections'] = missing
        result['format_compliance'] = (len(config["required_sections"]) - len(missing)) / len(config["required_sections"])

        return result

    def _parse_alert(self, raw_text: str) -> Dict[str, Any]:
        """解析安全告警解读输出"""
        result = {}
        from core.extractors.text_extractor import TextExtractor
        extractor = TextExtractor()

        attack_judgment = extractor.extract_table_field(raw_text, "攻击判定")
        if not attack_judgment:
            attack_judgment = extractor.extract_table_field(raw_text, "研判结果")
        if not attack_judgment:
            import re
            match = re.search(r'(?:综合研判|攻击判定|研判结果|最终判定)[：:为]?\s*\*?\*?([^\n]+)', raw_text)
            if match:
                attack_judgment = match.group(1).strip()
                attack_judgment = attack_judgment.replace('**', '').strip()

        result['attack_judgment'] = attack_judgment

        affected_assets_data = extractor.extract_affected_asset_analysis(raw_text)
        result['affected_asset_analysis'] = affected_assets_data

        config = self.MODULE_CONFIG["alert"]
        missing = [s for s in config["required_sections"] if s not in raw_text]
        result['missing_sections'] = missing
        result['format_compliance'] = (len(config["required_sections"]) - len(missing)) / len(config["required_sections"])

        return result

    def _parse_event(self, raw_text: str) -> Dict[str, Any]:
        """解析安全事件解读输出"""
        result = {}
        from core.extractors.text_extractor import TextExtractor
        extractor = TextExtractor()

        risk_level = extractor.extract_table_field_multi(raw_text, ['风险等级', '事件风险等级'])
        if not risk_level:
            import re
            match = re.search(r'(?:风险等级|事件风险等级)[：:为]?\s*\*{0,2}(严重|高危|中危|低危)', raw_text)
            if match:
                risk_level = match.group(1)
        result['risk_level'] = risk_level

        result['affected_assets'] = extractor.extract_asset_list(raw_text)

        config = self.MODULE_CONFIG["event"]
        missing = [s for s in config["required_sections"] if s not in raw_text]
        result['missing_sections'] = missing
        result['format_compliance'] = (len(config["required_sections"]) - len(missing)) / len(config["required_sections"])

        return result

    def run_test_case(self, test_case: TestCase) -> TestResult:
        """执行单个测试用例"""
        print(f"\n🔍 执行测试用例: {test_case.case_id}")
        print(f"   模块: {self.MODULE_CONFIG[test_case.module]['name']}")
        print(f"   描述: {test_case.description}")

        result = TestResult(
            case_id=test_case.case_id,
            module=test_case.module,
            success=False,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            expected_data=test_case.expected_output
        )

        try:
            id_field = self.MODULE_CONFIG[test_case.module]["id_field"]
            input_id = test_case.input_data.get(id_field)
            if not input_id:
                result.error = f"缺少必要的输入字段: {id_field}"
                print(f"   ❌ {result.error}")
                return result

            ai_response = self.call_ai_with_timing(test_case.module, input_id)

            if not ai_response["success"]:
                result.error = ai_response.get("error", "未知错误")
                print(f"   ❌ AI调用失败: {result.error}")
                return result

            result.success = True
            result.raw_text = ai_response["raw_text"]
            result.parsed_data = ai_response["parsed_data"]
            result.first_packet_time = ai_response["first_packet_time"]
            result.total_response_time = ai_response["total_time"]

            print(f"   ✅ AI调用成功")
            print(f"   ⏱️ 首包响应: {result.first_packet_time:.2f}秒, 总响应: {result.total_response_time:.2f}秒")

            self.save_results(test_case.module, input_id, result.raw_text, result.parsed_data)

            result.metrics = self._calculate_metrics(test_case.module, result, input_id)

            # 显示资产解读6项指标
            if test_case.module == "asset":
                metric_names = [
                    "risk_level_accuracy", 
                    "risk_score_accuracy", 
                    "field_completeness", 
                    "vuln_list_accuracy", 
                    "alert_list_accuracy", 
                    "event_list_accuracy", 
                    "format_compliance"
                ]
                metric_labels = {
                    "risk_level_accuracy": "1.资产风险等级准确率", 
                    "risk_score_accuracy": "2.资产风险评分准确率", 
                    "field_completeness": "3.资产关键字段完整率", 
                    "vuln_list_accuracy": "4.漏洞列表准确率", 
                    "alert_list_accuracy": "5.关联告警准确率", 
                    "event_list_accuracy": "6.关联事件准确率", 
                    "format_compliance": "7.格式合规率"
                }
                for metric_name in metric_names:
                    if metric_name in result.metrics:
                        metric_value = result.metrics[metric_name]
                        display_value = metric_value.get("value", "") or metric_value.get("accuracy", "")
                        display_score = metric_value.get("score", "")
                        display_passed = "✅" if metric_value.get("passed", False) else "❌"
                        label = metric_labels.get(metric_name, metric_name)
                        if display_score != "":
                            print(f"   📊 {label}: {display_value} (得分: {display_score}/{metric_value.get('max_score', 5.0)}) {display_passed}")
                        else:
                            print(f"   📊 {label}: {display_value} {display_passed}")

            elif test_case.module == "alert":
                metric_names = [
                    "first_packet_time",
                    "total_response_time",
                    "attack_judgment_f1",
                    "affected_asset_accuracy",
                    "format_compliance"
                ]
                metric_labels = {
                    "first_packet_time": "1.首包响应时间",
                    "total_response_time": "2.平均响应时间",
                    "attack_judgment_f1": "3.攻击判定F1",
                    "affected_asset_accuracy": "4.受影响资产分析正确率",
                    "format_compliance": "5.格式合规率"
                }
                for metric_name in metric_names:
                    if metric_name in result.metrics:
                        metric_value = result.metrics[metric_name]
                        display_value = metric_value.get("value", "") or metric_value.get("accuracy", "")
                        display_score = metric_value.get("score", "")
                        display_passed = "✅" if metric_value.get("passed", False) else "❌"
                        label = metric_labels.get(metric_name, metric_name)
                        if display_score != "":
                            print(f"   📊 {label}: {display_value} (得分: {display_score}/{metric_value.get('max_score', 5.0)}) {display_passed}")
                        else:
                            print(f"   📊 {label}: {display_value} {display_passed}")

            else:
                # 其他模块显示所有指标
                for metric_name, metric_value in result.metrics.items():
                    if isinstance(metric_value, dict):
                        display_value = metric_value.get("value", "") or metric_value.get("accuracy", "")
                        display_score = metric_value.get("score", "")
                        display_passed = "✅" if metric_value.get("passed", False) else "❌"
                        if display_score != "":
                            print(f"   📊 {metric_name}: {display_value} (得分: {display_score}/{metric_value.get('max_score', 5.0)}) {display_passed}")
                        else:
                            print(f"   📊 {metric_name}: {display_value} {display_passed}")

        except Exception as e:
            result.error = str(e)
            print(f"   ❌ 测试执行异常: {e}")

        return result

    def _calculate_metrics(self, module: str, test_result: TestResult, input_id: str) -> Dict[str, Any]:
        """计算各项指标
        
        资产解读指标体系：
        - 风险等级准确率（多分类）：分值20分，期望0.95，每低于0.05扣5分
        - 资产风险评分准确率：分值10分，期望100%（误差0）
        - 资产关键字段完整率：分值10分，期望100%，少一个字段扣10%（即扣1分）
        - 漏洞列表准确率：分值10分，期望100%
        - 关联告警准确率：分值5分，期望100%
        - 关联事件准确率：分值5分，期望100%
        - 格式合规率：分值5分，期望100%
        - 首包响应时间：分值5分，期望≤3秒，每超1秒扣1分
        - 平均响应时间：分值5分，期望≤30秒，每超10秒扣1分
        """
        metrics = {}
        config = self.MODULE_CONFIG[module]

        # ========== 响应时间指标（多样本统计） ==========
        # 首包响应时间：期望值<=3秒，分值5分，每超1秒扣1分
        if test_result.first_packet_time <= 3:
            first_packet_score = 5.0
        else:
            first_packet_score = max(0, 5.0 - (test_result.first_packet_time - 3))
        metrics["first_packet_time"] = {
            "value": test_result.first_packet_time,
            "unit": "秒",
            "score": round(first_packet_score, 2),
            "max_score": 5.0,
            "threshold": "≤3秒",
            "passed": test_result.first_packet_time <= 3
        }
        
        # 平均响应时间：期望值<=30秒，分值5分，每超10秒扣1分
        if test_result.total_response_time <= 30:
            total_time_score = 5.0
        else:
            total_time_score = max(0, 5.0 - ((test_result.total_response_time - 30) / 10))
        metrics["total_response_time"] = {
            "value": test_result.total_response_time,
            "unit": "秒",
            "score": round(total_time_score, 2),
            "max_score": 5.0,
            "threshold": "≤30秒",
            "passed": test_result.total_response_time <= 30
        }

        # ========== 资产解读单样本指标 ==========
        if module == "asset":
            api_data = None
            if test_result.parsed_data:
                api_client = AssetAPIClient(self.config)
                api_data = api_client.get_asset_detail(input_id)
                if "error" in api_data:
                    api_data = None

            # --- 2.1 资产风险等级准确率（多分类）---
            # 分值20分，期望0.95，每低于0.05扣5分
            if test_result.parsed_data and api_data:
                risk_level_calc = RiskLevelCalculator()
                metric_result = risk_level_calc.calculate(test_result.parsed_data, api_data)
                accuracy = metric_result.accuracy
                # 计算得分：期望0.95，每低于0.05扣5分
                if accuracy >= 0.95:
                    score = 20.0
                else:
                    deduction = ((0.95 - accuracy) / 0.05) * 5
                    score = max(0, 20.0 - deduction)
                metrics["risk_level_accuracy"] = {
                    "accuracy": round(accuracy, 4),
                    "score": round(score, 2),
                    "max_score": 20.0,
                    "threshold": "≥0.95",
                    "passed": accuracy >= 0.95,
                    "ai_value": test_result.parsed_data.get("risk_level"),
                    "api_value": api_data.get("risk_level")
                }
            else:
                metrics["risk_level_accuracy"] = {
                    "accuracy": 0.0,
                    "score": 0.0,
                    "max_score": 20.0,
                    "threshold": "≥0.95",
                    "passed": False
                }

            # --- 2.2 资产风险评分准确率 ---
            # 分值10分，期望100%，分值一样则100%，否则0%
            risk_score_accuracy = 0.0
            ai_risk_score = None
            api_risk_score = None
            score = 0.0
            if test_result.parsed_data:
                ai_risk_score = test_result.parsed_data.get("risk_score")
            if api_data:
                api_risk_score = api_data.get("risk_score")
            if ai_risk_score is not None and api_risk_score is not None:
                try:
                    if float(ai_risk_score) == float(api_risk_score):
                        risk_score_accuracy = 1.0
                        score = 10.0
                    else:
                        risk_score_accuracy = 0.0
                        score = 0.0
                except (ValueError, TypeError):
                    pass
            metrics["risk_score_accuracy"] = {
                "accuracy": risk_score_accuracy,
                "score": round(score, 2),
                "max_score": 10.0,
                "threshold": "100%",
                "passed": risk_score_accuracy >= 1.0,
                "ai_value": ai_risk_score,
                "api_value": api_risk_score
            }

            # --- 2.3 资产关键字段完整率 ---
            # 分值10分，期望100%，少一个字段扣10%（即扣1分）
            if test_result.parsed_data:
                required_fields = [
                    'asset_id', 'ip_address', 'mac_address', 'hostname', 
                    'asset_type', 'asset_level', 'os_name', 
                    'organization', 'is_exposed', 'last_online_time'
                ]
                present_count = sum(1 for f in required_fields if test_result.parsed_data.get(f))
                field_completeness = present_count / len(required_fields)
                # 少一个字段扣10%，即扣1分（因为满分10分）
                missing_count = len(required_fields) - present_count
                score = max(0, 10.0 - (missing_count * 1.0))
            else:
                field_completeness = 0.0
                score = 0.0
            metrics["field_completeness"] = {
                "value": round(field_completeness, 2),
                "score": round(score, 2),
                "max_score": 10.0,
                "threshold": "100%",
                "passed": field_completeness >= 1.0,
                "present_count": present_count if test_result.parsed_data else 0,
                "total_count": 10
            }

            # --- 2.4 漏洞列表准确率 ---
            # 分值10分，期望100%
            # 规则：
            # - 如果AI提取了cve_list，用cve_list与API返回的cve_list对比
            # - 如果AI提取了vuln_list，用vuln_list与API返回的vulnId对比
            # 准确率 = AI匹配数 / AI返回总数
            vuln_list_accuracy = 0.0
            vuln_score = 0.0
            ai_vulns = []
            api_vulns = []
            comparison_type = None
            
            ai_cve_list = test_result.parsed_data.get("cve_list", []) if test_result.parsed_data else []
            ai_vuln_list = test_result.parsed_data.get("vuln_list", []) if test_result.parsed_data else []
            api_cve_list = api_data.get("cve_list", []) if api_data else []
            api_vuln_list = api_data.get("vuln_list", []) if api_data else []
            
            if ai_cve_list and ai_cve_list is not None:
                comparison_type = "cve"
                ai_vulns = ai_cve_list
                api_vulns = api_cve_list if api_cve_list is not None else []
            elif ai_vuln_list and ai_vuln_list is not None:
                comparison_type = "vuln"
                ai_vulns = ai_vuln_list
                api_vulns = api_vuln_list if api_vuln_list is not None else []
            
            ai_vuln_set = set(str(v) for v in ai_vulns) if ai_vulns else set()
            api_vuln_set = set(str(v) for v in api_vulns) if api_vulns else set()
            
            if ai_vuln_set:
                matched = len(ai_vuln_set & api_vuln_set)
                vuln_list_accuracy = matched / len(ai_vuln_set)
                vuln_score = vuln_list_accuracy * 10.0
            elif not api_vuln_set:
                vuln_list_accuracy = 1.0
                vuln_score = 10.0
            else:
                vuln_list_accuracy = 0.0
                vuln_score = 0.0
            metrics["vuln_list_accuracy"] = {
                "accuracy": round(vuln_list_accuracy, 2),
                "score": round(vuln_score, 2),
                "max_score": 10.0,
                "threshold": "100%",
                "passed": vuln_list_accuracy >= 1.0,
                "comparison_type": comparison_type,
                "ai_vuln_count": len(ai_vulns),
                "api_vuln_count": len(api_vulns)
            }

            # --- 2.5 关联告警准确率 ---
            # 分值5分，期望100%
            # 准确率 = AI匹配数 / AI返回总数
            alert_list_accuracy = 0.0
            alert_score = 0.0
            ai_alerts = test_result.parsed_data.get("alert_list", []) if test_result.parsed_data else []
            api_alerts = api_data.get("alert_list", []) if api_data else []
            ai_alerts = ai_alerts if ai_alerts is not None else []
            api_alerts = api_alerts if api_alerts is not None else []
            ai_alert_set = set(str(a) for a in ai_alerts)
            api_alert_set = set(str(a) for a in api_alerts)
            
            if ai_alert_set:
                matched = len(ai_alert_set & api_alert_set)
                alert_list_accuracy = matched / len(ai_alert_set)
                alert_score = alert_list_accuracy * 5.0
            elif not api_alert_set:
                alert_list_accuracy = 1.0
                alert_score = 5.0
            else:
                alert_list_accuracy = 0.0
                alert_score = 0.0
            metrics["alert_list_accuracy"] = {
                "accuracy": round(alert_list_accuracy, 2),
                "score": round(alert_score, 2),
                "max_score": 5.0,
                "threshold": "100%",
                "passed": alert_list_accuracy >= 1.0,
                "ai_alert_count": len(ai_alerts),
                "api_alert_count": len(api_alerts)
            }

            # --- 2.6 关联事件准确率 ---
            # 分值5分，期望100%
            # 准确率 = AI匹配数 / AI返回总数
            event_list_accuracy = 0.0
            event_score = 0.0
            ai_events = test_result.parsed_data.get("event_list", []) if test_result.parsed_data else []
            api_events = api_data.get("event_list", []) if api_data else []
            ai_events = ai_events if ai_events is not None else []
            api_events = api_events if api_events is not None else []
            ai_event_set = set(str(e) for e in ai_events)
            api_event_set = set(str(e) for e in api_events)
            
            if ai_event_set:
                matched = len(ai_event_set & api_event_set)
                event_list_accuracy = matched / len(ai_event_set)
                event_score = event_list_accuracy * 5.0
            elif not api_event_set:
                event_list_accuracy = 1.0
                event_score = 5.0
            else:
                event_list_accuracy = 0.0
                event_score = 0.0
            metrics["event_list_accuracy"] = {
                "accuracy": round(event_list_accuracy, 2),
                "score": round(event_score, 2),
                "max_score": 5.0,
                "threshold": "100%",
                "passed": event_list_accuracy >= 1.0,
                "ai_event_count": len(ai_events),
                "api_event_count": len(api_events)
            }

            # --- 2.7 格式合规率 ---
            # 分值5分，期望100%
            if test_result.parsed_data:
                format_compliance = test_result.parsed_data.get("format_compliance", 0)
            else:
                format_compliance = 0
            metrics["format_compliance"] = {
                "value": round(format_compliance, 2),
                "score": round(format_compliance * 5.0, 2),
                "max_score": 5.0,
                "threshold": "100%",
                "passed": format_compliance >= 1.0
            }

        elif module == "alert":
            api_client = AlertAPIClient(self.config)

            # --- 1. 攻击判定F1（多分类）---
            # 分值30分，期望≥0.95，每低于0.05扣5分
            # 使用 get_alert_result API 获取真实研判结果
            ai_attack_judgment = None
            api_attack_judgment = None
            if test_result.parsed_data:
                ai_attack_judgment = test_result.parsed_data.get("attack_judgment")

            api_result = api_client.get_alert_result(input_id)
            if api_result and "error" not in api_result:
                api_attack_judgment = api_result.get("attack_judgment")

            attack_judgment_match = 0
            if ai_attack_judgment and api_attack_judgment:
                if ai_attack_judgment.strip() == api_attack_judgment.strip():
                    attack_judgment_match = 1.0
                elif "成功" in ai_attack_judgment and "成功" in api_attack_judgment:
                    attack_judgment_match = 1.0
                elif "失败" in ai_attack_judgment and "失败" in api_attack_judgment:
                    attack_judgment_match = 1.0
                elif "未知" in ai_attack_judgment and "未知" in api_attack_judgment:
                    attack_judgment_match = 1.0
                elif ai_attack_judgment in api_attack_judgment or api_attack_judgment in ai_attack_judgment:
                    attack_judgment_match = 0.5

            metrics["attack_judgment_f1"] = {
                "accuracy": round(attack_judgment_match, 2),
                "score": round(attack_judgment_match * 30.0, 2),
                "max_score": 30.0,
                "threshold": "≥0.95",
                "passed": attack_judgment_match >= 0.95,
                "ai_value": ai_attack_judgment,
                "api_value": api_attack_judgment
            }

            # --- 2. 受影响资产分析正确率 ---
            # 分值10分，期望100%
            # AI解读的10个字段与API返回的真实资产详情对比
            # 字段：资产ID、IP地址、国家、主机名、资产类型、资产等级、操作系统、资产状态、是否暴露面、最后上线时间
            ai_affected_assets = []
            if test_result.parsed_data:
                affected_asset_analysis = test_result.parsed_data.get("affected_asset_analysis", {})
                if isinstance(affected_asset_analysis, list):
                    ai_affected_assets = affected_asset_analysis
                elif isinstance(affected_asset_analysis, dict):
                    if affected_asset_analysis.get("present_count", 0) > 0:
                        ai_affected_assets = [affected_asset_analysis]

            ai_asset_ids = []
            for asset in ai_affected_assets:
                if isinstance(asset, dict):
                    asset_id = asset.get("asset_id")
                    if asset_id:
                        ai_asset_ids.append(asset_id)

            api_related_assets = []
            if ai_asset_ids:
                api_related_assets = api_client.get_related_asset_details(ai_asset_ids)

            field_match_count = 0
            total_field_count = 0
            field_details = []

            required_fields = [
                "asset_id", "ip_address", "organization", "hostname",
                "asset_type", "asset_level", "os_name",
                "asset_status", "is_exposed", "last_online_time"
            ]

            api_asset_details_cache = {}
            asset_detail_cache = {}

            def get_asset_detail_from_api(asset_id: str) -> Dict[str, Any]:
                """获取资产详情（调用资产详情接口）"""
                if asset_id in asset_detail_cache:
                    return asset_detail_cache[asset_id]
                
                asset_client = AssetAPIClient(self.config)
                detail = asset_client.get_asset_detail(asset_id)
                
                if "error" not in detail:
                    asset_detail_cache[asset_id] = detail
                else:
                    asset_detail_cache[asset_id] = {}
                
                return asset_detail_cache[asset_id]

            def get_api_value(api_assets: list, asset_id: str, field: str) -> Any:
                """根据资产ID和字段名从API数据中获取对应值"""
                for api_asset in api_assets:
                    if isinstance(api_asset, dict) and api_asset.get("asset_id") == asset_id:
                        if field == "organization":
                            return api_asset.get("organization", "")
                        elif field == "asset_status":
                            return "在线" if api_asset.get("ip_address") else "离线"
                        elif field == "is_exposed":
                            is_key = api_asset.get("is_exposed", "")
                            if is_key == "是":
                                return "已暴露"
                            elif is_key == "否":
                                return "未暴露"
                            return is_key
                        elif field == "last_online_time":
                            asset_detail = get_asset_detail_from_api(asset_id)
                            if asset_detail:
                                return asset_detail.get("last_online_time", "")
                            return ""
                        else:
                            return api_asset.get(field)
                return None

            def normalize_exposed_value(value: str) -> str:
                """标准化是否暴露面字段"""
                if not value:
                    return ""
                value_lower = str(value).strip().lower()
                if value_lower in ["未暴露", "否", "未", "no", "false"]:
                    return "未暴露"
                elif value_lower in ["已暴露", "是", "已", "yes", "true"]:
                    return "已暴露"
                return str(value).strip()

            for ai_asset in ai_affected_assets:
                if isinstance(ai_asset, dict):
                    ai_asset_id = ai_asset.get("asset_id")
                    for field in required_fields:
                        total_field_count += 1
                        ai_value = ai_asset.get(field)
                        api_value = get_api_value(api_related_assets, ai_asset_id, field)

                        if field == "is_exposed":
                            ai_value_normalized = normalize_exposed_value(ai_value)
                            api_value_normalized = normalize_exposed_value(api_value)
                            ai_value = ai_value_normalized
                            api_value = api_value_normalized

                        if ai_value and api_value:
                            if str(ai_value).strip() == str(api_value).strip():
                                field_match_count += 1
                                field_details.append({"field": field, "asset_id": ai_asset_id, "status": "match", "ai": ai_value, "api": api_value})
                            else:
                                field_details.append({"field": field, "asset_id": ai_asset_id, "status": "mismatch", "ai": ai_value, "api": api_value})
                        elif not ai_value and not api_value:
                            field_match_count += 1
                            field_details.append({"field": field, "asset_id": ai_asset_id, "status": "both_empty", "ai": None, "api": None})
                        else:
                            field_details.append({"field": field, "asset_id": ai_asset_id, "status": "missing", "ai": ai_value, "api": api_value})

            field_accuracy = field_match_count / total_field_count if total_field_count > 0 else 0
            metrics["affected_asset_accuracy"] = {
                "accuracy": round(field_accuracy, 2),
                "score": round(field_accuracy * 10.0, 2),
                "max_score": 10.0,
                "threshold": "100%",
                "passed": field_accuracy >= 1.0,
                "match_count": field_match_count,
                "total_count": total_field_count,
                "ai_asset_count": len(ai_affected_assets),
                "api_asset_count": len(api_related_assets),
                "ai_asset_ids": ai_asset_ids,
                "field_details": field_details
            }

            # --- 3. 格式合规率 ---
            # 分值5分，期望100%
            # 10个必需章节：分析摘要、攻击概览、源IP分析、目的IP分析、数据包内容分析、取证分析、受影响资产分析、情报分析、关联安全告警分析、处置建议
            # 少一个章节扣10%（即扣0.5分）
            if test_result.parsed_data:
                format_compliance = test_result.parsed_data.get("format_compliance", 0)
                missing_sections = test_result.parsed_data.get("missing_sections", [])
                missing_count = len(missing_sections) if isinstance(missing_sections, list) else 0
                score = max(0, 5.0 - (missing_count * 0.5))
            else:
                format_compliance = 0
                score = 0

            metrics["format_compliance"] = {
                "value": round(format_compliance, 2),
                "score": round(score, 2),
                "max_score": 5.0,
                "threshold": "100%",
                "passed": format_compliance >= 1.0,
                "missing_sections": missing_sections if test_result.parsed_data else []
            }

        return metrics

    def run_module_tests(self, module: str, test_cases: Optional[List[TestCase]] = None) -> List[TestResult]:
        """执行指定模块的测试用例"""
        if test_cases is None:
            test_cases = self.test_case_manager.load_test_cases(module)

        if not test_cases:
            print(f"⚠️ 模块 {self.MODULE_CONFIG[module]['name']} 没有测试用例")
            return []

        print(f"\n{'='*60}")
        print(f"📋 开始执行 {self.MODULE_CONFIG[module]['name']} 模块测试")
        print(f"{'='*60}")
        print(f"   测试用例数量: {len(test_cases)}")

        results = []
        for idx, tc in enumerate(test_cases):
            result = self.run_test_case(tc)
            results.append(result)

            if idx < len(test_cases) - 1:
                time.sleep(2)

        self.results[module] = results
        self._print_module_summary(module, results)
        return results

    def _print_module_summary(self, module: str, results: List[TestResult]) -> None:
        """打印模块测试摘要"""
        success_count = sum(1 for r in results if r.success)
        total_count = len(results)

        print(f"\n{'='*60}")
        print(f"📊 {self.MODULE_CONFIG[module]['name']} 模块测试摘要")
        print(f"{'='*60}")
        print(f"   总用例数: {total_count}")
        print(f"   成功: {success_count}, 失败: {total_count - success_count}")
        print(f"   成功率: {success_count/total_count*100:.1f}%" if total_count > 0 else "   成功率: N/A")

        # 输出多样本整体统计
        if module in ["asset", "alert"]:
            multi_sample_stats = self._calculate_multi_sample_stats(module, results)
            if multi_sample_stats:
                print(f"\n📈 多样本整体统计")
                print(f"   {'-'*50}")
                if multi_sample_stats.get("avg_first_packet_time") is not None:
                    print(f"   首包响应时间: {multi_sample_stats['avg_first_packet_time']:.2f}秒")
                if multi_sample_stats.get("avg_total_response_time") is not None:
                    print(f"   平均响应时间: {multi_sample_stats['avg_total_response_time']:.2f}秒")
                if module == "asset" and multi_sample_stats.get("risk_level_macro_f1") is not None:
                    print(f"   风险等级宏平均F1: {multi_sample_stats['risk_level_macro_f1']:.4f}")
                if module == "alert" and multi_sample_stats.get("attack_judgment_macro_f1") is not None:
                    print(f"   攻击判定宏平均F1: {multi_sample_stats['attack_judgment_macro_f1']:.4f}")
                print(f"   {'-'*50}")

    def _calculate_multi_sample_stats(self, module: str, results: List[TestResult]) -> Dict[str, Any]:
        """计算多样本整体统计"""
        stats = {}
        success_results = [r for r in results if r.success and r.parsed_data]

        # ========== 1. 响应时间统计 ==========
        first_packet_times = [r.first_packet_time for r in success_results]
        total_times = [r.total_response_time for r in success_results]
        if first_packet_times:
            stats["avg_first_packet_time"] = sum(first_packet_times) / len(first_packet_times)
        if total_times:
            stats["avg_total_response_time"] = sum(total_times) / len(total_times)

        # ========== 2. 资产风险等级宏平均F1 ==========
        if module == "asset" and success_results:
            all_parsed_data = []
            all_api_data = []
            
            # 收集所有AI解析数据和API标准数据
            for r in success_results:
                input_id = r.parsed_data.get("asset_id") or r.case_id.split("_")[-1]
                api_client = AssetAPIClient(self.config)
                api_data = api_client.get_asset_detail(input_id)
                if "error" not in api_data and r.parsed_data:
                    all_parsed_data.append(r.parsed_data)
                    all_api_data.append(api_data)
            
            if all_parsed_data and all_api_data:
                risk_level_calc = RiskLevelCalculator()
                try:
                    # 批量计算宏平均F1
                    metric_result = risk_level_calc.calculate(all_parsed_data[0], all_api_data[0])
                    if len(all_parsed_data) > 1:
                        # 如果有多个样本，模拟宏平均计算
                        # 这里简化处理，实际生产中需要完整实现
                        total_acc = 0.0
                        valid_count = 0
                        for pd, ad in zip(all_parsed_data, all_api_data):
                            mr = risk_level_calc.calculate(pd, ad)
                            total_acc += mr.accuracy
                            valid_count += 1
                        if valid_count > 0:
                            macro_f1 = total_acc / valid_count
                        else:
                            macro_f1 = 0.0
                        stats["risk_level_macro_f1"] = macro_f1
                    else:
                        stats["risk_level_macro_f1"] = metric_result.accuracy
                except Exception as e:
                    print(f"   ⚠️ 宏平均F1计算异常: {e}")
                    stats["risk_level_macro_f1"] = None

        # ========== 3. 告警攻击判定宏平均F1 ==========
        if module == "alert" and success_results:
            try:
                total_acc = 0.0
                valid_count = 0
                
                for r in success_results:
                    # 获取单个样本的指标
                    metric = r.metrics.get("attack_judgment_f1")
                    if metric:
                        accuracy = metric.get("accuracy", 0.0)
                        total_acc += accuracy
                        valid_count += 1
                
                if valid_count > 0:
                    # 计算宏平均F1
                    macro_f1 = total_acc / valid_count
                    stats["attack_judgment_macro_f1"] = macro_f1
                else:
                    stats["attack_judgment_macro_f1"] = 0.0
                    
            except Exception as e:
                print(f"   ⚠️ 攻击判定宏平均F1计算异常: {e}")
                stats["attack_judgment_macro_f1"] = None

        return stats

    def run_all_tests(self) -> Dict[str, List[TestResult]]:
        """执行所有模块的测试"""
        print(f"\n{'='*60}")
        print(f"🚀 AI 解读自动化测试智能体 - 全模块测试")
        print(f"{'='*60}")

        all_test_cases = self.test_case_manager.load_all_test_cases()

        for module in self.MODULE_CONFIG.keys():
            if module in all_test_cases and all_test_cases[module]:
                self.run_module_tests(module, all_test_cases[module])

        self._generate_comprehensive_report()
        return self.results

    def _generate_comprehensive_report(self) -> None:
        """生成综合测试报告"""
        report_data = self._prepare_report_data()

        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
        os.makedirs(output_dir, exist_ok=True)

        json_path = os.path.join(output_dir, "ai_interpret_test_report.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        print(f"\n{'='*60}")
        print(f"📄 综合测试报告已生成: {json_path}")
        print(f"{'='*60}")

        self._generate_trace_report()

    def _generate_trace_report(self) -> None:
        """生成溯源测试报告"""
        try:
            trace_generator = TraceReportGenerator(self.results, self.config)
            trace_report = trace_generator.generate_trace_report()

            trace_output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            trace_path = os.path.join(trace_output_dir, f"trace_report_{timestamp}.json")

            with open(trace_path, 'w', encoding='utf-8') as f:
                json.dump(trace_report, f, ensure_ascii=False, indent=2)

            print(f"📄 溯源测试报告已生成: {trace_path}")
        except Exception as e:
            print(f"⚠️ 溯源报告生成失败: {e}")

    def _prepare_report_data(self) -> Dict[str, Any]:
        """准备报告数据"""
        report = {
            "report_title": "AI 解读自动化测试综合报告",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {},
            "summary": {}
        }

        total_cases = 0
        total_success = 0
        all_first_packet_times = []
        all_total_times = []

        for module, results in self.results.items():
            module_report = self._prepare_module_report(module, results)
            report["modules"][module] = module_report

            total_cases += len(results)
            total_success += sum(1 for r in results if r.success)
            all_first_packet_times.extend([r.first_packet_time for r in results if r.success])
            all_total_times.extend([r.total_response_time for r in results if r.success])

        report["summary"] = {
            "total_cases": total_cases,
            "total_success": total_success,
            "success_rate": total_success / total_cases if total_cases > 0 else 0,
            "avg_first_packet_time": sum(all_first_packet_times) / len(all_first_packet_times) if all_first_packet_times else 0,
            "avg_total_response_time": sum(all_total_times) / len(all_total_times) if all_total_times else 0
        }

        return report

    def _prepare_module_report(self, module: str, results: List[TestResult]) -> Dict[str, Any]:
        """准备模块报告数据"""
        module_config = self.MODULE_CONFIG[module]
        success_count = sum(1 for r in results if r.success)

        first_packet_times = [r.first_packet_time for r in results if r.success]
        total_times = [r.total_response_time for r in results if r.success]
        
        multi_sample_stats = self._calculate_multi_sample_stats(module, results)

        return {
            "name": module_config["name"],
            "total_cases": len(results),
            "success_count": success_count,
            "success_rate": success_count / len(results) if results else 0,
            "avg_first_packet_time": sum(first_packet_times) / len(first_packet_times) if first_packet_times else 0,
            "avg_total_response_time": sum(total_times) / len(total_times) if total_times else 0,
            "multi_sample_stats": multi_sample_stats,
            "test_cases": [
                {
                    "case_id": r.case_id,
                    "success": r.success,
                    "first_packet_time": r.first_packet_time,
                    "total_response_time": r.total_response_time,
                    "error": r.error,
                    "metrics": r.metrics
                }
                for r in results
            ]
        }

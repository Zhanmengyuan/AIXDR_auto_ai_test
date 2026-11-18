"""
AI 解读自动化测试智能体主控制器
整合各模块的测试流程：资产解读、漏洞解读、安全告警解读等
"""
import sys
import os
import time
import json
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.config_loader import ConfigLoader
from core.api_clients import AssetAPIClient, VulnAPIClient, AlarmAPIClient, EventAPIClient, SandboxAPIClient
from core.extractors import AIExtractor
from core.contract import (
    StandardResult,
    Metric,
    metric_from_calculator_result,
    STATUS_VALID,
    STATUS_FAILED,
    STATUS_INVALID,
)
from core.calculators import (
    RiskLevelCalculator,
    ResponseTimeCalculator,
    FieldCompletenessCalculator,
    FormatComplianceCalculator,
    CVSSCalculator,
    SandboxRiskLevelCalculator,
    SandboxInfoExtractionCalculator,
    SandboxDisposalCalculator,
    SandboxFormatCalculator,
    SandboxCompletenessCalculator,
)
from core.reporter import ReportGenerator
from core.reporter.html_report_generator import HTMLReportGenerator
from .test_case_manager import TestCaseManager, TestCase

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    """测试结果

    样本分类：
    - success=False → 失败样本（AI调用失败，不参与指标计算）
    - success=True, is_invalid=True → 失效样本（API查不到业务数据，不参与指标计算）
    - success=True, is_invalid=False → 有效样本（参与指标计算）
    """
    case_id: str
    module: str
    success: bool
    agent_id: str = ""
    input_id: str = ""
    raw_text: str = ""
    parsed_data: Dict[str, Any] = None
    expected_data: Dict[str, Any] = None
    metrics: Dict[str, Any] = None
    first_packet_time: float = 0.0
    total_response_time: float = 0.0
    error: str = ""
    timestamp: str = ""
    is_invalid: bool = False  # API数据失效（业务数据不存在）
    recommend_questions: list = None  # SSE流中捕获的推荐问题
    standard_result: Any = None  # StandardResult 契约对象（run_test_case结尾自动转换）


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
                FormatComplianceCalculator
            ],
            "required_sections": [
                "风险速览", "风险轨迹", "当前威胁"
            ]
        },
        "vuln": {
            "name": "漏洞解读",
            "agent": "vuln",
            "biz_type": 3,
            "id_field": "vuln_id",
            "api_client": VulnAPIClient,
            "calculators": [
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator
            ]
        },
        "alarm": {
            "name": "安全告警解读",
            "agent": "alarm",
            "biz_type": 1,
            "id_field": "alarm_id",
            "api_client": AlarmAPIClient,
            "calculators": [
                RiskLevelCalculator,
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator
            ],
            "required_sections": [
                "告警定性", "关键实体", "攻击结果与举证",
                "当前攻击影响", "风险预测", "处置建议"
            ]
        },
        "event": {
            "name": "安全事件解读",
            "agent": "event",
            "biz_type": 2,
            "id_field": "event_id",
            "api_client": EventAPIClient,
            "calculators": [
                RiskLevelCalculator,
                ResponseTimeCalculator,
                FieldCompletenessCalculator,
                FormatComplianceCalculator
            ],
            "required_sections": [
                "事件定性", "关键实体", "攻击结果与举证",
                "当前攻击影响", "风险预测", "处置建议"
            ]
        },
        "sandbox": {
            "name": "沙箱报告解读",
            "agent": "sandbox",
            "biz_type": 6,
            "id_field": "sandbox_id",
            "api_client": SandboxAPIClient,
            "calculators": [
                SandboxRiskLevelCalculator,
                SandboxInfoExtractionCalculator,
                SandboxDisposalCalculator,
                SandboxFormatCalculator,
                SandboxCompletenessCalculator,
            ],
            "required_sections": [
                "执行环境", "样本信息", "风险评估", "违规与检测依据",
                "关键系统行为", "网络行为分析", "释放文件分析",
                "黑名单命中情况", "威胁类型判断",
                "总体风险判断", "建议处置方式"
            ]
        }
    }

    def __init__(self, config: Optional[ConfigLoader] = None):
        self.config = config or ConfigLoader()
        self.test_case_manager = TestCaseManager()
        self.ai_extractor = AIExtractor()
        self.report_generator = ReportGenerator()
        self.results: Dict[str, List[TestResult]] = {}
        # 记录启动时的时间戳，整个测试过程统一用此目录（跨午夜不变，多次执行不覆盖）
        self.run_date = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 各模块 API 客户端在初始化时统一创建（只登录一次），后续复用
        self._asset_client = AssetAPIClient(self.config)
        self._alarm_client = AlarmAPIClient(self.config)
        self._event_client = EventAPIClient(self.config)
        self._vuln_client = VulnAPIClient(self.config)
        self._sandbox_client = SandboxAPIClient(self.config)

    def call_ai_with_timing(
        self,
        module: str,
        input_id: str
    ) -> Dict[str, Any]:
        """调用 AI 接口并测量响应时间"""

        # 沙箱模块使用异步接口（submit + 轮询getResult），不走SSE流式chat
        if module == "sandbox":
            return self._call_sandbox_ai(input_id)

        import uuid

        config = self.MODULE_CONFIG[module]
        base_url = self.config.base_url
        headers = self.config.headers

        # 本地生成 sessionId（UUID 格式，模拟服务端生成格式）
        session_id = f"-1@{uuid.uuid4()}"
        alarm_info = ""

        if module == "alarm":
            api_data = self._alarm_client.get_alarm_detail(input_id)
            alarm_info = ""
            if api_data and "error" not in api_data:
                alarm_type = api_data.get("alarm_type", "")
                if alarm_type:
                    alarm_info = f"查询木马相关域名：{alarm_type}，"
            question = f"请为我分析检测到{alarm_info}告警ID：{input_id}"
        elif module == "event":
            question = f"请为我调查这个安全事件,事件ID: {input_id}"
        elif module == "vuln":
            question = f"请为我分析这个漏洞,编号：{input_id}"
        else:  # asset
            question = f"请为我调查这个资产,资产ID: {input_id}"

        chat_url = f"{base_url}/maxs/szr/chat/chat"
        chat_payload = {
            "newSession": True,
            "userId": -1,
            "question": question,
            "sessionId": session_id,
            "tag": "id",
            "bizType": config["biz_type"],
            "bizId": input_id,
            "agent": config["agent"],
            "network": False,
            "fileId": [],
            "recommend": False
        }

        raw_text = ""
        recommend_questions = []
        first_packet_time = None
        total_time = None
        start_time = time.time()

        try:
            resp = requests.post(
                chat_url,
                headers={**headers, "Accept": "text/event-stream"},
                json=chat_payload,
                stream=True,
                verify=False,
                timeout=180
            )
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}

            content_type = resp.headers.get("Content-Type", "")
            if "text/event-stream" not in content_type:
                try:
                    body = resp.text[:500]
                    err_data = json.loads(body)
                    err_msg = err_data.get("message", body)
                except Exception:
                    err_msg = body if content_type else "响应非SSE流"
                return {"success": False, "error": f"非SSE响应(Content-Type={content_type}): {err_msg}"}

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
                        total_time = time.time() - start_time
                        break
                    try:
                        json_data = json.loads(data_str)
                        code = json_data.get("code")
                        answer_type = str(json_data.get("answerType", "")).lower()

                        # 各模块按各自的终止信号记录报告生成结束时间
                        if str(code) == "200" and total_time is None:
                            data_val = json_data.get("data", "")
                            # 告警/事件：收到 recommend_start 时结束计时
                            if module in ("alarm", "event") and answer_type == "recommend_start":
                                total_time = time.time() - start_time
                            # 漏洞：收到 answerType=text, data="<END_OF_TURN>" 时结束计时
                            elif module == "vuln" and answer_type == "text" and data_val == "<END_OF_TURN>":
                                total_time = time.time() - start_time
                            # 资产：收到 confirm_plan_start 时结束计时
                            elif module == "asset" and answer_type == "confirm_plan_start":
                                total_time = time.time() - start_time

                        # 兼容不同返回结构
                        chunk = json_data.get("data", "")
                        if isinstance(chunk, dict):
                            chunk = chunk.get("content") or chunk.get("text") or ""
                        if not isinstance(chunk, str):
                            chunk = str(chunk) if chunk is not None else ""

                        # 接受 text / markdown 等常见类型，避免因类型变化导致丢失正文
                        accepted_types = {"text", "markdown", "md", "content", "answer", ""}
                        if str(code) == "200" and answer_type in accepted_types and chunk:
                            raw_text += chunk

                        # 捕获推荐问题（answerType=recommend）
                        if str(code) == "200" and answer_type == "recommend" and chunk:
                            try:
                                questions = json.loads(chunk) if isinstance(chunk, str) else chunk
                                if isinstance(questions, list):
                                    recommend_questions = questions
                            except Exception:
                                pass

                        # 某些场景 answerType 缺失或非标准，但 data 中仍有可用文本
                        if str(code) == "200" and chunk and not answer_type:
                            raw_text += chunk
                    except:
                        continue
        except Exception as e:
            return {"success": False, "error": str(e)}

        if not raw_text:
            return {"success": False, "error": "无AI响应内容"}

        # 检测 AI 返回的是平台错误提示而非真实解读内容
        AI_ERROR_PATTERNS = [
            "AI大模型连接异常",
            "请检查「平台配置",
            "AI大模型配置",
        ]
        for pattern in AI_ERROR_PATTERNS:
            if pattern in raw_text:
                return {"success": False, "error": f"AI平台异常（大模型连接失败）: {raw_text[:100].strip()}"}

        if total_time is None:
            total_time = time.time() - start_time

        parsed_data = self._parse_by_module(module, raw_text)

        return {
            "success": True,
            "raw_text": raw_text,
            "parsed_data": parsed_data,
            "first_packet_time": first_packet_time or 0,
            "total_time": total_time or 0,
            "recommend_questions": recommend_questions
        }

    def _call_sandbox_ai(self, biz_id: str) -> Dict[str, Any]:
        """沙箱模块专用：异步submit + 轮询getResult获取解读报告"""
        start_time = time.time()

        result = self._sandbox_client.submit_and_wait(biz_id, biz_type=6, poll_interval=5, max_wait=180)

        if not result.get("success"):
            return {"success": False, "error": result.get("error", "沙箱解读失败")}

        raw_text = result["result"]
        first_packet_time = result.get("first_packet_time", 0)
        total_time = result.get("total_time", time.time() - start_time)

        parsed_data = self._parse_sandbox(raw_text)

        return {
            "success": True,
            "raw_text": raw_text,
            "parsed_data": parsed_data,
            "first_packet_time": first_packet_time,
            "total_time": total_time,
            "recommend_questions": []
        }

    def _parse_sandbox(self, raw_text: str) -> Dict[str, Any]:
        """解析沙箱AI解读报告"""
        from core.extractors.sandbox_extractor import SandboxExtractor
        extractor = SandboxExtractor()
        return extractor.extract_all(raw_text)

    def save_results(self, module: str, input_id: str, raw_text: str, parsed_data: Dict[str, Any], recommend_questions: list = None, index: int = None) -> None:
        """保存解析结果到文件（用启动日期归档，避免跨午夜目录切换）

        Args:
            index: 样本序号（对应 config 顺序），非空时文件名加序号前缀，便于对照
        """
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs", "ai_test_agent", self.run_date)

        if module == "asset":
            md_dir = os.path.join(output_dir, "asset_raw_md")
            json_dir = os.path.join(output_dir, "asset_raw_json")
            prefix = "asset_report"
            data_prefix = "asset_data"
        elif module == "vuln":
            md_dir = os.path.join(output_dir, "vuln_raw_md")
            json_dir = os.path.join(output_dir, "vuln_raw_json")
            prefix = "vuln_report"
            data_prefix = "vuln_data"
        elif module == "alarm":
            md_dir = os.path.join(output_dir, "alarm_raw_md")
            json_dir = os.path.join(output_dir, "alarm_raw_json")
            prefix = "alarm_report"
            data_prefix = "alarm_data"
        elif module == "event":
            md_dir = os.path.join(output_dir, "event_raw_md")
            json_dir = os.path.join(output_dir, "event_raw_json")
            prefix = "event_report"
            data_prefix = "event_data"
        elif module == "sandbox":
            md_dir = os.path.join(output_dir, "sandbox_raw_md")
            json_dir = os.path.join(output_dir, "sandbox_raw_json")
            prefix = "sandbox_report"
            data_prefix = "sandbox_data"
        else:
            return

        os.makedirs(md_dir, exist_ok=True)
        os.makedirs(json_dir, exist_ok=True)

        # 文件名带序号前缀（对应 config 顺序），便于排序后对照
        if index is not None:
            md_name = f"{prefix}_{index:02d}_{input_id}.md"
            json_name = f"{data_prefix}_{index:02d}_{input_id}.json"
        else:
            md_name = f"{prefix}_{input_id}.md"
            json_name = f"{data_prefix}_{input_id}.json"

        md_file = os.path.join(md_dir, md_name)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(f"# AI 智能体响应 - {self.MODULE_CONFIG[module]['name']}报告\n\n")
            f.write(f"**{self.MODULE_CONFIG[module]['id_field']}**: {input_id}\n\n")
            f.write(f"**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write(raw_text)
            # 追加推荐问题
            if recommend_questions:
                f.write("\n\n---\n\n## 💡 推荐问题\n\n")
                for i, q in enumerate(recommend_questions, 1):
                    f.write(f"{i}. {q}\n")

        json_file = os.path.join(json_dir, json_name)
        with open(json_file, 'w', encoding='utf-8') as f:
            save_data = {
                self.MODULE_CONFIG[module]['id_field']: input_id,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "parsed_fields": parsed_data,
                "recommend_questions": recommend_questions or []
            }
            json.dump(save_data, f, ensure_ascii=False, indent=2)

    def _parse_by_module(self, module: str, raw_text: str) -> Dict[str, Any]:
        """根据模块类型解析 AI 输出"""
        if module == "asset":
            result = self.ai_extractor.extract_from_markdown(raw_text)

            # 章节结构完整率（风险速览、风险轨迹、当前威胁）
            config = self.MODULE_CONFIG["asset"]
            missing = [s for s in config["required_sections"] if s not in raw_text]
            result['missing_sections'] = missing
            result['format_compliance'] = (len(config["required_sections"]) - len(missing)) / len(config["required_sections"]) if config["required_sections"] else 0

            return result
        elif module == "vuln":
            return self._parse_vuln(raw_text)
        elif module == "alarm":
            return self._parse_alarm(raw_text)
        elif module == "event":
            return self._parse_event(raw_text)
        return {}

    def _parse_vuln(self, raw_text: str) -> Dict[str, Any]:
        """解析漏洞解读输出（动态章节逻辑）"""
        result = {}
        from core.extractors.text_extractor import TextExtractor
        extractor = TextExtractor()

        # 1. 提取核心结论：是否立即处置
        need_fix_conclusion = self._extract_need_immediate_fix(raw_text)
        result['need_immediate_fix'] = need_fix_conclusion

        # 2. 根据「是否需要立即处置」结论（是/否）动态确定必检章节
        required_sections = ["漏洞概要", "漏洞原理", "修复建议"]
        if need_fix_conclusion == "是":
            required_sections.append("资产波及范围")

        # 3. 按章节标题结构匹配（summary / ## 标题），避免正文子串误命中
        missing = [s for s in required_sections if not self._vuln_section_present(raw_text, s)]
        result['missing_sections'] = missing
        result['required_sections'] = required_sections
        result['format_compliance'] = (len(required_sections) - len(missing)) / len(required_sections) if required_sections else 0

        return result

    def _parse_alarm(self, raw_text: str) -> Dict[str, Any]:
        """解析安全告警解读输出"""
        result = {}
        import re
        from core.extractors.text_extractor import TextExtractor
        extractor = TextExtractor()

        # 提取威胁定性（取最后一个匹配）
        threat_determination = extractor.extract_table_field(raw_text, "威胁定性")
        if not threat_determination:
            matches = re.findall(r'威胁定性(?:结论)?[：:]\s*\*{0,2}\s*(正报|误报|不能确认)', raw_text)
            if matches:
                threat_determination = matches[-1]
        result['threat_determination'] = threat_determination if threat_determination else "未获取到"

        # 提取攻击结果
        attack_result = extractor.extract_table_field(raw_text, "攻击结果")
        if not attack_result:
            # 兼容多种格式：
            # "攻击结果：未知" / "**攻击结果：** 未知" / "攻击结果：**未知**"
            match = re.search(
                r'(?:事件级)?攻击结果[：:]\s*\*{0,2}\s*(成功|失败|未知)\s*\*{0,2}',
                raw_text
            )
            if match:
                attack_result = match.group(1)
        result['attack_result'] = attack_result if attack_result else "未获取到"

        config = self.MODULE_CONFIG["alarm"]
        missing = [s for s in config["required_sections"] if s not in raw_text]
        result['missing_sections'] = missing
        result['format_compliance'] = (len(config["required_sections"]) - len(missing)) / len(config["required_sections"])

        return result

    def _parse_event(self, raw_text: str) -> Dict[str, Any]:
        """解析安全事件解读输出"""
        result = {}
        import re
        from core.extractors.text_extractor import TextExtractor
        extractor = TextExtractor()

        # 提取威胁定性（取最后一个匹配）
        threat_determination = extractor.extract_table_field(raw_text, "威胁定性")
        if not threat_determination:
            matches = re.findall(r'威胁定性(?:结论)?[：:]\s*\*{0,2}\s*(正报|误报|不能确认)', raw_text)
            if matches:
                threat_determination = matches[-1]
        result['threat_determination'] = threat_determination if threat_determination else "未获取到"

        # 提取攻击结果
        attack_result = extractor.extract_table_field(raw_text, "攻击结果")
        if not attack_result:
            # 兼容多种格式：
            # "攻击结果：未知" / "**攻击结果：** 未知" / "攻击结果：**未知**"
            match = re.search(
                r'(?:事件级)?攻击结果[：:]\s*\*{0,2}\s*(成功|失败|未知)\s*\*{0,2}',
                raw_text
            )
            if match:
                attack_result = match.group(1)
        result['attack_result'] = attack_result if attack_result else "未获取到"

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
            agent_id=f"ai_interpret_{test_case.module}",
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

            result.input_id = input_id

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
            result.recommend_questions = ai_response.get("recommend_questions", [])

            print(f"   ✅ AI调用成功")
            print(f"   ⏱️ 首包响应: {result.first_packet_time:.2f}秒, 总响应: {result.total_response_time:.2f}秒")
            if result.recommend_questions:
                print(f"   💡 推荐问题: {len(result.recommend_questions)}个")

            # 从 case_id 提取序号（如 sandbox_test_01 → 1），用于文件名标注
            import re as _re
            _m = _re.search(r'_(\d+)$', test_case.case_id)
            index = int(_m.group(1)) if _m else None

            self.save_results(test_case.module, input_id, result.raw_text, result.parsed_data, result.recommend_questions, index=index)

            result.metrics = self._calculate_metrics(test_case.module, result, input_id)

            # 失效样本提示（API查不到业务数据）
            if result.is_invalid:
                print(f"   ⚠️ 失效样本: {result.error}")
                print(f"   ⚠️ 该样本不参与指标计算")

            # 显示模块专属指标
            module_display_metrics = {
                "asset": {
                    "metrics_order": ["chapter_structure_completeness", "risk_level_accuracy"],
                    "labels": {
                        "chapter_structure_completeness": "1.结构完整率",
                        "risk_level_accuracy": "2.风险等级准确率"
                    }
                },
                "vuln": {
                    "metrics_order": ["dynamic_structure_completeness"],
                    "labels": {
                        "dynamic_structure_completeness": "1.动态结构完整率"
                    }
                },
                "alarm": {
                    "metrics_order": ["chapter_structure_completeness", "threat_determination_accuracy", "attack_result_accuracy"],
                    "labels": {
                        "chapter_structure_completeness": "1.6章结构完整率",
                        "threat_determination_accuracy": "2.威胁定性准确率",
                        "attack_result_accuracy": "3.攻击结果准确率"
                    }
                },
                "event": {
                    "metrics_order": ["chapter_structure_completeness", "threat_determination_accuracy", "attack_result_accuracy"],
                    "labels": {
                        "chapter_structure_completeness": "1.6章结构完整率",
                        "threat_determination_accuracy": "2.威胁定性准确率",
                        "attack_result_accuracy": "3.攻击结果准确率"
                    }
                },
                "sandbox": {
                    "metrics_order": ["risk_level_accuracy", "sample_info_accuracy", "disposal_rationality", "format_compliance", "section_completeness"],
                    "labels": {
                        "risk_level_accuracy": "1.风险评估等级判定准确性",
                        "sample_info_accuracy": "2.样本信息提取正确率",
                        "disposal_rationality": "3.处置建议合理性",
                        "format_compliance": "4.格式规范性",
                        "section_completeness": "5.章节完整性"
                    }
                }
            }

            # 通用指标显示
            for time_metric in ["first_packet_time", "total_response_time"]:
                if time_metric in result.metrics:
                    mv = result.metrics[time_metric]
                    label = "首包响应时间" if time_metric == "first_packet_time" else "总包处理时长"
                    dv = mv.get("value", "")
                    ds = mv.get("score", "")
                    dp = "✅" if mv.get("passed", False) else "❌"
                    if ds != "":
                        print(f"   ⏱️ {label}: {dv:.2f}{mv.get('unit', '')} (得分: {ds}/{mv.get('max_score', 5.0)}) {dp}")

            # 模块专属指标显示
            display_cfg = module_display_metrics.get(test_case.module, {})
            for metric_key in display_cfg.get("metrics_order", []):
                if metric_key in result.metrics:
                    mv = result.metrics[metric_key]
                    label = display_cfg["labels"].get(metric_key, metric_key)
                    acc = mv.get("accuracy", mv.get("value", ""))
                    score = mv.get("score", "")

                    # 优先判断完美得分
                    is_perfect = mv.get("accuracy") == 1.0 or str(mv.get("accuracy")) == "100.0%" or (mv.get("score") is not None and mv.get("max_score") is not None and mv.get("score") == mv.get("max_score"))
                    original_passed = mv.get("is_passed", mv.get("passed", False))
                    dp = "✅" if is_perfect or original_passed else "❌"

                    ai_str = f", AI: {mv.get('ai_value', '')}" if mv.get('ai_value') else ""
                    api_str = f", API: {mv.get('api_value', '')}" if mv.get('api_value') else ""
                    print(f"   📊 {label}: {acc}{ai_str}{api_str} {dp}")

                    # 补充显示缺失章节
                    if metric_key.endswith("structure_completeness") and not mv.get("is_passed", mv.get("passed", False)):
                        missing_sections = mv.get("detail", {}).get("missing_sections", [])
                        if missing_sections:
                            print(f"     👉 缺失章节: {', '.join(missing_sections)}")

        except Exception as e:
            result.error = str(e)
            print(f"   ❌ 测试执行异常: {e}")

        result.standard_result = self.to_standard_result(result)
        return result

    def to_standard_result(self, test_result: TestResult) -> StandardResult:
        """将 TestResult 转换为 StandardResult 契约对象

        所有智能体的测试结果归一为 StandardResult，供后续跨智能体聚合和统一报告使用。
        """
        if not test_result.success:
            status = STATUS_FAILED
        elif test_result.is_invalid:
            status = STATUS_INVALID
        else:
            status = STATUS_VALID

        agent_id = test_result.agent_id or f"ai_interpret_{test_result.module}"

        _METRIC_FALLBACK = {
            "first_packet_time": {"dimension": "performance", "name_cn": "首包响应时间"},
            "total_response_time": {"dimension": "performance", "name_cn": "总响应时间"},
        }

        metric_list = []
        for metric_key, metric_data in (test_result.metrics or {}).items():
            if not isinstance(metric_data, dict):
                continue
            fallback = _METRIC_FALLBACK.get(metric_key, {})
            dimension = metric_data.get("dimension", fallback.get("dimension", "accuracy"))
            metric = metric_from_calculator_result(metric_data, dimension)
            if not metric.key:
                metric.key = metric_key
            if not metric.name_cn:
                metric.name_cn = fallback.get("name_cn", metric_key)
            metric_list.append(metric)

        return StandardResult(
            agent_id=agent_id,
            case_id=test_result.case_id,
            sample_id=test_result.input_id,
            run_id=self.run_date,
            status=status,
            first_packet_time=test_result.first_packet_time,
            total_response_time=test_result.total_response_time,
            metrics=metric_list,
            raw_text=test_result.raw_text,
            error=test_result.error,
            timestamp=test_result.timestamp,
        )

    def _calculate_metrics(self, module: str, test_result: TestResult, input_id: str) -> Dict[str, Any]:
        """计算各项指标

        每个模块的指标体系：
        - 资产解读：风险等级准确率(加权准确率), 结构完整率(3大章+7子章), 首包响应时间, 总包处理时长
        - 漏洞解读：动态结构完整率, 首包响应时间, 总包处理时长
        - 告警解读：6章结构完整率, 威胁定性准确率(加权准确率), 攻击结果准确率(加权准确率), 首包响应时间, 总包处理时长
        - 事件解读：6章结构完整率, 威胁定性准确率(加权准确率), 攻击结果准确率(加权准确率), 首包响应时间, 总包处理时长
        """
        metrics = {}

        # ========== 通用指标：首包响应时间 ==========
        total_threshold = 100 if module == "sandbox" else 150
        metrics["first_packet_time"] = {
            "value": test_result.first_packet_time,
            "unit": "秒",
            "threshold": "≤3秒",
            "passed": test_result.first_packet_time <= 3,
            "dimension": "performance"
        }

        # ========== 通用指标：总包处理时长 ==========
        metrics["total_response_time"] = {
            "value": test_result.total_response_time,
            "unit": "秒",
            "threshold": f"≤{total_threshold}秒",
            "passed": test_result.total_response_time <= total_threshold,
            "dimension": "performance"
        }

        # ========== 资产解读模块 ==========
        if module == "asset":
            # 0. 检测不完整报告：连接中断导致AI未完成生成，全无报告章节（风险速览/风险轨迹/当前威胁），不参与指标计算
            asset_sections = ["风险速览", "风险轨迹", "当前威胁"]
            raw_text = test_result.raw_text or ""
            if not any(s in raw_text for s in asset_sections):
                test_result.is_invalid = True
                test_result.error = "AI未完成报告生成（所有必需章节缺失），属于失效样本"
                return metrics

            # 1. 结构完整率
            from core.calculators import StructureCompletenessCalculator
            try:
                struct_metric = StructureCompletenessCalculator(module="asset").calculate({"raw_text": test_result.raw_text})
                metrics["chapter_structure_completeness"] = struct_metric.to_dict()
            except Exception as e:
                metrics["chapter_structure_completeness"] = {
                    "metric_name": "chapter_structure_completeness",
                    "metric_cn": "结构完整率",
                    "accuracy": 0.0,
                    "ai_value": "解析异常",
                    "api_value": "3/3",
                    "is_passed": False,
                    "detail": {"error": str(e)}
                }

            # 2. 风险等级准确率（单样本0/1，多样本取均值即加权准确率）
            if test_result.parsed_data:
                api_data = self._asset_client.get_asset_detail(input_id)
                if api_data and "error" not in api_data:
                    from core.calculators import RiskLevelCalculator
                    try:
                        risk_metric = RiskLevelCalculator().calculate(test_result.parsed_data, api_data)
                        metrics["risk_level_accuracy"] = risk_metric.to_dict()
                    except Exception as e:
                        metrics["risk_level_accuracy"] = {
                            "metric_name": "risk_level_accuracy",
                            "metric_cn": "风险等级准确率",
                            "score": 0.0, "max_score": 20.0, "accuracy": 0.0,
                            "ai_value": test_result.parsed_data.get("risk_level"),
                            "api_value": api_data.get("risk_level"),
                            "is_passed": False,
                            "detail": {"error": str(e)}
                        }
                else:
                    test_result.is_invalid = True
                    test_result.error = f"API未查询到资产 {input_id} 的信息，属于失效样本"

        # ========== 漏洞解读模块（逻辑已移至 _parse_vuln） ==========
        elif module == "vuln":
            # 动态结构完整率的计算已在 _parse_vuln 中完成，这里只需传递
            if test_result.parsed_data and "format_compliance" in test_result.parsed_data:
                metrics["dynamic_structure_completeness"] = {
                    "metric_name": "dynamic_structure_completeness",
                    "metric_cn": "动态结构完整率",
                    "accuracy": test_result.parsed_data["format_compliance"],
                    "ai_value": f'{len(test_result.parsed_data.get("required_sections", [])) - len(test_result.parsed_data.get("missing_sections", []))}/{len(test_result.parsed_data.get("required_sections", []))}',
                    "api_value": "动态章节",
                    "is_passed": test_result.parsed_data["format_compliance"] == 1.0,
                    "dimension": "accuracy",
                    "detail": test_result.parsed_data
                }

        # ========== 安全告警解读模块 ==========
        elif module == "alarm":
            from core.calculators import StructureCompletenessCalculator, ThreatDeterminationCalculator, AttackResultCalculator

            # 1. 6章结构完整率
            try:
                struct_metric = StructureCompletenessCalculator(module="alarm").calculate({"raw_text": test_result.raw_text})
                metrics["chapter_structure_completeness"] = struct_metric.to_dict()
            except Exception as e:
                metrics["chapter_structure_completeness"] = {
                    "metric_name": "chapter_structure_completeness",
                    "metric_cn": "6章结构完整率",
                    "score": 0.0, "max_score": 5.0, "accuracy": 0.0,
                    "ai_value": "解析异常", "api_value": "6/6",
                    "is_passed": False,
                    "detail": {"error": str(e)}
                }

            # 2. 威胁定性准确率 + 攻击结果准确率
            api_detail = self._alarm_client.get_alarm_detail_by_id(input_id)
            api_valid = api_detail and "error" not in api_detail
            if not api_valid:
                test_result.is_invalid = True
                test_result.error = f"API未查询到告警 {input_id} 的信息，属于失效样本"
            if test_result.parsed_data and api_valid:
                try:
                    td_metric = ThreatDeterminationCalculator().calculate(test_result.parsed_data, api_detail)
                    metrics["threat_determination_accuracy"] = td_metric.to_dict()
                except Exception as e:
                    metrics["threat_determination_accuracy"] = {
                        "metric_name": "threat_determination_accuracy",
                        "metric_cn": "威胁定性准确率",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": test_result.parsed_data.get("threat_determination"),
                        "api_value": api_detail.get("threat_determination"),
                        "is_passed": False,
                        "detail": {"error": str(e)}
                    }

                try:
                    ar_metric = AttackResultCalculator().calculate(test_result.parsed_data, api_detail)
                    metrics["attack_result_accuracy"] = ar_metric.to_dict()
                except Exception as e:
                    metrics["attack_result_accuracy"] = {
                        "metric_name": "attack_result_accuracy",
                        "metric_cn": "攻击结果准确率",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": test_result.parsed_data.get("attack_result"),
                        "api_value": api_detail.get("attack_result"),
                        "is_passed": False,
                        "detail": {"error": str(e)}
                    }

        # ========== 安全事件解读模块 ==========
        elif module == "event":
            from core.calculators import StructureCompletenessCalculator, ThreatDeterminationCalculator, AttackResultCalculator

            # 1. 6章结构完整率
            try:
                struct_metric = StructureCompletenessCalculator(module="event").calculate({"raw_text": test_result.raw_text})
                metrics["chapter_structure_completeness"] = struct_metric.to_dict()
            except Exception as e:
                metrics["chapter_structure_completeness"] = {
                    "metric_name": "chapter_structure_completeness",
                    "metric_cn": "6章结构完整率",
                    "score": 0.0, "max_score": 5.0, "accuracy": 0.0,
                    "ai_value": "解析异常", "api_value": "6/6",
                    "is_passed": False,
                    "detail": {"error": str(e)}
                }

            # 2. 威胁定性准确率 + 攻击结果准确率
            api_detail = self._event_client.get_event_detail_by_id(input_id)
            api_valid = api_detail and "error" not in api_detail
            if not api_valid:
                test_result.is_invalid = True
                test_result.error = f"API未查询到事件 {input_id} 的信息，属于失效样本"
            if test_result.parsed_data and api_valid:
                try:
                    td_metric = ThreatDeterminationCalculator().calculate(test_result.parsed_data, api_detail)
                    metrics["threat_determination_accuracy"] = td_metric.to_dict()
                except Exception as e:
                    metrics["threat_determination_accuracy"] = {
                        "metric_name": "threat_determination_accuracy",
                        "metric_cn": "威胁定性准确率",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": test_result.parsed_data.get("threat_determination"),
                        "api_value": api_detail.get("threat_determination"),
                        "is_passed": False,
                        "detail": {"error": str(e)}
                    }

                try:
                    ar_metric = AttackResultCalculator().calculate(test_result.parsed_data, api_detail)
                    metrics["attack_result_accuracy"] = ar_metric.to_dict()
                except Exception as e:
                    metrics["attack_result_accuracy"] = {
                        "metric_name": "attack_result_accuracy",
                        "metric_cn": "攻击结果准确率",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": test_result.parsed_data.get("attack_result"),
                        "api_value": api_detail.get("attack_result"),
                        "is_passed": False,
                        "detail": {"error": str(e)}
                    }

        # ========== 沙箱报告解读模块 ==========
        elif module == "sandbox":
            from core.extractors.sandbox_extractor import SandboxExtractor
            extractor = SandboxExtractor()

            # 获取沙箱原始报告（EXT_FIELD_ONE）作为基准真值，直接用文件哈希/文件名查找
            sandbox_api = self._sandbox_client.get_sandbox_detail(input_id)
            api_valid = sandbox_api and "error" not in sandbox_api

            if not api_valid:
                test_result.is_invalid = True
                test_result.error = f"未获取到沙箱报告 {input_id} 的原始数据，属于失效样本"
            else:
                biz_content = sandbox_api.get("biz_content", {})
                api_risk = extractor.extract_risk_from_api(biz_content)
                api_info = extractor.extract_sample_info_from_api(biz_content)
                api_data = {"risk_level": api_risk, "sample_info": api_info}

                # 1. 风险等级判定准确率（关键项）
                try:
                    risk_metric = SandboxRiskLevelCalculator().calculate(test_result.parsed_data, api_data)
                    metrics["risk_level_accuracy"] = risk_metric.to_dict()
                except Exception as e:
                    metrics["risk_level_accuracy"] = {
                        "metric_name": "risk_level_accuracy", "metric_cn": "风险等级判定准确率",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": test_result.parsed_data.get("risk_level", "未获取到"),
                        "api_value": api_risk, "is_passed": False, "detail": {"error": str(e)}
                    }

                # 2. 样本基本信息提取正确率
                try:
                    info_metric = SandboxInfoExtractionCalculator().calculate(test_result.parsed_data, api_data)
                    metrics["sample_info_accuracy"] = info_metric.to_dict()
                except Exception as e:
                    metrics["sample_info_accuracy"] = {
                        "metric_name": "sample_info_accuracy", "metric_cn": "样本基本信息提取正确率",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": "", "api_value": "", "is_passed": False, "detail": {"error": str(e)}
                    }

                # 3. 处置建议合理性（LLM-as-a-Judge，需传入 raw_text 作为上下文）
                try:
                    ai_data_with_raw = {**test_result.parsed_data, "raw_text": test_result.raw_text}
                    disposal_metric = SandboxDisposalCalculator().calculate(ai_data_with_raw, api_data)
                    metrics["disposal_rationality"] = disposal_metric.to_dict()
                except Exception as e:
                    metrics["disposal_rationality"] = {
                        "metric_name": "disposal_rationality", "metric_cn": "处置建议合理性",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": "", "api_value": "", "is_passed": False, "detail": {"error": str(e)}
                    }

                # 4. 格式规范性
                try:
                    format_metric = SandboxFormatCalculator().calculate(test_result.parsed_data)
                    metrics["format_compliance"] = format_metric.to_dict()
                except Exception as e:
                    metrics["format_compliance"] = {
                        "metric_name": "format_compliance", "metric_cn": "格式规范性",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": "", "api_value": "", "is_passed": False, "detail": {"error": str(e)}
                    }

                # 5. 章节完整性
                try:
                    completeness_metric = SandboxCompletenessCalculator().calculate(test_result.parsed_data)
                    metrics["section_completeness"] = completeness_metric.to_dict()
                except Exception as e:
                    metrics["section_completeness"] = {
                        "metric_name": "section_completeness", "metric_cn": "章节完整性",
                        "score": 0.0, "max_score": 100.0, "accuracy": 0.0,
                        "ai_value": "", "api_value": "", "is_passed": False, "detail": {"error": str(e)}
                    }

        self._mark_extraction_failures(metrics, test_result.parsed_data)
        return metrics

    def _mark_extraction_failures(self, metrics: Dict[str, Any], parsed_data: Dict[str, Any]) -> None:
        """标记提取失败的指标（AI未获取到值或计算器异常），这些不计入平均准确率

        判定规则：
        1. detail中含error字段 → 计算器异常（适用于所有指标）
        2. AI值为"未获取到"/"无法判断"/空 → 提取失败（适用于特定准确率指标）
        两种情况均设置 accuracy=None, is_extraction_failure=True
        """
        invalid_values = {"未获取到", "无法判断", "", None}

        # 第一遍：检查所有指标的计算器异常（detail中有error）
        for metric_key, metric in metrics.items():
            detail = metric.get("detail", {})
            if isinstance(detail, dict) and "error" in detail:
                metric["accuracy"] = None
                metric["score"] = None
                metric["is_passed"] = False
                metric["is_extraction_failure"] = True
                detail["extraction_failure"] = f"{metric.get('metric_cn', metric_key)}计算异常: {detail['error']}"

        # 第二遍：检查特定准确率指标的AI值提取失败
        extraction_check_map = {
            "risk_level_accuracy": ("risk_level", "风险等级"),
            "threat_determination_accuracy": ("threat_determination", "威胁定性"),
            "attack_result_accuracy": ("attack_result", "攻击结果"),
        }

        for metric_key, (data_field, field_cn) in extraction_check_map.items():
            if metric_key not in metrics:
                continue
            metric = metrics[metric_key]
            if metric.get("is_extraction_failure"):
                continue  # 已在第一遍中标记
            ai_value = parsed_data.get(data_field) if parsed_data else None
            if ai_value in invalid_values:
                metric["accuracy"] = None
                metric["score"] = None
                metric["is_passed"] = False
                metric["is_extraction_failure"] = True
                detail = metric.get("detail", {})
                if not isinstance(detail, dict):
                    detail = {}
                    metric["detail"] = detail
                detail["extraction_failure"] = f"AI未提取到{field_cn}值"

    def _extract_one_sentence_summary(self, raw_text: str) -> str:
        """从AI解读文本中提取一句话总结

        优先从 Markdown 表格或章节标题中提取，
        如果找不到则取前 200 个字符作为摘要。
        """
        if not raw_text:
            return ""

        import re

        # 预处理：去除 ** 粗体标记，统一格式（兼容 **一句话总结：** / **一句话总结**： / 一句话总结： 等变体）
        clean_text = raw_text.replace('**', '')

        # 1. 尝试从"一句话总结"或类似标题后提取（在 clean_text 上匹配，避免 ** 干扰）
        summary_patterns = [
            r'(?:一句话总结)\s*[：:为]?\s*(.+?)(?:\n---|\n\n|\n#{1,6}\s|\Z)',
        ]
        for pattern in summary_patterns:
            match = re.search(pattern, clean_text, re.IGNORECASE | re.DOTALL)
            if match:
                summary = match.group(1).strip().replace('\n', '')
                if len(summary) > 10:
                    return summary[:300]

        # 2. 尝试从表格中提取第一个描述性段落
        paragraph_pattern = r'[>|]\s*[*]*(?:分析|描述|总结|概述)[*]*[：:]\s*([^\n|]+)'
        match = re.search(paragraph_pattern, raw_text)
        if match:
            return match.group(1).strip()[:300]

        # 3. 取正文第一段有意义的文字（跳过元数据行如 event_id / 时间 等）
        lines = raw_text.split('\n')
        for line in lines:
            line = line.strip()
            # 跳过标题、空行、纯符号行、元数据行、引用块行（> 开头）
            if not line or line.startswith('#') or line.startswith('---') or line.startswith('|') or line.startswith('>'):
                continue
            # 跳过元数据行：兼容裸 **字段名** 和去粗体后的 字段名：值 等格式
            if re.match(r'^\*{0,2}(?:event_id|事件编号|alarm_id|告警编号|时间|生成时间|告警名称|告警编号|event_name|alarm_name)\*{0,2}[：:\s]', line):
                continue
            if len(line) > 15:
                return line[:300]

        # 4. 最终降级：取前200字符
        return raw_text.strip()[:200]

    def _vuln_section_present(self, raw_text: str, section_name: str) -> bool:
        """检查漏洞报告是否包含指定折叠/标题章节（非正文子串匹配）"""
        import re

        escaped = re.escape(section_name)
        patterns = [
            rf'第\s*\d+\s*章[：:]\s*{escaped}',
            rf'##\s*(?:第\s*\d+\s*章[：:]\s*)?{escaped}',
            rf'<summary>[^<]*{escaped}',
        ]
        for pattern in patterns:
            if re.search(pattern, raw_text):
                return True
        return False

    def _extract_need_immediate_fix(self, raw_text: str) -> str:
        """从漏洞解读文本中提取「是否需要立即处置」结论，返回 是 / 否 / 无法判断"""
        if not raw_text:
            return ""

        import re

        # 1. 规范权威源：HTML 注释 <!-- VULN_CONCLUSION:是/否 -->
        comment_match = re.search(
            r'<!--\s*VULN_CONCLUSION\s*:\s*(是|否)\s*-->',
            raw_text, re.IGNORECASE
        )
        if comment_match:
            return comment_match.group(1)

        # 2. 研判结论行的显式取值（兼容多种格式）
        # 格式1: **是否需要立即处置：**<span ...>否</span>
        # 格式2: 是否需要立即处置：否
        # 格式3: 是否需要立即处置：**否**
        inline_patterns = [
            r'是否需要立即处置[：:为]?\s*\*{0,2}\s*(?:<\s*span[^>]*>\s*)?(是|否)(?:\s*</\s*span>)?\s*\*{0,2}',
            r'是否需要立即处置[：:为]?\s*\*{0,2}(是|否)\*{0,2}',
        ]
        for pattern in inline_patterns:
            match = re.search(pattern, raw_text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)

        # 3. 兼容旧表述（需要/不需要），同样兼容 ** 和 span 包裹
        legacy_match = re.search(
            r'是否需要立即处置[：:为]?\s*\*{0,2}\s*(?:<\s*span[^>]*>\s*)?(需要|不需要)(?:\s*</\s*span>)?\s*\*{0,2}',
            raw_text, re.IGNORECASE | re.DOTALL
        )
        if legacy_match:
            return "是" if legacy_match.group(1) == "需要" else "否"

        legacy_match2 = re.search(
            r'是否需要立即处置[：:为]?\s*\*{0,2}(需要|不需要)\*{0,2}',
            raw_text, re.IGNORECASE
        )
        if legacy_match2:
            return "是" if legacy_match2.group(1) == "需要" else "否"

        return "无法判断"

    def _check_stability_with_llm_judge(
        self, summary1: str, summary2: str, alarm_description: str
    ) -> Dict[str, Any]:
        """使用LLM裁判判断两次解读的核心结论是否一致

        Args:
            summary1: 第一次解读的一句话总结
            summary2: 第二次解读的一句话总结
            alarm_description: 告警/事件描述（供裁判参考）

        Returns:
            {"passed": bool, "inconsistencies": list, "judge_response": str}
        """
        from core.llm_client import LLMClient

        system_prompt = """你是一个严格的裁判，负责判断两次AI解读的"一句话总结"核心结论是否一致。

判断规则：
1. 如果两次总结的核心意思一致（威胁类型、攻击结果、关键实体等）→ 稳定
2. 如果核心意思有实质性差异（结论相反、威胁类型不同、关键实体不同）→ 不稳定
3. 如果两次总结表达方式不同但核心结论相同 → 算稳定
4. 如果某次总结内容为空或无法提取有效信息 → 算不稳定

请严格按照以下JSON格式输出（不要输出其他内容）：
{
    "is_stable": true/false,
    "reason": "简要说明判断理由",
    "inconsistencies": ["如果有不一致，列出具体不一致之处"]
}
"""

        user_prompt = f"""## 告警/事件描述
{alarm_description[:500]}

## 第一次解读的一句话总结
{summary1[:500]}

## 第二次解读的一句话总结
{summary2[:500]}

请判断两次总结的核心结论是否一致。
"""

        try:
            llm = LLMClient()
            response = llm.call_llm(system_prompt, user_prompt, max_tokens=1024)
            if not response:
                return {"passed": False, "inconsistencies": ["LLM裁判未响应"], "judge_response": ""}

            import json, re
            # 尝试提取 JSON
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return {
                    "passed": result.get("is_stable", False),
                    "inconsistencies": result.get("inconsistencies", []),
                    "judge_response": response
                }

            # 如果没找到JSON，通过关键词判断
            is_stable = "is_stable\": true" in response or "稳定" in response[:50]
            return {
                "passed": is_stable,
                "inconsistencies": [] if is_stable else ["无法解析裁判响应"],
                "judge_response": response
            }
        except Exception as e:
            return {"passed": False, "inconsistencies": [f"LLM裁判异常: {e}"], "judge_response": ""}

    def _check_vuln_stability(self, need_fix1: str, need_fix2: str) -> Dict[str, Any]:
        """直接比较两次漏洞"是否需要立即处置"结论是否一致

        Args:
            need_fix1: 第一次解读的结论
            need_fix2: 第二次解读的结论

        Returns:
            {"passed": bool, "inconsistencies": list}
        """
        if not need_fix1 or not need_fix2:
            return {"passed": False, "inconsistencies": ["某次未提取到结论"]}

        # 归一化为 是/否
        def normalize(text: str) -> str:
            text = text.strip()
            if text in ["是", "需要", "需要立即处置", "需要立即修复", "紧急"]:
                return "是"
            if text in ["否", "不需要", "无需", "无需处置", "暂缓"]:
                return "否"
            return text

        norm1 = normalize(need_fix1)
        norm2 = normalize(need_fix2)

        if norm1 == norm2:
            return {"passed": True, "inconsistencies": []}
        else:
            return {
                "passed": False,
                "inconsistencies": [
                    f"第一次结论为「{need_fix1}」，第二次结论为「{need_fix2}」"
                ]
            }

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
        valid_count = sum(1 for r in results if r.success and not r.is_invalid)
        error_count = sum(1 for r in results if not r.success)
        invalid_count = sum(1 for r in results if r.is_invalid)
        total_count = len(results)

        print(f"\n{'='*60}")
        print(f"📊 {self.MODULE_CONFIG[module]['name']} 模块测试摘要")
        print(f"{'='*60}")
        print(f"   总用例数: {total_count}")
        print(f"   ✅ 有效样本: {valid_count}（参与指标计算）")
        print(f"   ❌ 失败样本: {error_count}（AI调用失败）")
        print(f"   ⚠️ 失效样本: {invalid_count}（API查不到业务数据）")
        if valid_count > 0:
            print(f"   有效率: {valid_count/total_count*100:.1f}%")
            # 列出有效样本ID
            valid_ids = [r.input_id for r in results if r.success and not r.is_invalid]
            print(f"   有效样本ID: {', '.join(valid_ids)}")
        if invalid_count > 0:
            invalid_ids = [r.input_id for r in results if r.is_invalid]
            print(f"   失效样本ID: {', '.join(invalid_ids)}")

        # 输出多样本整体统计
        if module in ["asset", "alarm", "event", "vuln"]:
            multi_sample_stats = self._calculate_multi_sample_stats(module, results)
            if multi_sample_stats:
                print(f"\n📈 多样本整体统计")
                print(f"   {'-'*50}")
                if multi_sample_stats.get("avg_first_packet_time") is not None:
                    print(f"   平均首包响应时间: {multi_sample_stats['avg_first_packet_time']:.2f}秒")
                if multi_sample_stats.get("avg_total_response_time") is not None:
                    print(f"   平均总包处理时长: {multi_sample_stats['avg_total_response_time']:.2f}秒")

                # 打印所有指标的平均准确率
                if multi_sample_stats.get("avg_accuracies"):
                    print(f"\n   各项指标准确率")
                    for key, metric in multi_sample_stats["avg_accuracies"].items():
                        excl = f"（排除{metric['excluded_count']}个提取失败）" if metric.get('excluded_count') else ""
                        print(f"     - {metric['metric_cn']}: {metric['avg_accuracy']:.1%}{excl}")

                print(f"   {'-'*50}")

    def _calculate_multi_sample_stats(self, module: str, results: List[TestResult]) -> Dict[str, Any]:
        """计算多样本整体统计

        所有指标统一使用加权准确率（正确样本数/总样本数，0~1）。
        宏平均F1需各类别≥30样本且均衡分布，不适合真实业务不均衡数据，暂不采用。
        """
        stats = {}
        valid_results = [r for r in results if r.success and r.metrics and not r.is_invalid]
        if not valid_results:
            return stats

        # ========== 1. 响应时间统计 ==========
        first_packet_times = [r.first_packet_time for r in valid_results]
        total_times = [r.total_response_time for r in valid_results]
        if first_packet_times:
            stats["avg_first_packet_time"] = sum(first_packet_times) / len(first_packet_times)
        if total_times:
            stats["avg_total_response_time"] = sum(total_times) / len(total_times)

        # ========== 2. 所有准确率指标：加权准确率（排除提取失败）==========

        metric_aggregates = {}
        for r in valid_results:
            for key, metric_value in r.metrics.items():
                if "accuracy" not in metric_value:
                    continue
                if metric_value.get("is_extraction_failure"):
                    if key not in metric_aggregates:
                        metric_aggregates[key] = {
                            "total_accuracy": 0, "count": 0,
                            "excluded_count": 0,
                            "metric_cn": metric_value.get("metric_cn", key)
                        }
                    metric_aggregates[key]["excluded_count"] += 1
                    continue
                try:
                    accuracy = float(metric_value["accuracy"])
                except (ValueError, TypeError):
                    continue
                if key not in metric_aggregates:
                    metric_aggregates[key] = {
                        "total_accuracy": 0, "count": 0,
                        "excluded_count": 0,
                        "metric_cn": metric_value.get("metric_cn", key)
                    }
                metric_aggregates[key]["total_accuracy"] += accuracy
                metric_aggregates[key]["count"] += 1

        avg_accuracies = {}
        for key, agg in metric_aggregates.items():
            if agg["count"] > 0:
                avg_accuracies[key] = {
                    "metric_cn": agg["metric_cn"],
                    "avg_accuracy": agg["total_accuracy"] / agg["count"],  # 0~1
                    "valid_count": agg["count"],
                    "excluded_count": agg["excluded_count"]
                }

        stats["avg_accuracies"] = avg_accuracies
        return stats

    def run_all_tests(self) -> Dict[str, List[TestResult]]:
        """执行所有模块的测试"""
        print(f"\n{'='*60}")
        print(f"🚀 AI 解读自动化测试智能体 - 全模块测试")
        print(f"{'='*60}")

        # 默认从配置 ID 动态生成用例
        all_test_cases = {}
        config = self.config

        print("  ℹ️ 从配置 ID 动态生成用例...")

        for module in self.MODULE_CONFIG.keys():
                id_field = self.MODULE_CONFIG[module]["id_field"]
                # 映射 config 上的属性
                config_key_map = {
                    "asset": "test_assets",
                    "vuln": "test_vulns",
                    "alarm": "test_alarms",
                    "event": "test_events",
                }
                attr_name = config_key_map.get(module)
                ids = getattr(config, attr_name, []) if attr_name else []
                if ids:
                    cases = []
                    for idx, id_val in enumerate(ids):
                        cases.append(TestCase(
                            case_id=f"{module}_auto_{idx+1:02d}",
                            module=module,
                            input_data={id_field: str(id_val)},
                            expected_output={},
                            description=f"{self.MODULE_CONFIG[module]['name']}测试 - {id_val}",
                            tags=["automated", module]
                        ))
                    all_test_cases[module] = cases

        for module in self.MODULE_CONFIG.keys():
            if module in all_test_cases and all_test_cases[module]:
                self.run_module_tests(module, all_test_cases[module])
            else:
                print(f"  ⏭️ 跳过 {self.MODULE_CONFIG[module]['name']}（无测试ID）")

        self._generate_comprehensive_report()
        return self.results

    def _generate_comprehensive_report(self) -> str:
        """生成综合测试报告（JSON + HTML），每次执行独立目录，不覆盖历史
        
        Returns:
            output_dir: 本次报告所在目录路径（供审查使用）
        """
        report_data = self._prepare_report_data()

        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs", "ai_test_agent", self.run_date)
        os.makedirs(output_dir, exist_ok=True)

        # JSON 报告：每天固定文件名，多次执行覆盖，只保留最新
        json_path = os.path.join(output_dir, "ai_interpret_test_report.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        # StandardResult 契约JSON：提取所有样本的标准化结果，供统一框架消费
        standard_results = []
        for module_results in self.results.values():
            for r in module_results:
                if r.standard_result:
                    standard_results.append(r.standard_result.to_dict())
        sr_path = os.path.join(output_dir, "standard_results.json")
        with open(sr_path, 'w', encoding='utf-8') as f:
            json.dump(standard_results, f, ensure_ascii=False, indent=2)

        print(f"\n{'='*60}")
        print(f"📄 综合测试报告已生成: {json_path}")
        print(f"📄 标准结果契约: {sr_path}（{len(standard_results)}条 StandardResult）")
        
        # 生成 HTML 可视化报告
        html_generator = HTMLReportGenerator(output_dir)
        html_paths = html_generator.generate(report_data)
        for p in html_paths:
            print(f"      ├── {p}")
        
        print(f"{'='*60}")
        return output_dir

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
        total_errors = 0
        total_invalid = 0
        all_first_packet_times = []
        all_total_times = []

        for module, results in self.results.items():
            module_report = self._prepare_module_report(module, results)
            report["modules"][module] = module_report

            total_cases += len(results)
            total_success += sum(1 for r in results if r.success and not r.is_invalid)
            total_errors += sum(1 for r in results if not r.success)
            total_invalid += sum(1 for r in results if r.is_invalid)
            # 仅有效样本的响应时间参与统计
            all_first_packet_times.extend([r.first_packet_time for r in results if r.success and not r.is_invalid])
            all_total_times.extend([r.total_response_time for r in results if r.success and not r.is_invalid])

        report["summary"] = {
            "total_cases": total_cases,
            "total_success": total_success,
            "total_errors": total_errors,
            "total_invalid": total_invalid,
            "valid_count": total_success,
            "success_rate": total_success / total_cases if total_cases > 0 else 0,
            "avg_first_packet_time": sum(all_first_packet_times) / len(all_first_packet_times) if all_first_packet_times else 0,
            "avg_total_response_time": sum(all_total_times) / len(all_total_times) if all_total_times else 0
        }

        return report

    def _prepare_module_report(self, module: str, results: List[TestResult]) -> Dict[str, Any]:
        """准备模块报告数据"""
        module_config = self.MODULE_CONFIG[module]
        success_count = sum(1 for r in results if r.success and not r.is_invalid)
        error_count = sum(1 for r in results if not r.success)
        invalid_count = sum(1 for r in results if r.is_invalid)

        # 仅有效样本的响应时间参与统计
        first_packet_times = [r.first_packet_time for r in results if r.success and not r.is_invalid]
        total_times = [r.total_response_time for r in results if r.success and not r.is_invalid]

        multi_sample_stats = self._calculate_multi_sample_stats(module, results)

        # 有效样本ID列表
        valid_sample_ids = [r.input_id for r in results if r.success and not r.is_invalid]
        # 失效样本ID列表
        invalid_sample_ids = [r.input_id for r in results if r.is_invalid]
        # 失败样本ID列表
        failed_sample_ids = [r.input_id for r in results if not r.success]

        return {
            "name": module_config["name"],
            "total_cases": len(results),
            "success_count": success_count,
            "error_count": error_count,
            "invalid_count": invalid_count,
            "valid_count": success_count,
            "success_rate": success_count / len(results) if results else 0,
            "avg_first_packet_time": sum(first_packet_times) / len(first_packet_times) if first_packet_times else 0,
            "avg_total_response_time": sum(total_times) / len(total_times) if total_times else 0,
            "multi_sample_stats": multi_sample_stats,
            "valid_sample_ids": valid_sample_ids,
            "invalid_sample_ids": invalid_sample_ids,
            "failed_sample_ids": failed_sample_ids,
            "test_cases": [
                {
                    module_config["id_field"]: r.input_id,
                    "case_id": r.case_id,
                    "agent_id": r.agent_id,
                    "success": r.success,
                    "is_invalid": r.is_invalid,
                    "first_packet_time": r.first_packet_time,
                    "total_response_time": r.total_response_time,
                    "error": r.error,
                    "metrics": r.metrics,
                    "standard_result": r.standard_result.to_dict() if r.standard_result else None
                }
                for r in results
            ]
        }

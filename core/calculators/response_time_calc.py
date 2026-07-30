"""
响应时间计算器
计算AI接口的首包响应时间和平均响应时间
"""
import time
import threading
import queue
import requests
import urllib3
from typing import Any, Dict, List, Tuple
from datetime import datetime
from .base_calculator import BaseCalculator, MetricResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ResponseTimeCalculator(BaseCalculator):
    """响应时间计算器"""

    METRIC_NAME = "response_time"
    METRIC_CN = "响应时间"
    MAX_SCORE = 5

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.base_url = config.base_url
        self.headers = config.headers

    def measure_single_asset(self, asset_id: str) -> Tuple[float, float]:
        """测量单个资产的响应时间（秒）

        Returns:
            (首包时间, 总响应时间)
        """
        chat_url = f"{self.base_url}/maxs/szr/chat/chat"
        session_id = f"-1@{datetime.now().strftime('%Y%m%d%H%M%S')}-0000-000000000000"
        timestamp_ms = int(time.time() * 1000)
        random_str = "".join([chr(ord('a') + i % 26) for i in range(8)])
        conversation_id = f"{session_id}@{timestamp_ms}-{random_str}"

        chat_payload = {
            "question": f"请为我调查这个资产,资产ID: {asset_id}",
            "agent": "asset",
            "bizId": asset_id,
            "bizType": 4,
            "fileId": [],
            "network": False,
            "recommend": False,
            "sessionId": session_id,
            "conversationId": conversation_id,
            "tag": "id"
        }

        result_queue = queue.Queue()
        start_time = time.time()

        def send_request():
            try:
                response = requests.post(
                    chat_url,
                    headers={**self.headers, "Content-Type": "application/json"},
                    json=chat_payload,
                    verify=False,
                    timeout=120
                )
                result_queue.put(("request_sent", response.status_code))
            except Exception as e:
                result_queue.put(("error", str(e)))

        def receive_response():
            try:
                connect_url = f"{self.base_url}/maxs/szr/chat/connect"
                connect_params = {"sessionId": session_id}

                first_packet_time = None
                total_time = None

                with requests.get(
                    connect_url,
                    params=connect_params,
                    headers={**self.headers, "Accept": "text/event-stream"},
                    stream=True,
                    verify=False,
                    timeout=120
                ) as resp:
                    for line in resp.iter_lines():
                        elapsed = time.time() - start_time

                        if first_packet_time is None and line:
                            first_packet_time = elapsed

                        if line:
                            try:
                                line_str = line.decode('utf-8')
                                if line_str.startswith("data:") or line_str.startswith("data :"):
                                    data_str = line_str.lstrip().replace("data:", "").replace("data :", "").strip()
                                    if data_str == "[DONE]":
                                        total_time = elapsed
                                        result_queue.put(("done", first_packet_time, total_time))
                                        return
                            except:
                                pass

                if total_time is None:
                    result_queue.put(("done", first_packet_time, time.time() - start_time))

            except Exception as e:
                result_queue.put(("error", str(e)))

        send_thread = threading.Thread(target=send_request)
        recv_thread = threading.Thread(target=receive_response)

        send_thread.start()
        recv_thread.start()

        send_thread.join(timeout=180)
        recv_thread.join(timeout=180)

        first_packet_time = None
        total_time = None

        while not result_queue.empty():
            event_type, *event_data = result_queue.get()
            if event_type == "done":
                first_packet_time = event_data[0] if event_data[0] else 0
                total_time = event_data[1] if len(event_data) > 1 else 0
                break

        return first_packet_time or 0, total_time or 0

    def measure_multiple_assets(self, asset_ids: List[str]) -> Dict[str, Any]:
        """测量多个资产的响应时间

        Args:
            asset_ids: 资产ID列表

        Returns:
            测量结果
        """
        first_packet_times = []
        total_times = []
        successful_count = 0

        for asset_id in asset_ids:
            print(f"  测量资产: {asset_id}")
            fp_time, total_time = self.measure_single_asset(asset_id)

            if total_time > 0:
                first_packet_times.append(fp_time)
                total_times.append(total_time)
                successful_count += 1
                print(f"    首包: {fp_time:.2f}秒, 总时间: {total_time:.2f}秒")

        avg_first_packet = sum(first_packet_times) / len(first_packet_times) if first_packet_times else 0
        avg_total = sum(total_times) / len(total_times) if total_times else 0

        return {
            "asset_count": len(asset_ids),
            "successful_count": successful_count,
            "first_packet_times": first_packet_times,
            "total_times": total_times,
            "avg_first_packet_time": avg_first_packet,
            "avg_total_time": avg_total
        }

    def calculate_first_packet_metric(self, measurement_result: Dict[str, Any]) -> MetricResult:
        """计算首包响应时间指标

        评分标准：
        - <3秒: 100%
        - 3-5秒: 80%
        - 5-10秒: 60%
        - 10-15秒: 40%
        - >15秒: 20%
        """
        avg_fp_time = measurement_result["avg_first_packet_time"]

        if avg_fp_time == 0:
            accuracy = 0.0
        elif avg_fp_time < 3:
            accuracy = 1.0
        elif avg_fp_time < 5:
            accuracy = 0.8
        elif avg_fp_time < 10:
            accuracy = 0.6
        elif avg_fp_time < 15:
            accuracy = 0.4
        else:
            accuracy = 0.2

        detail = {
            "avg_first_packet_time": avg_fp_time,
            "successful_count": measurement_result["successful_count"],
            "total_assets": measurement_result["asset_count"],
            "first_packet_times": measurement_result["first_packet_times"]
        }

        return MetricResult(
            metric_name="first_packet_time",
            metric_cn="首包响应时间",
            score=accuracy * 5,
            max_score=5,
            accuracy=accuracy,
            ai_value=f"{avg_fp_time:.2f}秒",
            api_value="<3秒",
            detail=detail,
            is_passed=accuracy >= 0.8
        )

    def calculate_avg_time_metric(self, measurement_result: Dict[str, Any]) -> MetricResult:
        """计算平均响应时间指标

        评分标准：
        - <30秒: 100%
        - 30-60秒: 80%
        - 60-120秒: 60%
        - >120秒: 40%
        """
        avg_time = measurement_result["avg_total_time"]

        if avg_time == 0:
            accuracy = 0.0
        elif avg_time < 30:
            accuracy = 1.0
        elif avg_time < 60:
            accuracy = 0.8
        elif avg_time < 120:
            accuracy = 0.6
        else:
            accuracy = 0.4

        detail = {
            "avg_total_time": avg_time,
            "successful_count": measurement_result["successful_count"],
            "total_assets": measurement_result["asset_count"],
            "total_times": measurement_result["total_times"]
        }

        return MetricResult(
            metric_name="avg_response_time",
            metric_cn="平均响应时间",
            score=accuracy * 5,
            max_score=5,
            accuracy=accuracy,
            ai_value=f"{avg_time:.2f}秒",
            api_value="<30秒",
            detail=detail,
            is_passed=accuracy >= 0.8
        )

"""
事件列表API客户端
获取资产关联的事件列表
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List
from .base_client import BaseAPIClient


class EventAPIClient(BaseAPIClient):
    """事件列表API客户端"""

    # EVENT_RESULT_FLAG 取值映射（威胁定性）
    EVENT_RESULT_FLAG_MAP = {
        "1": "正报",
        "2": "误报",
        "3": "不能确认",
        "": "不能确认",
        None: "不能确认",
    }

    # RESULT 取值映射（攻击结果）
    ATTACK_RESULT_MAP = {
        "成功": "成功",
        "失败": "失败",
        "未知": "未知",
        "": "未知",
        None: "未知",
        # 支持其他可能的取值
        "attack_success": "成功",
        "attack_failed": "失败",
        "unknown": "未知",
    }

    def get_asset_events(self, asset_id: str, days: int = 90) -> List[str]:
        """获取资产关联的事件ID列表

        Args:
            asset_id: 资产ID
            days: 查询最近几天的事件（默认30天）

        Returns:
            事件ID列表
        """
        endpoint = self.config.event_endpoint

        now = datetime.now()
        end_date = now.strftime("%Y-%m-%d %H:%M:%S")
        start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "selectAllFlag": True,
            "orgIds": ["1"],
            "startTime": start_date,
            "endTime": end_date,
            "advanced": 0,
            "conditionUnitList": [
                {
                    "key": "AFFECTED_ASSET_ID",
                    "operator": "equals",
                    "value": [asset_id]
                }
            ],
            "exact": "1",
            "assetPortraitFlag": True,
            "isEvent": "是",
            "pageIndex": 1,
            "pageSize": 100,
            "order": "desc",
            "sort": "END_TIME"
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return []

        return self._extract_event_ids(response)

    def _extract_event_ids(self, api_response: Dict[str, Any]) -> List[str]:
        """从API响应中提取事件ID列表"""
        events = []

        if api_response.get("error"):
            return []

        data = api_response.get("data", {})
        if isinstance(data, dict):
            row_data = data.get("rowData", [])
        elif isinstance(data, list):
            row_data = data
        else:
            row_data = []

        for record in row_data:
            if isinstance(record, dict):
                event_id = record.get("SNOW_ID") or record.get("snow_id")
                if event_id:
                    event_str = str(event_id).strip()
                    events.append(event_str)

        return list(set(events))

    def get_asset_events_full(self, asset_id: str, days: int = 90) -> List[Dict[str, Any]]:
        """获取资产关联的完整事件信息"""
        endpoint = self.config.event_endpoint

        now = datetime.now()
        end_date = now.strftime("%Y-%m-%d %H:%M:%S")
        start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "selectAllFlag": True,
            "orgIds": ["1"],
            "startTime": start_date,
            "endTime": end_date,
            "advanced": 0,
            "conditionUnitList": [
                {
                    "key": "AFFECTED_ASSET_ID",
                    "operator": "equals",
                    "value": [asset_id]
                }
            ],
            "exact": "1",
            "assetPortraitFlag": True,
            "isEvent": "是",
            "pageIndex": 1,
            "pageSize": 100,
            "order": "desc",
            "sort": "END_TIME"
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return []

        data = api_response.get("data", {})
        row_data = data.get("rowData", []) if isinstance(data, dict) else []

        return row_data

    def get_event_detail_by_id(self, event_id: str) -> Dict[str, Any]:
        """通过 pageEvent 接口获取事件详情，提取威胁定性和攻击结果字段

        API: POST {event_endpoint}
        Payload:
            {
                "selectAllFlag": true,
                "orgIds": ["1"],
                "startTime": "...",
                "endTime": "...",
                "advanced": 0,
                "conditionUnitList": [
                    {
                        "key": "SNOW_ID",
                        "operator": "equals",
                        "value": [event_id]
                    }
                ],
                "exact": "0",
                "pageIndex": 1,
                "pageSize": 10,
                "order": "desc",
                "sort": "END_TIME"
            }

        返回字段及含义:
            1. 威胁定性（EVENT_RESULT_FLAG/ALERT_RESULT_FLAG）:
                1  → 正报
                2  → 误报
                3 或空 → 不能确认
            
            2. 攻击结果（RESULT）:
                直接取 RESULT 字段值，若无或为空则 → 未知

        Args:
            event_id: 事件ID

        Returns:
            {
                "event_id": "xxx",
                "threat_determination": "正报/误报/不能确认",
                "attack_result": "成功/失败/未知",
                "result_raw": "xxx",
                "raw_result": {...}
            } 或 {"error": "错误信息"}
        """
        endpoint = self.config.event_endpoint
        now = datetime.now()
        end_time = now.strftime("%Y-%m-%d %H:%M:%S")
        start_time = (now - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "selectAllFlag": True,
            "orgIds": ["1"],
            "startTime": start_time,
            "endTime": end_time,
            "advanced": 0,
            "conditionUnitList": [
                {
                    "key": "SNOW_ID",
                    "operator": "equals",
                    "value": [event_id]
                }
            ],
            "exact": "0",
            "pageIndex": 1,
            "pageSize": 10,
            "order": "desc",
            "sort": "END_TIME"
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return {"error": response.get("error")}

        data = response.get("data", {})
        row_data = data.get("rowData", []) if isinstance(data, dict) else []

        if not row_data:
            return {"error": "未找到事件"}

        raw = row_data[0]

        # --- 提取威胁定性 ---
        # 尝试多种字段名获取威胁定性标记
        flag_raw = (
            raw.get("EVENT_RESULT_FLAG") or
            raw.get("event_result_flag") or
            raw.get("ALERT_RESULT_FLAG") or
            raw.get("alert_result_flag") or
            ""
        )
        flag_str = str(flag_raw).strip()
        threat_label = self.EVENT_RESULT_FLAG_MAP.get(flag_str, "不能确认")

        # --- 提取攻击结果 ---
        # 从 RESULT 字段获取攻击结果
        result_raw = raw.get("RESULT") or raw.get("result") or ""

        # 确定攻击结果
        attack_label = "未知"
        if result_raw and str(result_raw).strip():
            result_str = str(result_raw).strip()
            attack_label = self.ATTACK_RESULT_MAP.get(result_str, result_str)
        else:
            result_raw = ""

        return {
            "event_id": event_id,
            "threat_determination": threat_label,
            "event_result_flag_raw": flag_raw,
            "attack_result": attack_label,
            "result_raw": result_raw,
            "raw_result": raw
        }

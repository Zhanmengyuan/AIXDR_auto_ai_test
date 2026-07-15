"""
告警列表API客户端
获取资产关联的告警列表
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List
from .base_client import BaseAPIClient


class AlertAPIClient(BaseAPIClient):
    """告警列表API客户端"""

    def get_asset_alerts(self, asset_id: str, days: int = 90) -> List[str]:
        """获取资产关联的告警ID列表

        Args:
            asset_id: 资产ID
            days: 查询最近几天的告警（默认30天）

        Returns:
            告警ID列表 (ALE-xxx格式)
        """
        endpoint = self.config.alert_endpoint

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
            "pageIndex": 1,
            "pageSize": 100,
            "order": "desc",
            "sort": "END_TIME"
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return []

        return self._extract_alert_ids(response)

    def _extract_alert_ids(self, api_response: Dict[str, Any]) -> List[str]:
        """从API响应中提取告警ID列表"""
        alerts = []

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
                alert_id = record.get("SNOW_ID") or record.get("snow_id")
                if alert_id:
                    alert_str = str(alert_id).strip()
                    if not alert_str.upper().startswith("ALE-"):
                        alert_str = f"ALE-{alert_str}"
                    alerts.append(alert_str.upper())

        return list(set(alerts))

    def get_asset_alerts_full(self, asset_id: str, days: int = 90) -> List[Dict[str, Any]]:
        """获取资产关联的完整告警信息"""
        endpoint = self.config.alert_endpoint

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
            "pageIndex": 1,
            "pageSize": 100,
            "order": "desc",
            "sort": "END_TIME"
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return []

        data = response.get("data", {})
        row_data = data.get("rowData", []) if isinstance(data, dict) else []

        return row_data

    def get_alert_detail(self, alert_id: str) -> Dict[str, Any]:
        """获取单个告警的详细信息

        Args:
            alert_id: 告警ID

        Returns:
            告警详细信息字典，包含 attack_judgment 等字段
        """
        endpoint = self.config.alert_endpoint

        now = datetime.now()
        end_date = now.strftime("%Y-%m-%d %H:%M:%S")
        start_date = (now - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "selectAllFlag": True,
            "orgIds": ["1"],
            "startTime": start_date,
            "endTime": end_date,
            "advanced": 0,
            "conditionUnitList": [
                {
                    "key": "SNOW_ID",
                    "operator": "equals",
                    "value": [alert_id]
                }
            ],
            "exact": "1",
            "assetPortraitFlag": True,
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
            return {"error": "未找到告警"}

        alert_data = row_data[0] if row_data else {}

        result = {
            "alert_id": alert_id,
            "attack_judgment": alert_data.get("ALARM_RESULT") or alert_data.get("alarm_result"),
            "risk_level": alert_data.get("ALARM_LEVEL") or alert_data.get("alarm_level"),
            "affected_assets": [
                alert_data.get("AFFECTED_ASSET_ID") or alert_data.get("affected_asset_id")
            ],
            "alert_type": alert_data.get("ALARM_TYPE") or alert_data.get("alarm_type"),
            "raw_data": alert_data
        }

        return result

    # ALERT_RESULT_FLAG 取值映射（威胁定性）
    ALERT_RESULT_FLAG_MAP = {
        "1": "正报",
        "2": "误报",
        "3": "不能确认",
        "": "不能确认",
        None: "不能确认",
    }

    # AI_RESULT/RESULT 取值映射（攻击结果）
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

    def get_alert_result(self, alert_id: str) -> Dict[str, Any]:
        """获取告警的真实研判结果（attack_judgment）（兼容旧接口，内部转发）

        Args:
            alert_id: 告警ID

        Returns:
            {"attack_judgment": "..."} 或 {"error": "错误信息"}
        """
        detail = self.get_alarm_detail_by_id(alert_id)
        if "error" in detail:
            return detail
        return {
            "alert_id": alert_id,
            "attack_judgment": detail.get("threat_determination", ""),
            "raw_result": detail.get("raw_result", {})
        }

    def get_alarm_detail_by_id(self, alert_id: str) -> Dict[str, Any]:
        """通过 pageAlarm 接口获取告警详情，提取威胁定性和攻击结果字段

        API: POST {alert_endpoint}
        Payload:
            {
                "selectAllFlag": true,
                "orgIds": ["1"],
                "startTime": "...",
                "endTime": "...",
                "advanced": 1,
                "conditionGroup": "告警ID = \"{alert_id}\"",
                "pageIndex": 1,
                "pageSize": 10,
                "order": "desc",
                "sort": "END_TIME"
            }

        返回字段及含义:
            1. 威胁定性（ALERT_RESULT_FLAG）:
                1  → 正报
                2  → 误报
                3 或空 → 不能确认
            
            2. 攻击结果（AI_RESULT/RESULT）:
                优先取 AI_RESULT，若无则取 RESULT
                若两者都无或为空 → 未知

        Args:
            alert_id: 告警ID

        Returns:
            {
                "alert_id": "xxx",
                "threat_determination": "正报/误报/不能确认",
                "attack_result": "成功/失败/未知",
                "ai_result_raw": "xxx",
                "result_raw": "xxx",
                "raw_result": {...}
            } 或 {"error": "错误信息"}
        """
        from datetime import datetime, timedelta

        endpoint = self.config.alert_endpoint
        now = datetime.now()
        end_time = now.strftime("%Y-%m-%d %H:%M:%S")
        start_time = (now - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "selectAllFlag": True,
            "orgIds": ["1"],
            "startTime": start_time,
            "endTime": end_time,
            "advanced": 1,
            "conditionGroup": f'告警ID = "{alert_id}"',
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
            return {"error": "未找到告警"}

        raw = row_data[0]

        # --- 提取威胁定性 ---
        flag_raw = raw.get("ALERT_RESULT_FLAG") or raw.get("alert_result_flag") or ""
        flag_str = str(flag_raw).strip()
        threat_label = self.ALERT_RESULT_FLAG_MAP.get(flag_str, "不能确认")

        # --- 提取攻击结果 ---
        # 优先取 AI_RESULT，若无则取 RESULT
        ai_result_raw = raw.get("AI_RESULT") or raw.get("ai_result") or ""
        result_raw = raw.get("RESULT") or raw.get("result") or ""

        # 确定攻击结果
        attack_result_raw = None
        attack_label = "未知"

        if ai_result_raw and str(ai_result_raw).strip():
            attack_result_raw = ai_result_raw
            attack_result_str = str(ai_result_raw).strip()
            attack_label = self.ATTACK_RESULT_MAP.get(attack_result_str, attack_result_str)
        elif result_raw and str(result_raw).strip():
            attack_result_raw = result_raw
            attack_result_str = str(result_raw).strip()
            attack_label = self.ATTACK_RESULT_MAP.get(attack_result_str, attack_result_str)
        else:
            attack_result_raw = ""
            attack_label = "未知"

        return {
            "alert_id": alert_id,
            "threat_determination": threat_label,
            "alert_result_flag_raw": flag_raw,
            "attack_result": attack_label,
            "ai_result_raw": ai_result_raw,
            "result_raw": result_raw,
            "attack_result_raw": attack_result_raw,
            "raw_result": raw
        }

    def get_related_asset_details(self, asset_ids: List[str]) -> List[Dict[str, Any]]:
        """获取关联资产的详细信息

        API: POST maxs/asset/statistic/relatedAssetsByParams
        Payload: [{"assetId": "xxx"}, ...]
        返回字段: assetId, assetLevel, assetTypeName, hostName, ip, macAddress, organize, osName, isKey, updateTime

        Args:
            asset_ids: 资产ID列表

        Returns:
            资产详细信息列表
        """
        base_url = self.config.base_url
        headers = self.config.headers

        url = f"{base_url}/maxs/asset/statistic/relatedAssetsByParams"

        payload = [{"assetId": aid} for aid in asset_ids if aid]

        try:
            import requests
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                verify=False,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                data = result.get("data", [])

                assets = []
                for item in data if isinstance(data, list) else []:
                    asset_info = {
                        "asset_id": item.get("assetId", ""),
                        "ip_address": item.get("ip", ""),
                        "mac_address": item.get("macAddress", ""),
                        "hostname": item.get("hostName", ""),
                        "asset_type": item.get("assetTypeName", ""),
                        "asset_level": item.get("assetLevel", ""),
                        "os_name": item.get("osName", ""),
                        "organization": item.get("organize", ""),
                        "is_exposed": item.get("isKey", ""),
                        "last_online_time": item.get("updateTime", ""),
                    }
                    assets.append(asset_info)
                return assets
            else:
                return []
        except Exception as e:
            print(f"  [获取关联资产详情异常] {e}")
            return []


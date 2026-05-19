"""
告警列表API客户端
获取资产关联的告警列表
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List
from .base_client import BaseAPIClient


class AlertAPIClient(BaseAPIClient):
    """告警列表API客户端"""

    def get_asset_alerts(self, asset_id: str, days: int = 30) -> List[str]:
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

    def get_asset_alerts_full(self, asset_id: str, days: int = 30) -> List[Dict[str, Any]]:
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

    def get_alert_result(self, alert_id: str) -> Dict[str, Any]:
        """获取告警的真实研判结果（attack_judgment）

        API: GET maxs/rv/alarm/detail/getAlarmDetailById?snowId={alert_id}&esIndex=maxs_alarm_202605
        返回结构: {data: {result: "..."}}

        Args:
            alert_id: 告警ID

        Returns:
            {"attack_judgment": "攻击成功/失败/未知"} 或 {"error": "错误信息"}
        """
        base_url = self.config.base_url
        headers = self.config.headers

        es_index = "maxs_alarm_202605"
        url = f"{base_url}/maxs/rv/alarm/detail/getAlarmDetailById"
        params = {
            "snowId": alert_id,
            "esIndex": es_index
        }

        try:
            import requests
            response = requests.get(
                url,
                params=params,
                headers=headers,
                verify=False,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                data = result.get("data", {})
                
                attack_result = (
                    data.get("result") or 
                    data.get("RESULT") or 
                    data.get("ALARM_RESULT") or
                    data.get("attack_result") or
                    ""
                )
                
                return {
                    "alert_id": alert_id,
                    "attack_judgment": attack_result,
                    "raw_result": data
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

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


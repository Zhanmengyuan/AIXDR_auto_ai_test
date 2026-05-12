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

        data = api_response.get("data", {})
        row_data = data.get("rowData", []) if isinstance(data, dict) else []

        return row_data

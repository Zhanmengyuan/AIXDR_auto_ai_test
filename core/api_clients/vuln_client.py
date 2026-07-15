"""
漏洞列表API客户端
获取资产关联的漏洞列表
"""
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List
from .base_client import BaseAPIClient


class VulnAPIClient(BaseAPIClient):
    """漏洞列表API客户端"""

    def get_asset_vulns(self, asset_id: str, days: int = 90) -> List[str]:
        """获取资产关联的漏洞ID列表

        Args:
            asset_id: 资产ID
            days: 查询最近几天的漏洞

        Returns:
            漏洞ID列表 (AVE-xxx格式)
        """
        endpoint = self.config.vuln_endpoint

        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        end_date = now.strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "assetId": asset_id,
            "findTimes": [start_date, end_date],
            "dealStatus": 1,
            "vulnType": "",
            "vulnLevel": "",
            "sort": "VULN_TYPE",
            "order": "desc",
            "pageIndex": 1,
            "pageSize": 100
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return []

        return self._extract_vuln_ids(response)

    def _extract_vuln_ids(self, api_response: Dict[str, Any]) -> List[str]:
        """从API响应中提取漏洞ID列表"""
        vulns = []

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
                vuln_id = record.get("vulnId") or record.get("vuln_id")
                if vuln_id:
                    vuln_str = str(vuln_id).strip()
                    if not vuln_str.upper().startswith("AVE-"):
                        vuln_str = f"AVE-{vuln_str}"
                    vulns.append(vuln_str.upper())

        return list(set(vulns))

    def get_asset_vulns_full(self, asset_id: str, days: int = 90) -> List[Dict[str, Any]]:
        """获取资产关联的完整漏洞信息"""
        endpoint = self.config.vuln_endpoint

        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        end_date = now.strftime("%Y-%m-%d %H:%M:%S")

        payload = {
            "assetId": asset_id,
            "findTimes": [start_date, end_date],
            "dealStatus": 1,
            "vulnType": "",
            "vulnLevel": "",
            "sort": "VULN_TYPE",
            "order": "desc",
            "pageIndex": 1,
            "pageSize": 100
        }

        response = self.post(endpoint, payload)

        if "error" in response:
            return []

        data = api_response.get("data", {})
        row_data = data.get("rowData", []) if isinstance(data, dict) else []

        return row_data

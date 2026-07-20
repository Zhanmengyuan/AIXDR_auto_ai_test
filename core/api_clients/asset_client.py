"""
资产详情API客户端
获取资产的完整字段信息
"""
import requests
from typing import Dict, List, Any, Optional
from .base_client import BaseAPIClient


class AssetAPIClient(BaseAPIClient):
    """资产详情API客户端"""

    # 字段映射：标准字段 -> API返回字段
    FIELD_MAPPING = {
        "asset_id": ["ASSET_ID", "assetId"],
        "ip_address": ["IP", "ip", "ipAddress"],
        "mac_address": ["MAC", "mac", "macAddress"],
        "hostname": ["HOST_NAME", "hostname", "hostName"],
        "asset_type": ["ASSET_TYPE$NAME", "ASSET_TYPE", "assetType"],
        "asset_level": ["ASSET_LEVEL$NAME", "ASSET_LEVEL", "assetLevel"],
        "os_name": ["OS_NAME", "OS", "osName"],
        "organization": ["ORG_ID$NAME", "ORGANIZATION", "orgName"],
        "is_exposed": ["IS_EXPOSURE$NAME", "IS_EXPOSED", "exposed"],
        "last_online_time": ["LAST_ONLINE_TIME", "LAST_LOGIN_TIME"],
        "risk_level": ["RISK_LEVEL", "riskLevel"],
        "risk_score": ["RISK_SCORE", "riskScore"],
    }

    def get_asset_detail(self, asset_id: str) -> Dict[str, Any]:
        """获取资产详情，含漏洞/告警/事件列表"""
        endpoint = self.config.asset_endpoint
        payload = {"ASSET_ID": asset_id}

        response = self.post(endpoint, payload)

        if "error" in response:
            return {"error": response["error"]}

        result = self._extract_fields(response)

        # 从独立端点获取漏洞/告警/事件完整列表（5秒超时）
        # 漏洞需要同时获取 vulnId（AVE列表）和 vulnCveCode（CVE列表）
        vuln_data = self._fetch_vuln_list(
            self.config.vuln_endpoint,
            {"assetId": asset_id, "pageIndex": 1, "pageSize": 200}
        )
        result["vuln_list"] = vuln_data["vuln_ids"]
        result["cve_list"] = vuln_data["cve_codes"]
        result["alarm_list"] = self._fetch_list(
            self.config.alarm_endpoint,
            {"selectAllFlag": True, "conditionUnitList": [{"key": "AFFECTED_ASSET_ID", "operator": "equals", "value": [asset_id]}], "pageIndex": 1, "pageSize": 200},
            ["rowData", "data"],
            ["alarmId", "alarm_id", "id"]
        )
        result["event_list"] = self._fetch_list(
            self.config.event_endpoint,
            {"selectAllFlag": True, "conditionUnitList": [{"key": "AFFECTED_ASSET_ID", "operator": "equals", "value": [asset_id]}], "pageIndex": 1, "pageSize": 200},
            ["rowData", "data"],
            ["eventId", "event_id", "id"]
        )

        return result

    def _fetch_vuln_list(self, endpoint: str, payload: dict) -> Dict[str, List[str]]:
        """获取漏洞AVE列表和CVE列表"""
        try:
            url = f"{self.base_url}{endpoint}"
            resp = requests.post(url, headers=self.headers, json=payload, verify=False, timeout=5)
            if resp.status_code != 200:
                return {"vuln_ids": [], "cve_codes": []}
            data = resp.json()
            records = data.get("data", {}).get("rowData", []) if isinstance(data, dict) else []
            if not isinstance(records, list):
                return {"vuln_ids": [], "cve_codes": []}
            vuln_ids = []
            cve_codes = []
            for r in records:
                if isinstance(r, dict):
                    vid = r.get("vulnId") or r.get("vuln_id")
                    if vid:
                        vuln_ids.append(str(vid))
                    cve = r.get("vulnCveCode") or r.get("cveCode") or r.get("cve_code")
                    if cve:
                        cve_codes.append(str(cve))
            return {
                "vuln_ids": list(set(vuln_ids)),
                "cve_codes": list(set(cve_codes))
            }
        except Exception:
            return {"vuln_ids": [], "cve_codes": []}

    def _fetch_list(self, endpoint: str, payload: dict, data_paths: list, id_keys: list) -> List[str]:
        """通用列表获取方法，5秒超时"""
        try:
            url = f"{self.base_url}{endpoint}"
            resp = requests.post(url, headers=self.headers, json=payload, verify=False, timeout=5)
            if resp.status_code != 200:
                return []
            data = resp.json()
            records = None
            for path in data_paths:
                if isinstance(path, str):
                    path = [path]
                val = data
                for key in path:
                    if isinstance(val, dict):
                        val = val.get(key, {})
                    else:
                        val = {}
                if val:
                    records = val
                    break
            if not records:
                if isinstance(data, dict):
                    records = data.get("data", {}).get("rowData", [])
            if not records:
                return []
            if not isinstance(records, list):
                return []
            ids = []
            for r in records:
                for k in id_keys:
                    v = r.get(k) if isinstance(r, dict) else None
                    if v:
                        ids.append(str(v))
                        break
            return list(set(ids))
        except Exception:
            return []

    def _extract_fields(self, api_response: Dict[str, Any]) -> Dict[str, Any]:
        """从API响应中提取所有字段"""
        result = {}
        if api_response.get("data"):
            data = api_response["data"]
        else:
            data = api_response
        for field, keys in self.FIELD_MAPPING.items():
            value = self._find_value(data, keys)
            result[field] = value
        return result

    def _find_value(self, data: Any, keys: List[str]) -> Optional[Any]:
        """递归查找字段值"""
        if isinstance(data, dict):
            for key in keys:
                if key in data:
                    return data[key]
            for value in data.values():
                result = self._find_value(value, keys)
                if result is not None:
                    return result
        elif isinstance(data, list):
            for item in data:
                result = self._find_value(item, keys)
                if result is not None:
                    return result
        return None

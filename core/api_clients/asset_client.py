"""
资产详情API客户端
获取资产的完整字段信息
"""
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
        """获取资产详情"""
        endpoint = self.config.asset_endpoint
        payload = {"ASSET_ID": asset_id}

        response = self.post(endpoint, payload)

        if "error" in response:
            return {"error": response["error"]}

        return self._extract_fields(response)

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

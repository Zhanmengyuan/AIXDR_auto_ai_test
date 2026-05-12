"""
API客户端基类
提供通用的API调用方法
"""
import requests
import urllib3
from typing import Any, Dict, Optional
from ..config_loader import ConfigLoader

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseAPIClient:
    """API客户端基类"""

    def __init__(self, config: ConfigLoader = None):
        self.config = config or ConfigLoader()
        self.base_url = self.config.base_url
        self.headers = self.config.headers

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """发送POST请求"""
        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                verify=False,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "response": response.text}

        except Exception as e:
            return {"error": str(e)}

    def get(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """发送GET请求"""
        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                verify=False,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "response": response.text}

        except Exception as e:
            return {"error": str(e)}

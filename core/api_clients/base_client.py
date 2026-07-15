"""
API客户端基类
提供通用的API调用方法，支持自动登录鉴权
"""
import requests
import urllib3
from typing import Any, Dict, Optional
from ..config_loader import ConfigLoader
from .auth_client import AuthClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseAPIClient:
    """API客户端基类"""

    def __init__(self, config: ConfigLoader = None, auto_auth: bool = True):
        self.config = config or ConfigLoader()
        self.base_url = self.config.base_url
        self.headers = self.config.headers.copy()
        self.auto_auth = auto_auth
        self._auth_client: Optional[AuthClient] = None

        # 只在 config 中尚未有 Cookie 时才登录，避免多个客户端实例重复登录
        if auto_auth and self.config.auth_config.get("auto_login", True):
            if not self.config.get("cookie"):
                self._ensure_authenticated()
            # 已有 Cookie 则直接同步到本实例 headers
            else:
                self.headers = self.config.headers.copy()

    def _get_auth_client(self) -> AuthClient:
        """获取鉴权客户端"""
        if self._auth_client is None:
            self._auth_client = AuthClient(self.config)
        return self._auth_client

    def _ensure_authenticated(self):
        """确保已登录并Cookie有效，优先复用 config 中已有的 Cookie"""
        # 如果 config 中已有 Cookie，直接同步到本实例 headers，不重新登录
        existing_cookie = self.config.get("cookie", "")
        if existing_cookie:
            self.headers['Cookie'] = existing_cookie
            return

        # 无 Cookie 才走登录流程
        auth_client = self._get_auth_client()
        if not auth_client.is_cookie_valid():
            cookie = auth_client.get_cookie()
            if cookie:
                self._update_headers_cookie(cookie)
                self.config.update_cookie(cookie)

    def _update_headers_cookie(self, cookie: str):
        """更新请求头中的Cookie"""
        self.headers['Cookie'] = cookie

    def _refresh_auth_if_needed(self):
        """刷新鉴权（401/403时才调用，强制重新登录）"""
        auth_client = self._get_auth_client()
        cookie = auth_client.refresh_cookie()
        if cookie:
            self._update_headers_cookie(cookie)
            self.config.update_cookie(cookie)

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """发送POST请求"""
        # 确保鉴权有效
        if self.auto_auth:
            self._ensure_authenticated()

        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                verify=False,
                timeout=30
            )

            # 如果返回401/403，可能是鉴权过期，尝试刷新后重试
            if response.status_code in [401, 403] and self.auto_auth:
                self._refresh_auth_if_needed()
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
        # 确保鉴权有效
        if self.auto_auth:
            self._ensure_authenticated()

        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                verify=False,
                timeout=30
            )

            # 如果返回401/403，可能是鉴权过期，尝试刷新后重试
            if response.status_code in [401, 403] and self.auto_auth:
                self._refresh_auth_if_needed()
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

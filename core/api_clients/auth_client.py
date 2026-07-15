"""
登录鉴权客户端
用于获取 XDR 系统的登录 Cookie，支持 Redis 绕过验证码
"""
import requests
import urllib3
import base64
import time
import uuid
from typing import Dict, Any, Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from ..config_loader import ConfigLoader

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Redis客户端（延迟导入）
_redis_client = None


def _get_redis_client(config: ConfigLoader, force_new: bool = False):
    """获取Redis客户端（延迟导入）"""
    global _redis_client
    if _redis_client is None or force_new:
        try:
            import redis
            redis_config = config.redis_config
            password = redis_config.get("password")
            # 处理空密码情况
            if password == "" or password is None:
                password = None
            _redis_client = redis.Redis(
                host=redis_config.get("host", "192.168.112.150"),
                port=redis_config.get("port", 16379),
                db=redis_config.get("db", 2),
                password=password,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # 测试连接
            _redis_client.ping()
        except ImportError:
            print("[Auth] ⚠️ redis库未安装，无法从Redis读取验证码")
            return None
        except Exception as e:
            print(f"[Auth] ⚠️ Redis连接失败: {e}")
            _redis_client = None
            return None
    return _redis_client


class AuthClient:
    """登录鉴权客户端"""

    # 固定的RSA公钥（PEM格式）
    FIXED_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChDnCJSDnLdKrK5QBv7hb+QNIWiC2slLOeWYUQhA7DKYKp7f6aKmWFE7mDRnA/LUoo26yxEJcfT9Wt2CzMmrjnRQDT3BmJxlWBHul90Hv1dMVdkrDn+dP7uXLLeiT4NFwbhLRMVYrMaXSdRDaRAG6g6oDIJfPM24XvBVZf3a/J7wIDAQAB
-----END PUBLIC KEY-----"""

    def __init__(self, config: ConfigLoader = None):
        self.config = config or ConfigLoader()
        self.base_url = self.config.base_url
        self.session = requests.Session()
        self._cookie_cache: Optional[str] = None
        self._cookie_expire_time: float = 0
        self._cookie_lifetime: int = 1700  # Cookie有效期约30分钟，提前刷新

    def _get_public_key(self) -> str:
        """获取RSA公钥（使用固定PEM格式公钥）"""
        return self.FIXED_PUBLIC_KEY_PEM

    def _encrypt_password(self, password: str, public_key_pem: str) -> str:
        """使用RSA公钥加密密码（使用PKCS1_v1_5）"""
        try:
            # 解析PEM格式公钥
            public_key = RSA.import_key(public_key_pem.encode())

            # 使用PKCS1_v1_5加密
            cipher = PKCS1_v1_5.new(public_key)
            encrypted = cipher.encrypt(password.encode('utf-8'))

            # Base64 编码加密结果
            encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')
            return encrypted_base64

        except Exception as e:
            print(f"[Auth] 密码加密失败: {e}")
            return base64.b64encode(password.encode('utf-8')).decode('utf-8')

    def _get_captcha_from_redis(self, captcha_uuid: str) -> str:
        """从Redis获取验证码文本

        Args:
            captcha_uuid: 验证码UUID，格式如 captcha_xxx

        Returns:
            验证码文本，失败返回空字符串
        """
        redis_client = _get_redis_client(self.config)
        if redis_client is None:
            return ""

        try:
            # 尝试多种可能的Redis key格式
            possible_keys = [
                captcha_uuid,  # 直接使用uuid作为key
                f"captcha:{captcha_uuid}",  # captcha:前缀
                f"captcha_code:{captcha_uuid}",  # captcha_code:前缀
                captcha_uuid.replace("captcha_", "captcha:"),  # 替换格式
            ]

            for key in possible_keys:
                value = redis_client.get(key)
                if value:
                    return value

            # 尝试模糊匹配
            if captcha_uuid.startswith("captcha_"):
                # 搜索最近的验证码
                pattern = "captcha:*"
                keys = redis_client.keys(pattern)
                if keys:
                    # 获取最新的一个（假设Redis有序）
                    for key in keys[-5:]:  # 只检查最后5个
                        value = redis_client.get(key)
                        if value and len(value) <= 10:  # 验证码通常是4-6位
                            return value

            return ""

        except Exception as e:
            print(f"[Auth] ❌ Redis读取验证码失败: {e}")
            return ""

    def _generate_captcha_uuid(self) -> str:
        """生成验证码UUID"""
        # 格式: captcha_数字
        return f"captcha_{uuid.uuid4().int}"

    def _get_captcha_uuid_from_api(self) -> str:
        """POST请求获取验证码UUID

        Returns:
            captchaUuid字符串
        """
        captcha_endpoint = "/maxs/pm/sso/login/_getCaptcha"
        url = f"{self.base_url}{captcha_endpoint}"

        try:
            response = self.session.post(
                url,
                json={},
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                verify=False,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                captcha_uuid = result.get("data", {}).get("captchaUuid", "")
                return captcha_uuid

            return ""

        except Exception as e:
            print(f"[Auth] ❌ 请求验证码UUID异常: {e}")
            return ""

    def _get_captcha_from_redis_dynamic(self) -> Dict[str, str]:
        """动态获取验证码：POST获取UUID，然后从Redis读取验证码值"""
        # 1. POST请求获取captchaUuid
        captcha_uuid = self._get_captcha_uuid_from_api()
        if not captcha_uuid:
            return {"captcha": "", "captchaUuid": ""}

        # 2. 从Redis读取验证码值
        redis_client = _get_redis_client(self.config)
        if redis_client is None:
            return {"captcha": "", "captchaUuid": captcha_uuid}

        try:
            # 直接用captchaUuid作为key
            captcha_value = redis_client.get(captcha_uuid)

            if captcha_value:
                return {
                    "captcha": captcha_value,
                    "captchaUuid": captcha_uuid
                }

            return {"captcha": "", "captchaUuid": captcha_uuid}

        except Exception as e:
            print(f"[Auth] ❌ Redis读取验证码失败: {e}")
            return {"captcha": "", "captchaUuid": captcha_uuid}

    def _get_captcha(self) -> Dict[str, str]:
        """获取验证码和验证码UUID

        流程：
        1. POST /maxs/pm/sso/login/_getCaptcha → 获取captchaUuid
        2. Redis GET captchaUuid → 获取验证码值
        3. 返回 captcha + captchaUuid
        """
        return self._get_captcha_from_redis_dynamic()

    def login(self, username: str = "admin", password: str = "maxs.PDG~2022") -> Optional[str]:
        """执行登录并获取 Cookie

        Args:
            username: 用户名
            password: 密码

        Returns:
            Cookie字符串，登录失败返回None
        """
        print("[Auth] 开始登录...")

        # 1. 先访问前端页面获取初始 Cookie
        frontend_paths = [
            "/maxPage/login",
            "/login",
            "/",
            "/maxPage/"
        ]

        for path in frontend_paths:
            url = f"{self.base_url}{path}"
            try:
                response = self.session.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                    verify=False,
                    timeout=15
                )
                if response.status_code in [200, 302, 301]:
                    break
            except Exception:
                continue

        # 2. 使用固定RSA公钥加密密码
        public_key = self._get_public_key()
        encrypted_password = self._encrypt_password(password, public_key)

        # 3. 获取验证码
        captcha_info = self._get_captcha()
        login_endpoint = "/maxs/pm/sso/login/_login"
        url = f"{self.base_url}{login_endpoint}"

        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/maxPage/login",
            "X-Requested-With": "XMLHttpRequest"
        }

        login_payload = {
            "username": username,
            "password": encrypted_password,
            "captcha": captcha_info.get("captcha", ""),
            "tenantId": -1,
            "captchaUuid": captcha_info.get("captchaUuid", "")
        }

        try:
            response = self.session.post(
                url,
                headers=headers,
                json=login_payload,
                verify=False,
                timeout=30,
                allow_redirects=False
            )

            if response.status_code in [200, 302, 301]:
                # 从响应头获取 Set-Cookie
                cookies = response.headers.get("Set-Cookie", "")

                # 或从 session.cookies 获取
                if not cookies and self.session.cookies:
                    cookie_dict = dict(self.session.cookies)
                    cookies = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])

                # 检查响应体
                if response.status_code == 200:
                    try:
                        result = response.json()
                        if result.get("code") == 200 or result.get("success") or result.get("status") == "success":
                            print("[Auth] ✅ 登录成功")
                            if cookies:
                                self._cookie_cache = cookies
                                self._cookie_expire_time = time.time() + self._cookie_lifetime
                                return cookies
                        else:
                            print(f"[Auth] ❌ 登录失败: {result.get('msg') or result.get('message')}")
                            # 如果是验证码错误，尝试无验证码登录
                            if "验证码" in str(result.get('msg') or result.get('message') or ''):
                                print("[Auth] 尝试无验证码登录...")
                                login_payload["captcha"] = ""
                                login_payload["captchaUuid"] = ""
                                response = self.session.post(
                                    url,
                                    headers=headers,
                                    json=login_payload,
                                    verify=False,
                                    timeout=30,
                                    allow_redirects=False
                                )
                                if response.status_code == 200:
                                    result = response.json()
                                    if result.get("code") == 200 or result.get("success"):
                                        cookies = response.headers.get("Set-Cookie", "")
                                        if cookies:
                                            print("[Auth] ✅ 无验证码登录成功")
                                            self._cookie_cache = cookies
                                            self._cookie_expire_time = time.time() + self._cookie_lifetime
                                            return cookies
                    except Exception:
                        # 非 JSON 响应，检查是否有 Cookie
                        if cookies:
                            print("[Auth] ✅ 获取Cookie成功")
                            self._cookie_cache = cookies
                            self._cookie_expire_time = time.time() + self._cookie_lifetime
                            return cookies

                elif response.status_code in [302, 301]:
                    # 重定向通常意味着登录成功
                    location = response.headers.get("Location", "")
                    print(f"[Auth] 重定向到: {location}")
                    if cookies:
                        print("[Auth] ✅ 获取Cookie成功")
                        self._cookie_cache = cookies
                        self._cookie_expire_time = time.time() + self._cookie_lifetime
                        return cookies

            else:
                print(f"[Auth] ❌ 登录失败: HTTP {response.status_code}")
                try:
                    error_msg = response.json().get("msg", response.text[:200])
                    print(f"[Auth] 错误信息: {error_msg}")
                except Exception:
                    print(f"[Auth] 响应内容: {response.text[:200]}")

        except Exception as e:
            print(f"[Auth] ❌ 登录异常: {e}")

        # 5. 如果登录失败，尝试从已访问的页面获取 Cookie
        if self.session.cookies:
            cookie_dict = dict(self.session.cookies)
            if cookie_dict:
                cookies = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])
                print(f"[Auth] 从前端页面获取Cookie: {cookies[:100]}...")
                self._cookie_cache = cookies
                self._cookie_expire_time = time.time() + self._cookie_lifetime
                return cookies

        print("[Auth] ❌ 所有登录尝试失败")
        return None

    def get_cookie(self, force_refresh: bool = False) -> Optional[str]:
        """获取有效的Cookie（带缓存）

        Args:
            force_refresh: 是否强制刷新Cookie

        Returns:
            Cookie字符串
        """
        # 检查缓存是否有效
        if not force_refresh and self._cookie_cache:
            if time.time() < self._cookie_expire_time:
                return self._cookie_cache

        # Cookie过期或强制刷新，重新登录
        auth_config = self.config.auth_config
        username = auth_config.get("username", "admin")
        password = auth_config.get("password", "maxs.PDG~2022")

        return self.login(username, password)

    def refresh_cookie(self) -> Optional[str]:
        """刷新Cookie"""
        return self.get_cookie(force_refresh=True)

    def is_cookie_valid(self) -> bool:
        """检查Cookie是否仍然有效"""
        if not self._cookie_cache:
            return False
        return time.time() < self._cookie_expire_time
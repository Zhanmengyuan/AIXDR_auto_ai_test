"""
配置加载器
统一管理配置文件读取
"""
import os
import yaml
from typing import Any, Dict, List


class ConfigLoader:
    """配置加载器单例"""

    _instance = None
    _config: Dict[str, Any] = None

    def __new__(cls, config_path: str = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config(config_path)
        return cls._instance

    def _load_config(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), "..", "config", "config_api.yaml"
            )
        with open(config_path, 'r', encoding='utf-8') as f:
            self._config = yaml.safe_load(f)

        # 自动登录获取Cookie
        auth_config = self._config.get('auth', {})
        if auth_config.get('auto_login', False):
            self._auto_login(auth_config)

    def _auto_login(self, auth_config: Dict[str, Any]):
        """自动登录获取Cookie"""
        try:
            from .api_clients.auth_client import AuthClient
            auth = AuthClient(self)
            cookie = auth.login(
                auth_config.get('username', 'admin'),
                auth_config.get('password', 'maxs.PDG~2022')
            )
            if cookie:
                self.update_cookie(cookie)
                print("[ConfigLoader] ✅ 自动登录成功，Cookie已更新")
            else:
                print("[ConfigLoader] ⚠️ 自动登录失败，请检查配置")
        except Exception as e:
            print(f"[ConfigLoader] ❌ 自动登录异常: {e}")

    @classmethod
    def reload(cls, config_path: str = None):
        """重新加载配置"""
        cls._instance = None
        return cls(config_path)

    @property
    def base_url(self) -> str:
        return self._config.get('api', {}).get('base_url', '')

    @property
    def headers(self) -> Dict[str, str]:
        headers = self._config.get('headers', {}).copy()
        headers['Cookie'] = self._config.get('cookie', '')
        return headers

    @property
    def auth_config(self) -> Dict[str, Any]:
        """登录鉴权配置"""
        return self._config.get('auth', {
            "username": "admin",
            "password": "maxs.PDG~2022",
            "auto_login": True,
            "cookie_lifetime": 1700
        })

    def update_cookie(self, cookie: str):
        """更新Cookie配置"""
        self._config['cookie'] = cookie

    @property
    def redis_config(self) -> Dict[str, Any]:
        """Redis配置"""
        return self._config.get('redis', {
            "host": "192.168.112.150",
            "port": 16379,
            "db": 2,
            "password": None
        })

    @property
    def database_config(self) -> Dict[str, Any]:
        """沙箱报告数据库配置（PostgreSQL）"""
        return self._config.get('database', {
            "type": "postgresql",
            "host": "192.168.113.169",
            "port": 15432,
            "user": "root",
            "password": "maxs.PDG~2022",
            "dbname": "ssa",
            "table": "xdr_ddan_result",
            "id_column": "id",
            "search_column": "ext_field_one",
        })

    @property
    def test_assets(self) -> List[str]:
        return self._config.get('test_assets', [])

    @property
    def test_alarms(self) -> List[str]:
        return self._config.get('test_alarms', [])

    @property
    def test_events(self) -> List[str]:
        return self._config.get('test_events', [])

    @property
    def test_vulns(self) -> List[str]:
        return self._config.get('test_vulns', [])

    @property
    def test_sandboxes(self) -> List[str]:
        return self._config.get('test_sandboxes', [])

    @property
    def stability_test_alarms(self) -> List[str]:
        """稳定性测试专用告警ID列表"""
        return self._config.get('stability_test_alarms', [])

    @property
    def stability_test_events(self) -> List[str]:
        """稳定性测试专用事件ID列表"""
        return self._config.get('stability_test_events', [])

    @property
    def stability_test_vulns(self) -> List[str]:
        """稳定性测试专用漏洞ID列表"""
        return self._config.get('stability_test_vulns', [])

    @property
    def stability_test_sandboxes(self) -> List[str]:
        """稳定性测试专用沙箱ID列表"""
        return self._config.get('stability_test_sandboxes', [])

    @property
    def field_mapping(self) -> Dict[str, List[str]]:
        return self._config.get('field_mapping', {})

    @property
    def vuln_endpoint(self) -> str:
        return self._config.get('api', {}).get('vuln_endpoint', '/maxs/asset/vuln/pageAssetDetail')

    @property
    def alarm_endpoint(self) -> str:
        return self._config.get('api', {}).get('alarm_endpoint', '/maxs/rv/alarm/pageAlarm')

    @property
    def event_endpoint(self) -> str:
        return self._config.get('api', {}).get('event_endpoint', '/maxs/rv/event/pageEvent')

    @property
    def asset_endpoint(self) -> str:
        return self._config.get('api', {}).get('endpoint', '/maxs/asset/manage/getDetailById')

    @property
    def llm_config(self) -> Dict[str, str]:
        return self._config.get('llm', {})

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        return self._config.get(key, default)


def get_config(config_path: str = None) -> ConfigLoader:
    """获取配置加载器实例"""
    return ConfigLoader(config_path)

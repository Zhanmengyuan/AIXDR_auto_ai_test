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
    def test_assets(self) -> List[str]:
        return self._config.get('test_assets', [])

    @property
    def test_alerts(self) -> List[str]:
        return self._config.get('test_alerts', [])

    @property
    def field_mapping(self) -> Dict[str, List[str]]:
        return self._config.get('field_mapping', {})

    @property
    def vuln_endpoint(self) -> str:
        return self._config.get('api', {}).get('vuln_endpoint', '/maxs/asset/vuln/pageAssetDetail')

    @property
    def alert_endpoint(self) -> str:
        return self._config.get('api', {}).get('alert_endpoint', '/maxs/rv/alarm/pageAlarm')

    @property
    def event_endpoint(self) -> str:
        return self._config.get('api', {}).get('event_endpoint', '/maxs/rv/event/pageEvent')

    @property
    def asset_endpoint(self) -> str:
        return self._config.get('api', {}).get('endpoint', '/maxs/asset/manage/getDetailById')

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        return self._config.get(key, default)


def get_config(config_path: str = None) -> ConfigLoader:
    """获取配置加载器实例"""
    return ConfigLoader(config_path)

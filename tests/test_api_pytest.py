import pytest
import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.api_core import AssetApiClient, FieldExtractor, ResultComparator, load_yaml_config


class TestAssetApi:

    @pytest.fixture(scope="class")
    def config_path(self):
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "config_api.yaml")

    @pytest.fixture(scope="class")
    def yaml_config(self, config_path):
        return load_yaml_config(config_path)

    @pytest.fixture(scope="class")
    def api_client(self, config_path):
        return AssetApiClient(config_path)

    @pytest.fixture(scope="class")
    def field_extractor(self, yaml_config):
        return FieldExtractor(yaml_config['field_mapping'])

    @pytest.fixture(scope="class")
    def comparator(self, yaml_config):
        return ResultComparator(yaml_config['field_mapping'])

    @pytest.fixture(scope="class")
    def test_assets(self, yaml_config):
        return yaml_config.get('test_assets', [])


class TestApiCall(TestAssetApi):

    def test_api_connectivity(self, api_client):
        """测试API连接是否正常"""
        url = f"{api_client.api_config.base_url}{api_client.api_config.endpoint}"
        assert url.startswith("https://"), "API URL应该是HTTPS"
        assert api_client.api_config.method == "POST", "应该使用POST方法"

    def test_fetch_asset_detail(self, api_client, field_extractor, test_assets):
        """测试获取单个资产详情"""
        if not test_assets:
            pytest.skip("没有配置测试资产")

        asset_id = test_assets[0]
        response = api_client.call_api(asset_id)

        assert "error" not in response or response.get("error") is None, \
            f"API调用失败: {response.get('error', 'Unknown error')}"

        extracted = field_extractor.extract(response)
        assert extracted is not None, "应该能提取到字段数据"

        print(f"\n✅ 成功获取资产 {asset_id} 的API数据")

    def test_fetch_multiple_assets(self, api_client, test_assets):
        """测试批量获取多个资产"""
        if not test_assets:
            pytest.skip("没有配置测试资产")

        results = {}
        for asset_id in test_assets:
            response = api_client.call_api(asset_id)
            results[asset_id] = {
                "success": "error" not in response or response.get("error") is None,
                "has_data": bool(response) and "error" not in response
            }

        print(f"\n✅ 批量测试完成: {len(results)} 个资产")
        for asset_id, result in results.items():
            print(f"   {asset_id}: {'成功' if result['success'] else '失败'}")


class TestFieldExtraction(TestAssetApi):

    def test_extract_all_fields(self, api_client, field_extractor, test_assets):
        """测试提取所有定义的字段"""
        if not test_assets:
            pytest.skip("没有配置测试资产")

        asset_id = test_assets[0]
        response = api_client.call_api(asset_id)

        if "error" in response and response["error"]:
            pytest.skip(f"API调用失败: {response.get('error')}")

        extracted = field_extractor.extract(response)

        assert extracted is not None
        assert len(extracted) > 0, "应该提取到至少一个字段"

        print(f"\n📊 提取到 {len(extracted)} 个字段:")
        for field, value in extracted.items():
            print(f"   {field}: {value}")

    def test_extract_specific_fields(self, api_client, field_extractor, test_assets):
        """测试提取指定字段"""
        if not test_assets:
            pytest.skip("没有配置测试资产")

        asset_id = test_assets[0]
        response = api_client.call_api(asset_id)

        if "error" in response and response["error"]:
            pytest.skip(f"API调用失败: {response.get('error')}")

        fields = ["asset_id", "ip_address", "hostname", "os_name"]
        extracted = field_extractor.extract(response, fields)

        for field in fields:
            assert field in extracted, f"应该包含字段 {field}"

        print(f"\n📊 指定字段提取结果:")
        for field, value in extracted.items():
            print(f"   {field}: {value}")


class TestDataComparison(TestAssetApi):

    def test_compare_with_mock_data(self, api_client, field_extractor, comparator, test_assets):
        """测试与模拟AI数据的对比"""
        if not test_assets:
            pytest.skip("没有配置测试资产")

        asset_id = test_assets[0]
        response = api_client.call_api(asset_id)

        if "error" in response and response["error"]:
            pytest.skip(f"API调用失败: {response.get('error')}")

        api_data = field_extractor.extract(response)

        ai_mock_data = {
            "asset_id": test_assets[0],
            "ip_address": "10.28.195.239",
            "mac_address": "00:1A:2B:3C:4D:5E",
            "hostname": "T14P",
            "asset_type": "PC主机",
            "asset_level": "一般",
            "os_name": "Windows 11 家庭中文版",
            "ORG_ID$NAME": "技术部",
            "IS_EXPOSURE$NAME": "否",
            "last_online_time": "2026-05-06 14:02:41"
        }

        comparison = comparator.compare(ai_mock_data, api_data)

        print(f"\n🔄 AI vs API 对比结果:")
        for item in comparison:
            print(f"   【{item['field_cn']}】")
            print(f"      AI: {item['ai_value']}")
            print(f"      API: {item['api_value']}")
            print(f"      匹配: {item['match']}")

        match_counts = {}
        for item in comparison:
            match_type = item['match']
            match_counts[match_type] = match_counts.get(match_type, 0) + 1

        print(f"\n📈 匹配统计:")
        for match_type, count in match_counts.items():
            print(f"   {match_type}: {count}")


class TestDataExport(TestAssetApi):

    def test_save_api_response(self, api_client, tmp_path, test_assets):
        """测试保存API响应到文件"""
        if not test_assets:
            pytest.skip("没有配置测试资产")

        asset_id = test_assets[0]
        response = api_client.call_api(asset_id)

        if "error" in response and response["error"]:
            pytest.skip(f"API调用失败: {response.get('error')}")

        output_file = tmp_path / f"api_response_{asset_id}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                "asset_id": asset_id,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "api_response": response
            }, f, ensure_ascii=False, indent=2)

        assert output_file.exists(), "应该生成JSON文件"
        print(f"\n✅ API响应已保存到: {output_file}")


def run_quick_test():
    """快速运行测试的便捷函数"""
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_quick_test()

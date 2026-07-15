"""
测试用例管理模块
管理各模块的测试用例：资产解读、漏洞解读、安全告警解读等
"""
import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class TestCase:
    """测试用例"""
    case_id: str
    module: str
    input_data: Dict[str, Any]
    expected_output: Dict[str, Any]
    description: str = ""
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class TestCaseManager:
    """测试用例管理器"""

    MODULES = {
        "asset": "资产解读",
        "vuln": "漏洞解读",
        "alert": "安全告警解读",
        "event": "安全事件解读"
    }

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = data_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "test_data"
        )
        self.test_cases: Dict[str, List[TestCase]] = {}
        self._ensure_data_dir()

    def _ensure_data_dir(self) -> None:
        """确保数据目录存在"""
        os.makedirs(self.data_dir, exist_ok=True)
        for module in self.MODULES.keys():
            module_dir = os.path.join(self.data_dir, module)
            os.makedirs(module_dir, exist_ok=True)

    def load_test_cases(self, module: str) -> List[TestCase]:
        """加载指定模块的测试用例"""
        if module not in self.MODULES:
            raise ValueError(f"未知模块: {module}，支持的模块: {list(self.MODULES.keys())}")

        module_dir = os.path.join(self.data_dir, module)
        test_cases = []

        for filename in os.listdir(module_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(module_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                test_cases.append(TestCase(**item))
                        else:
                            test_cases.append(TestCase(**data))
                except Exception as e:
                    print(f"  ⚠️  加载测试用例失败 {filename}: {e}")

        self.test_cases[module] = test_cases
        return test_cases

    def load_all_test_cases(self) -> Dict[str, List[TestCase]]:
        """加载所有模块的测试用例"""
        result = {}
        for module in self.MODULES.keys():
            result[module] = self.load_test_cases(module)
        return result

    def add_test_case(self, module: str, test_case: TestCase) -> None:
        """添加测试用例"""
        if module not in self.test_cases:
            self.test_cases[module] = []
        self.test_cases[module].append(test_case)

    def save_test_case(self, module: str, test_case: TestCase, filename: Optional[str] = None) -> str:
        """保存测试用例到文件"""
        module_dir = os.path.join(self.data_dir, module)
        if filename is None:
            filename = f"{test_case.case_id}.json"
        filepath = os.path.join(module_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(asdict(test_case), f, ensure_ascii=False, indent=2)

        return filepath

    def get_test_case(self, module: str, case_id: str) -> Optional[TestCase]:
        """获取指定测试用例"""
        if module in self.test_cases:
            for tc in self.test_cases[module]:
                if tc.case_id == case_id:
                    return tc
        return None

    def filter_by_tags(self, module: str, tags: List[str]) -> List[TestCase]:
        """按标签筛选测试用例"""
        if module not in self.test_cases:
            return []
        return [
            tc for tc in self.test_cases[module]
            if any(tag in tc.tags for tag in tags)
        ]

    def create_sample_test_case(self, module: str) -> TestCase:
        """创建示例测试用例"""
        if module == "asset":
            return TestCase(
                case_id="asset_sample_001",
                module="asset",
                input_data={"asset_id": "2016345500103778306"},
                expected_output={
                    "risk_level": "高危",
                    "risk_score": 85,
                    "field_completeness": 1.0
                },
                description="资产解读示例测试用例",
                tags=["sample", "basic"]
            )
        elif module == "vuln":
            return TestCase(
                case_id="vuln_sample_001",
                module="vuln",
                input_data={"vuln_id": "VULN-001"},
                expected_output={
                    "cvss_score": 7.5,
                    "risk_level": "高危",
                    "affected_assets": ["asset_001"]
                },
                description="漏洞解读示例测试用例",
                tags=["sample", "basic"]
            )
        elif module == "alert":
            return TestCase(
                case_id="alert_sample_001",
                module="alert",
                input_data={"alert_id": "8414306276020527104"},
                expected_output={
                    "threat_determination": "攻击成功",
                },
                description="安全告警解读示例测试用例（新指标体系：首字时间+总时长+威胁定性）",
                tags=["sample", "basic"]
            )
        else:
            return TestCase(
                case_id=f"{module}_sample_001",
                module=module,
                input_data={},
                expected_output={},
                description=f"{self.MODULES[module]}示例测试用例",
                tags=["sample"]
            )

# AIXDR智能体自动测试框架

## 一、项目概述

本项目用于对AIXDR智能体的各类功能进行自动化测试，通过对比AI接口返回的解析结果与XDR业务API接口的标准数据，计算并评估各项指标。

---

## 二、项目结构

```
/Users/mengyuan/Documents/trae_projects/trae_project/
├── config/
│   └── config_api.yaml              # 配置文件
├── core/                           # 核心框架
│   ├── __init__.py
│   ├── config_loader.py           # 配置加载器
│   ├── extractors/                 # 数据提取层
│   │   ├── __init__.py
│   │   ├── ai_extractor.py        # AI输出解析
│   │   └── text_extractor.py      # 文本提取
│   ├── api_clients/               # API客户端层
│   │   ├── __init__.py
│   │   ├── base_client.py         # API基类
│   │   ├── asset_client.py        # 资产详情API
│   │   └── vuln_client.py         # 漏洞列表API
│   ├── calculators/               # 指标计算层
│   │   ├── __init__.py
│   │   ├── base_calculator.py     # 计算器基类
│   │   ├── field_completeness_calc.py  # 字段完整率
│   │   └── vuln_accuracy_calc.py  # 漏洞准确率
│   └── reporter/                  # 报告生成层
│       ├── __init__.py
│       └── report_generator.py    # 报告生成器
├── tests/                        # 测试用例
│   ├── test_asset_metrics.py     # 资产解读模块评测
│   └── test_api_pytest.py       # API接口测试
├── outputs/                     # 输出目录
├── test_AI.py                  # AI接口调用脚本
└── README.md                   # 本文档
```

---

## 三、框架设计

### 3.1 分层结构

```
┌─────────────────────────────────────────────────────────────┐
│                        测试层 (tests)                        │
│                   test_asset_metrics.py                       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    报告生成层 (reporter)                     │
│                    ReportGenerator                           │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    指标计算层 (calculators)                  │
│    FieldCompletenessCalculator | VulnAccuracyCalculator      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              API客户端层 (api_clients)                       │
│          AssetAPIClient | VulnAPIClient                      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              数据提取层 (extractors)                         │
│            AIExtractor | TextExtractor                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    配置层 (config)                           │
│                     ConfigLoader                            │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 模块职责

| 模块 | 职责 |
|------|------|
| `extractors` | 从AI输出（Markdown/JSON）中提取结构化数据 |
| `api_clients` | 调用XDR业务接口获取标准数据 |
| `calculators` | 计算各项评测指标 |
| `reporter` | 生成评测报告 |

---

## 四、资产解读模块评测指标（100分）

| 序号 | 指标 | 分值 | 说明 | 数据来源 |
|------|------|------|------|----------|
| 1 | 风险等级准确率（多分类） | 20 | AI vs API | AI vs API |
| 2 | 资产风险评分准确率 | 10 | \|AI评分-API评分\| ≤5 | AI vs API |
| 3 | 资产关键字段完整率 | 10 | 识别字段数/10 | AI提取 |
| 4 | 漏洞列表准确率 | 15 | AI返回漏洞匹配率 | AI vs API |
| 5 | 关联告警/事件准确率 | 5 | 100% | AI vs API |
| 6 | 格式合规率 | 5 | 章节完整性 | AI提取 |
| 7 | 稳定性（重复执行） | 5 | 重复3次一致性 | 多次调用 |
| 8 | 首包响应时间 | 5 | <3秒 | 计时 |
| 9 | 平均响应时间 | 5 | <30秒 | 计时 |
| 10 | 整体内容正确性 | 20 | 人工/AI判定 | 综合 |

---

## 五、资产关键字段（10个）

| 字段 | 英文名 |
|------|--------|
| 资产ID | asset_id |
| IP地址 | ip_address |
| MAC地址 | mac_address |
| 主机名 | hostname |
| 资产类型 | asset_type |
| 资产等级 | asset_level |
| 操作系统 | os_name |
| 所属组织 | organization |
| 是否暴露面 | is_exposed |
| 最后上线时间 | last_online_time |

---

## 六、运行命令

### 6.1 环境准备

```bash
pip install pytest pyyaml requests
```

### 6.2 执行测试

```bash
# 1. 调用AI接口（生成AI解析数据）
python test_AI.py

# 2. 运行资产解读模块评测（新框架）
python tests/test_asset_metrics.py --asset-id 2016345500103778306

# 3. 单独计算漏洞准确率（旧工具）
python core/vuln_accuracy.py --asset-id 2016345500103778306

# 4. pytest运行
python -m pytest tests/ -v
```

---

## 七、扩展开发

### 7.1 添加新的指标计算器

1. 在 `core/calculators/` 下创建新的计算器类
2. 继承 `BaseCalculator`
3. 实现 `calculate()` 方法

```python
from core.calculators import BaseCalculator

class MyMetricCalculator(BaseCalculator):
    METRIC_NAME = "my_metric"
    METRIC_CN = "我的指标"
    MAX_SCORE = 10

    def calculate(self, ai_data, api_data) -> MetricResult:
        # 计算逻辑
        accuracy = ...
        return self._create_result(ai_value, api_value, accuracy, detail)
```

### 7.2 添加新的API客户端

1. 在 `core/api_clients/` 下创建新的客户端类
2. 继承 `BaseAPIClient`
3. 实现数据获取和解析方法

---

## 八、依赖

- Python 3.9+
- pytest
- pyyaml
- requests
- urllib3
- python-docx

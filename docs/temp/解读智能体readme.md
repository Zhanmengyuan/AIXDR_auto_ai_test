# AI 解读自动化测试智能体

## 概述

AI 解读自动化测试智能体是一个统一的测试框架，用于自动化测试 AIXDR 智能体的各类解读模块（资产解读、漏洞解读、安全告警解读、安全事件解读、沙箱报告解读等）。

## 架构

```
AIXDR_auto_ai_test/
├── agents/                              # 智能体核心模块
│   ├── __init__.py
│   ├── ai_interpret_agent.py            # 主控制器
│   └── test_case_manager.py             # 测试用例管理
├── core/
│   ├── api_clients/                     # API 客户端
│   │   ├── asset_client.py              # 资产
│   │   ├── vuln_client.py               # 漏洞
│   │   ├── alarm_client.py              # 告警
│   │   ├── event_client.py              # 事件
│   │   └── sandbox_client.py            # 沙箱（异步 submit + 轮询 getResult）
│   ├── calculators/                     # 指标计算器
│   │   └── sandbox_calculators.py       # 沙箱专属指标
│   ├── extractors/                      # 数据提取器
│   │   └── sandbox_extractor.py         # 沙箱报告解析
│   └── reporter/                        # 报告生成器
├── config/
│   └── config_api.yaml                  # 配置（含 test_sandboxes）
├── skills/                              # 审查技能规范
└── run_ai_test_agent.py                 # 运行入口
```

## 支持的模块

| 模块名 | 中文名称 | 主要评测指标 |
|--------|----------|--------------|
| asset | 资产解读 | 风险等级准确率、字段完整率、格式合规率、响应时间 |
| vuln | 漏洞解读 | CVSS 评分误差、风险等级、影响范围、响应时间 |
| alarm | 安全告警解读 | 攻击判定准确率、影响资产召回率、响应时间 |
| event | 安全事件解读 | 综合研判准确率、响应时间 |
| sandbox | 沙箱报告解读 | 风险评估等级判定准确性、样本信息提取正确率、处置建议合理性、格式规范性、章节完整性、响应时间 |

## 快速开始

### 1. 安装依赖

```bash
pip install pyyaml requests pymysql
```

### 2. 初始化示例测试用例

```bash
python3 run_ai_test_agent.py --mode init
```

### 3. 运行各模块测试

```bash
python3 run_ai_test_agent.py --module asset     # 资产解读
python3 run_ai_test_agent.py --module vuln      # 漏洞解读
python3 run_ai_test_agent.py --module alarm     # 告警解读
python3 run_ai_test_agent.py --module event     # 事件解读
python3 run_ai_test_agent.py --module sandbox   # 沙箱报告解读
```

### 4. 运行全模块测试（不含沙箱）

```bash
python3 run_ai_test_agent.py --mode all
```

## 沙箱报告解读模块

### 概述

沙箱报告解读模块测试「AI 手动解读沙箱报告」功能，通过**异步接口**提交解读任务并轮询获取结果。

### 调用流程

```
文件哈希/文件名 → MySQL 查找 XDR_DDAN_RESULT.ID → submit 提交解读
    → 轮询 getResult → 获取解读报告 → 指标计算
```

沙箱走异步接口（`/maxs/szr/llmJudge/submit` + `/maxs/szr/llmJudge/getResult`），
不同于其他模块的 SSE 流式接口（`/maxs/szr/chat/chat`）。

### 数据库配置

沙箱样本的文件哈希/文件名需先在 MySQL `XDR_DDAN_RESULT` 表查找真实 `ID`：

- 主机：`192.168.113.167:3306`，库 `SSA`
- 查找字段：`SHA1` / `FILE_NAME` / `MD5` / `SHA256`
- 基准真值来源：`EXT_FIELD_ONE` 字段（沙箱原始报告 JSON）

### 评测指标

沙箱模块共 **7 个指标**，分 5 类：

| 类别 | 指标 | 计算方式 | 合格阈值 |
|------|------|---------|---------|
| 性能 | 首包响应时间 | 首次 getResult 返回有效记录时间 − submit 发起时间 | ≤3秒 |
| 性能 | 总包处理时长 | 解读完成时间 − submit 发起时间 | ≤100秒 |
| 准确性 | 风险评估等级判定准确性 | AI 风险等级 vs 基准真值 `OverallROZRating`（0=良性/1=低风险/2=中风险/3=高风险/负数=检测失败） | 100%（关键项） |
| 准确性 | 样本信息提取正确率 | AI 提取字段 vs 基准真值，10 个必检字段逐项比对（含时区归一化） | 100% |
| 合理性 | 处置建议合理性 | LLM-as-a-Judge 4维度打分（证据匹配35+可执行性30+延伸覆盖20+字段准确性15） | ≥60分 |
| 规范性 | 格式规范性 | 扫描控制字符、Prompt残留、原始字段名 | 0处违规 |
| 完整性 | 章节完整性 | 检查 11 个固定章节是否存在 | 11/11 |

### 样本信息 10 个必检字段

原始文件名、MD5、SHA1、SHA256、父样本SHA1、文件大小、分析开始时间、分析结束时间、样本解压密码、文件真实类型。

判定规则：**AI 提取到的字段才参与比对**，没提取到则跳过；基准值为空则跳过。

### 风险等级映射

| 数值 | 含义 |
|------|------|
| 0 | 良性 |
| 1 | 低风险 |
| 2 | 中风险 |
| 3 | 高风险 |
| -1 | 不支持的文件类型 |
| -19 | 无法访问 URL |
| 负数 | 检测失败 |

风险等级字段区分：
- `OverallROZRating`：综合风险评估等级（最终结论性评分，优先采用）
- `@ROZRating`：文件类型风险等级（静态属性预评分）

### 配置

沙箱测试样本在 `config/config_api.yaml` 中配置：

```yaml
test_sandboxes:
  - "2c1fd91bc1ce1c71c2b7421ef79c015df19c0ff9"   # SHA1 哈希
  - "wertyulkjnbvcxxcb.exe"                        # 或文件名
```

## 核心组件说明

### AIInterpretAgent（主控制器）

位置：`agents/ai_interpret_agent.py`

主要功能：
- `call_ai_with_timing()`: 调用 AI 接口并测量响应时间（沙箱走 `_call_sandbox_ai` 异步分支）
- `run_test_case()`: 执行单个测试用例
- `run_module_tests()`: 执行指定模块的测试
- `run_all_tests()`: 执行所有模块的测试
- `_generate_comprehensive_report()`: 生成综合测试报告

### 指标计算器

位置：`core/calculators/`

已实现的计算器：
- `RiskLevelCalculator`: 风险等级准确率（宏平均 F1）
- `CVSSCalculator`: CVSS 评分误差
- `ResponseTimeCalculator`: 响应时间测量
- `FieldCompletenessCalculator`: 字段完整率
- `FormatComplianceCalculator`: 格式合规率
- `SandboxRiskLevelCalculator`: 沙箱风险评估等级判定准确性
- `SandboxInfoExtractionCalculator`: 沙箱样本信息提取正确率
- `SandboxDisposalCalculator`: 沙箱处置建议合理性（LLM-as-a-Judge）
- `SandboxFormatCalculator`: 沙箱格式规范性
- `SandboxCompletenessCalculator`: 沙箱章节完整性

## 测试用例格式

测试用例使用 JSON 格式存储：

```json
{
    "case_id": "asset_sample_001",
    "module": "asset",
    "input_data": {
        "asset_id": "2016345500103778306"
    },
    "expected_output": {
        "risk_level": "高危",
        "risk_score": 85
    },
    "description": "资产解读示例测试用例",
    "tags": ["sample", "basic"]
}
```

## 测试报告

测试执行完成后，会在 `outputs/ai_test_agent/` 目录下生成综合测试报告：
- `ai_interpret_test_report.json`: 完整的 JSON 格式报告
- `html_reports/`: HTML 可视化报告

报告包含内容：
- 各模块测试摘要
- 测试用例详细结果
- 各项指标得分
- 响应时间统计
- 成功率统计

## 使用示例

### 自定义测试用例

```python
from agents import TestCaseManager, TestCase

manager = TestCaseManager()

test_case = TestCase(
    case_id="my_test_001",
    module="asset",
    input_data={"asset_id": "2016345500103778306"},
    expected_output={"risk_level": "高危"},
    description="我的自定义测试用例",
    tags=["custom"]
)

manager.save_test_case("asset", test_case)
```

### 使用 API 直接调用

```python
from agents import AIInterpretAgent

agent = AIInterpretAgent()

# 运行资产解读模块测试
results = agent.run_module_tests("asset")

# 运行所有模块测试
all_results = agent.run_all_tests()
```

## 扩展新模块

1. 在 `agents/ai_interpret_agent.py` 的 `MODULE_CONFIG` 中添加配置
2. 实现模块特定的解析方法 `_parse_<module>()`
3. （可选）添加新的指标计算器
4. 在 `config/config_api.yaml` 中添加测试 ID 列表

## 自动审查功能

### 功能概述

自动审查功能基于 LLM-as-a-Judge 方式，使用大模型自动审查 AI 生成的解读报告，确保报告符合技能规范要求。

> 注意：沙箱模块不参与自动审查，`run_batch_audit_after_interpret` 会自动跳过 sandbox。

### 工作流程

```
原始解读报告 → LLM自动审查 → 审查报告(_audit.md) → 自动汇总 → 总结报告(_audit_summary.md)
```

### 目录结构

```
outputs/
├── ai_test_agent/              # AI解读测试（run_ai_test_agent.py）生成
│   ├── alarm_raw_md/          # 原始告警解读报告
│   ├── event_raw_md/          # 原始事件解读报告
│   ├── vuln_raw_md/           # 原始漏洞解读报告
│   ├── sandbox_raw_md/        # 原始沙箱解读报告
│   └── html_reports/          # HTML 可视化报告
├── batch_audit/               # 批量审查（run_batch_audit.py）生成
│   ├── alarm_report/          # 告警审查报告
│   │   ├── {告警编号}_audit.md          # 审查报告
│   │   └── alarm_audit_summary.md       # 审查总结报告
│   ├── event_report/          # 事件审查报告
│   │   ├── {事件编号}_audit.md          # 审查报告
│   │   └── event_audit_summary.md       # 审查总结报告
│   └── vuln_report/           # 漏洞审查报告
│       ├── {漏洞ID}_audit.md            # 审查报告
│       └── vuln_audit_summary.md        # 审查总结报告
└── stability_test/            # 稳定性测试（run_stability_test.py）生成
    ├── stability_md/          # 稳定性测试原始markdown
    └── stability_reports/     # 稳定性测试报告
```

### 使用方法

#### 审查告警报告

```bash
python3 run_batch_audit.py alarm
```

#### 审查事件报告

```bash
python3 run_batch_audit.py event
```

#### 审查漏洞报告

```bash
python3 run_batch_audit.py vuln
```

#### 审查所有类型报告

```bash
python3 run_batch_audit.py all
```

### 审查报告内容

审查报告包含以下内容：

1. **总体审计结论**: 合规评级、综合得分、违规项计数、一句话总评
2. **评分详情**: 各维度得分、扣分说明、评级映射标准
3. **违规项详情**: 违规章节、违规类型、违规描述
4. **合规项详情**: 合规章节、合规说明
5. **纠错修改指引**: 可直接复制替换的修正 Markdown 片段

### 评级标准

| 分数区间 | 评级 | 处置 |
|----------|------|------|
| 90-100分 | 完全合规 | 可直接发布 |
| 70-89分 | 局部瑕疵(需微调) | 修正后可发布 |
| 0-69分 | 严重违规(驳回重写) | 驳回,重新生成 |

### 总结报告

批量审查完成后，系统会自动生成总结报告，包含：

- 审查统计（总报告数、成功数、平均分）
- 成功审查报告详情（ID、评级、得分、违规项数）
- 生成失败报告详情（ID、失败原因）
- 审查报告文件清单
- 结论

### 配置说明

LLM 参数配置在 `config/config_api.yaml` 文件中：

```yaml
llm:
  api_key: "your-api-key"
  api_url: "https://llm.asiainfo-sec.com/v1/chat/completions"
  model: "gpt-5.4-mini"
```

## 依赖项

- Python 3.7+
- requests
- pyyaml
- pymysql

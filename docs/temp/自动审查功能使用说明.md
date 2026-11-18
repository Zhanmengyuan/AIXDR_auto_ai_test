"""
自动审查功能使用说明
====================

## 功能概述

自动审查功能基于Trae IDE的审查技能（alarm_report_audit、event_report_audit、vuln_report_audit），
实现了对AI生成的解读报告的自动审查准备。

## 工作流程

1. **生成解读报告**: AI智能体生成告警、事件、漏洞解读报告并保存为Markdown文件
2. **自动准备审查**: 系统自动读取报告内容，准备审查输入，并保存到临时文件
3. **调用审查技能**: 用户在Trae IDE对话中调用相应的审查技能执行审查
4. **保存审查报告**: 审查技能生成审查报告并自动保存到指定目录

## 目录结构

```
outputs/
├── ai_test_agent/                  # AI解读测试（run_ai_test_agent.py）生成
│   ├── alarm_raw_md/               # 原始告警解读报告
│   ├── alarm_raw_json/             # 原始告警解读数据
│   ├── event_raw_md/               # 原始事件解读报告
│   ├── event_raw_json/             # 原始事件解读数据
│   ├── vuln_raw_md/                # 原始漏洞解读报告
│   ├── vuln_raw_json/              # 原始漏洞解读数据
│   └── html_reports/               # HTML 可视化报告
├── batch_audit/                    # 批量审查（run_batch_audit.py）生成
│   ├── alarm_report/               # 告警审查报告
│   │   ├── {告警编号}_audit.md          # 审查报告
│   │   └── {告警编号}_audit_input.txt   # 审查输入
│   ├── event_report/               # 事件审查报告
│   │   ├── {事件编号}_audit.md          # 审查报告
│   │   └── {事件编号}_audit_input.txt   # 审查输入
│   ├── vuln_report/                # 漏洞审查报告
│   │   ├── {CVE编号}_audit.md           # 审查报告
│   │   └── {CVE编号}_audit_input.txt    # 审查输入
│   └── audit_reports/              # 综合审查HTML报告
└── stability_test/                 # 稳定性测试（run_stability_test.py）生成
    ├── stability_md/               # 稳定性测试原始markdown
    └── stability_reports/          # 稳定性测试报告（JSON + HTML）
```

## 使用方法

### 方法1：自动审查（推荐）

在生成解读报告后，系统会自动准备审查输入并输出提示信息：

```
============================================================
🔍 自动审查准备完成
============================================================
  报告类型: alarm
  报告ID: 8327584877785079808
  报告文件: outputs/ai_test_agent/alarm_raw_md/alarm_report_8327584877785079808.md
  审查输入文件: outputs/batch_audit/alarm_report/8327584877785079808_audit_input.txt
  审查技能: alarm_report_audit
============================================================

💡 执行审查的方法:
   方法1: 在Trae IDE对话中输入以下内容:
   '请使用 alarm_report_audit 技能审查以下报告'
   然后将审查输入文件内容粘贴到对话中

   方法2: 直接在对话中输入:
   '请审查 alarm 报告 8327584877785079808'
   系统会自动调用 alarm_report_audit 技能
============================================================
```

### 方法2：手动审查

如果需要手动审查特定报告，可以使用以下方法：

```python
from core.auditors import AutoAuditManager

# 创建自动审查管理器
manager = AutoAuditManager()

# 审查特定告警报告
results = manager.auto_audit_report('alarm', '8327584877785079808')

# 审查所有告警报告
results = manager.auto_audit_report('alarm')

# 审查所有类型的报告
all_results = manager.auto_audit_all_reports()

# 查看审查摘要
manager.print_audit_summary()
```

## 审查技能说明

### alarm_report_audit（告警审查）

- **输入**: 待审计告警解读报告完整原文
- **输出**: 标准化审计报告，包含合规评级、违规统计、纠错修改指引
- **审查维度**: 结构完整性、逻辑分支、红线合规、处置建议、内容质量
- **保存位置**: outputs/batch_audit/alarm_report/{告警编号}_audit.md

### event_report_audit（事件审查）

- **输入**: 待审计事件解读报告完整原文
- **输出**: 标准化审计报告，包含合规评级、违规统计、纠错修改指引
- **审查维度**: 结构完整性、聚合视角、逻辑分支、红线合规、处置建议、内容质量
- **保存位置**: outputs/batch_audit/event_report/{事件编号}_audit.md

### vuln_report_audit（漏洞审查）

- **输入**: 待审计漏洞解读报告完整原文
- **输出**: 标准化审计报告，包含合规评级、违规统计、纠错修改指引
- **审查维度**: 结构完整性、研判结论、条件性章节、红线合规、内容与修复建议、内容质量
- **保存位置**: outputs/batch_audit/vuln_report/{CVE编号}_audit.md

## 审查报告内容

审查报告包含以下内容：

1. **总体审计结论**: 合规评级、综合得分、违规项计数、一句话总评
2. **评分详情**: 各维度得分、扣分说明、评级映射标准
3. **违规项详情**: 违规章节、违规类型、违规描述
4. **合规项详情**: 合规章节、合规说明
5. **纠错修改指引**: 可直接复制替换的修正Markdown片段

## 评级标准

| 分数区间 | 评级 | 处置 |
|----------|------|------|
| 90-100分 | 完全合规 | 可直接发布 |
| 70-89分 | 局部瑕疵(需微调) | 修正后可发布 |
| 0-69分 | 严重违规(驳回重写) | 驳回,重新生成 |

## 示例：审查告警报告

### 步骤1：生成解读报告

```bash
python run_ai_test_agent.py --module alarm
```

系统会自动生成告警解读报告并准备审查输入。

### 步骤2：调用审查技能

在Trae IDE对话中输入：

```
请使用 alarm_report_audit 技能审查告警报告 8327584877785079808
```

或者：

```
请审查 alarm 报告 8327584877785079808
```

### 步骤3：查看审查报告

审查报告会自动保存到：

```
outputs/batch_audit/alarm_report/8327584877785079808_audit.md
```

## 注意事项

1. **审查技能调用**: 审查技能需要在Trae IDE对话环境中调用，无法从Python代码直接调用
2. **审查输入准备**: 系统会自动准备审查输入并保存到临时文件，用户可以直接使用
3. **审查报告保存**: 审查技能会自动将审查报告保存到指定目录，无需手动保存
4. **审查覆盖率**: 可以使用 `manager.print_audit_summary()` 查看审查覆盖率

## 常见问题

### Q1: 为什么需要手动调用审查技能？

A: Trae IDE的Skill工具只能在对话环境中使用，无法从Python代码直接调用。系统会自动准备审查输入，用户只需在对话中调用审查技能即可。

### Q2: 如何批量审查所有报告？

A: 使用 `manager.auto_audit_all_reports()` 方法准备所有报告的审查输入，然后在对话中逐个调用审查技能。

### Q3: 审查报告保存在哪里？

A: 审查报告保存在 `outputs/batch_audit/{报告类型}_report/` 目录下，文件名格式为 `{报告ID}_audit.md`。

### Q4: 如何查看审查摘要？

A: 使用 `manager.print_audit_summary()` 方法查看各类型报告的审查覆盖率。

## 技术实现

- **AutoAuditManager**: 自动审查管理器，负责准备审查输入、保存审查报告、管理审查流程
- **ai_interpret_agent.py**: AI解读智能体，集成自动审查功能，在生成报告后自动准备审查输入
- **审查技能**: alarm_report_audit、event_report_audit、vuln_report_audit，负责执行实际审查

## 后续优化

1. **自动化程度提升**: 探索从Python代码直接调用Skill工具的方法
2. **审查结果分析**: 添加审查结果统计分析功能
3. **批量审查**: 实现批量审查多个报告的功能
4. **审查报告可视化**: 生成审查报告的可视化图表
"""
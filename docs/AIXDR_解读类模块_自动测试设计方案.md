# AIXDR智能体 解读类模块 自动测试设计方案

## 一、概述

### 1.1 目的
本方案针对AIXDR智能体测试评价标准中的**解读类模块**，设计一套可自动化执行的测试评价体系，实现对智能体输出质量的量化评估。

### 1.2 范围
解读类模块包括：
| 模块 | 评测重点 |
|------|----------|
| 安全告警/事件解读 | 攻击判定F1（三分类）、字段完整性、格式合规、稳定性、响应时间 |
| 资产解读 | 风险等级准确率、CVSS评分误差、字段完整性、格式合规 |
| 漏洞解读 | CVSS评分误差、风险等级、影响版本范围、关联资产召回/精确率 |
| 沙箱文件解读 | 恶意判定F1（二分类）、风险等级、格式合规、稳定性 |
| 恶意文件解读 | 恶意判定F1（二分类）、风险等级、格式合规、稳定性 |
| 钓鱼邮件解读 | 风险判定F1（三分类）、IOC提取、风险评分误差、格式合规 |

---

## 三、评测指标与自动评分

### 3.1 评测指标体系

#### 3.1.1 安全告警/事件解读

```
┌─────────────────────────────────────────────────────────────────┐
│                      自动测试执行引擎                            │
├─────────────────────────────────────────────────────────────────┤
│  测试用例管理  │  API调用层  │  结果解析  │  评分计算  │  报告生成 │
└─────────────────────────────────────────────────────────────────┘
        │              │            │            │            │
        ▼              ▼            ▼            ▼            ▼
   测试数据集     被测智能体     结构化输出    量化评分     测试报告
   (Excel/JSON)   (flowStream)   (JSON/MD)   (指标维度)    (HTML/Excel)
```

### 2.2 核心组件

| 组件 | 职责 |
|------|------|
| `TestDataManager` | 管理测试数据集的加载、校验、按模块分类 |
| `AIXDRClient` | 封装API调用逻辑，处理流式响应、异常重试 |
| `ResultParser` | 解析智能体输出，提取关键字段（JSON/Markdown） |
| `MetricsCalculator` | 按模块计算各项评测指标（F1、完整率、合规率等） |
| `Scorer` | 基于评分标准计算综合分值 |
| `ReportGenerator` | 生成可视化测试报告（支持Excel、HTML） |

---

## 三、评测指标与自动评分

### 3.1 评测指标体系

#### 3.1.1 安全告警/事件解读

| 指标 | 计算方法 | 期望值 | 分值 | 自动化方式 |
|------|----------|--------|------|------------|
| 攻击成功判定F1 | 三分类宏平均F1 | >0.85 | 30 | 脚本自动 |
| 受影响资产完整率 | 字段缺失率 | 100% | 10 | 脚本自动 |
| 格式合规率 | 必需章节缺失率 | 100% | 5 | 脚本自动 |
| 稳定性 | 10次重复关键字段一致率 | 100% | 10 | 脚本自动 |
| 首包响应时间 | 平均值 | <3秒 | 5 | 脚本计时 |
| 平均响应时间 | 平均值 | <30秒 | 5 | 脚本计时 |
| 整体内容正确性 | 专家抽检正确率 | ≥95% | 20 | AI相似度 |

#### 3.1.2 资产解读

| 指标 | 计算方法 | 期望值 | 分值 | 自动化方式 |
|------|----------|--------|------|------------|
| 风险等级准确率 | 分类正确率 | 100% | 10 | 脚本自动 |
| 风险评分误差 | 平均绝对误差 | ≤5分 | 10 | 脚本自动 |
| 关联漏洞召回率 | 遗漏率 | ≤5% | 10 | 脚本自动 |
| 关联告警召回率 | 遗漏率 | ≤5% | 10 | 脚本自动 |
| 字段完整率 | 必填字段缺失率 | 0% | 5 | 脚本自动 |
| 格式合规率 | 必需章节缺失率 | 100% | 5 | 脚本自动 |
| 稳定性 | 10次重复一致率 | 100% | 5 | 脚本自动 |
| 首包响应时间 | 平均值 | <3秒 | 5 | 脚本计时 |
| 平均响应时间 | 平均值 | <30秒 | 5 | 脚本计时 |
| 整体内容正确性 | 专家抽检正确率 | ≥95% | 20 | AI相似度 |

#### 3.1.3 漏洞解读

| 指标 | 计算方法 | 期望值 | 分值 | 自动化方式 |
|------|----------|--------|------|------------|
| CVSS评分误差 | 平均绝对误差 | ≤0.3 | 15 | 脚本自动 |
| 风险等级准确率 | 分类正确率 | 100% | 10 | 脚本自动 |
| 影响版本范围正确性 | 完全匹配率 | 100% | 10 | 脚本自动 |
| 关联资产召回率 | 召回率 | ≥90% | 15 | 脚本自动 |
| 关联资产精确率 | 精确率 | ≥90% | 5 | 脚本自动 |
| 处置建议结构完整率 | 三个子章节完整率 | 100% | 5 | 脚本自动 |
| 格式合规率 | 必需章节缺失率 | 100% | 5 | 脚本自动 |
| 稳定性 | 10次重复一致率 | 100% | 5 | 脚本自动 |
| 首包响应时间 | 平均值 | <3秒 | 5 | 脚本计时 |
| 平均响应时间 | 平均值 | <30秒 | 5 | 脚本计时 |
| 整体内容正确性 | 专家抽检正确率 | ≥95% | 20 | AI相似度 |

#### 3.1.4 钓鱼邮件解读

| 指标 | 计算方法 | 期望值 | 分值 | 自动化方式 |
|------|----------|--------|------|------------|
| 风险判定F1 | 三分类宏平均F1 | >0.90 | 30 | 脚本自动 |
| 风险评分绝对误差 | 平均绝对误差 | ≤10分 | 10 | 脚本自动 |
| 邮件关键字段正确率 | 字段错误率 | 0% | 10 | 脚本自动 |
| IOC提取准确率 | F1 | >0.95 | 10 | 脚本自动 |
| 风险阈值一致性 | 映射正确率 | 100% | 4 | 脚本自动 |
| 格式合规率 | 必需章节缺失率 | 100% | 10 | 脚本自动 |
| 稳定性 | 10次重复一致率 | 100% | 10 | 脚本自动 |
| 首包响应时间 | 平均值 | <3秒 | 5 | 脚本计时 |
| 平均响应时间 | 平均值 | <30秒 | 5 | 脚本计时 |
| 整体内容正确性 | 专家抽检正确率 | ≥90% | 20 | AI相似度 |

#### 3.1.5 沙箱/恶意文件解读

| 指标 | 计算方法 | 期望值 | 分值 | 自动化方式 |
|------|----------|--------|------|------------|
| 恶意判定F1 | 二分类F1 | >0.85 | 30 | 脚本自动 |
| 风险等级准确率 | 分类正确率 | 100% | 10 | 脚本自动 |
| 文件属性字段完整率 | 必填字段缺失率 | 0% | 5 | 脚本自动 |
| 家族归因准确率 | 正确归因率 | 正确或"未识别" | 10 | 脚本自动 |
| 格式合规率 | 必需章节缺失率 | 100% | 5 | 脚本自动 |
| 稳定性 | 5次重复一致率 | 100% | 10 | 脚本自动 |
| 首包响应时间 | 平均值 | <3秒 | 5 | 脚本计时 |
| 平均响应时间 | 平均值 | <30秒 | 5 | 脚本计时 |
| 整体内容正确性 | 专家抽检正确率 | ≥90% | 20 | AI相似度 |

---

## 四、F1计算实现

### 4.1 三分类F1（攻击成功/失败/未知）

```python
def calculate_triple_f1(y_true: List[str], y_pred: List[str]) -> float:
    """
    计算三分类宏平均F1
    类别: 攻击成功, 攻击失败, 未知
    """
    labels = ['攻击成功', '攻击失败', '未知']
    f1_scores = []

    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        f1_scores.append(f1)

    macro_f1 = sum(f1_scores) / len(f1_scores)
    return macro_f1
```

### 4.2 二分类F1（恶意/良性）

```python
def calculate_binary_f1(y_true: List[str], y_pred: List[str], positive: str = '恶意') -> float:
    """
    计算二分类F1
    positive: 正例类别（如'恶意'）
    """
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == positive and p == positive)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t != positive and p == positive)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == positive and p != positive)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return f1
```

### 4.3 IOC提取F1

```python
def calculate_ioc_f1(predicted_iocs: List[str], true_iocs: List[str]) -> float:
    """
    计算IOC（威胁指标）提取的精确率和召回率F1
    """
    pred_set = set(predicted_iocs)
    true_set = set(true_iocs)

    tp = len(pred_set & true_set)
    fp = len(pred_set - true_set)
    fn = len(true_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return f1
```

---

## 五、测试数据集设计

### 5.1 数据集结构

```
test_data/
├── 安全告警解读/
│   ├── data.xlsx          # 问题+标准答案
│   └── sample_*.json      # 流式响应样例
├── 资产解读/
│   ├── data.xlsx
│   └── sample_*.json
├── 漏洞解读/
│   ├── data.xlsx
│   └── sample_*.json
├── 沙箱文件解读/
│   ├── data.xlsx
│   └── sample_*.json
└── 钓鱼邮件解读/
    ├── data.xlsx
    └── sample_*.json
```

### 5.2 数据格式

```json
{
  "module": "安全告警解读",
  "test_cases": [
    {
      "id": "alert_001",
      "input": {
        "alert_id": "A123456",
        "description": "检测到疑似暴力破解行为"
      },
      "expected": {
        "judgment": "攻击成功",
        "risk_level": "高危",
        "affected_assets": ["asset_001", "asset_002"]
      }
    }
  ]
}
```

### 5.3 样本量配置

| 模块 | 自动化测试样本量 | 人工抽检样本量 |
|------|------------------|----------------|
| 安全告警/事件解读 | 100 | 10 |
| 资产解读 | 100 | 10 |
| 漏洞解读 | 100 | 15 |
| 沙箱文件解读 | 100 | 10 |
| 钓鱼邮件解读 | 100 | 15 |

---

## 六、测试执行流程

### 6.1 自动化测试流程

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  加载测试集  │ ──▶ │  逐条调用API │ ──▶ │  解析响应   │ ──▶ │  计算指标   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                   │
                                                                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  生成报告   │ ◀── │  汇总评分   │ ◀── │  比对标准   │ ◀── │  存储结果   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

#### 阶段一：加载测试集

**输入**：Excel测试数据文件（test_data/{模块名}/data.xlsx）

**处理逻辑**：
```python
# 1. 读取Excel文件
df = pd.read_excel(f"test_data/{module}/data.xlsx")

# 2. 解析测试用例
test_cases = []
for _, row in df.iterrows():
    test_cases.append({
        "id": row["用例ID"],
        "input": row["输入内容"],
        "expected": {
            "judgment": row["期望判定"],
            "risk_level": row["期望风险等级"],
            "fields": json.loads(row["期望字段"]) if isinstance(row["期望字段"], str) else row["期望字段"]
        }
    })
```

**输出**：测试用例列表 `List[TestCase]`

---

#### 阶段二：逐条调用API

**输入**：测试用例列表

**处理逻辑**：
```python
results = []
for case in test_cases:
    start_time = time.time()  # 记录开始时间

    # 调用API
    response = client.call(case["input"]["query"])

    end_time = time.time()    # 记录结束时间
    response_time = end_time - start_time

    results.append({
        "id": case["id"],
        "input": case["input"],
        "expected": case["expected"],
        "actual": parse_response(response["full_text"]),
        "response_time": response_time,
        "first_packet_time": response.get("first_packet_time", 0)
    })
```

**输出**：原始响应列表 `List[RawResult]`

---

#### 阶段三：解析响应

**输入**：原始响应（流式文本拼接）

**处理逻辑**：
```python
def parse_response(full_text: str) -> dict:
    """从文本中提取结构化字段"""
    parsed = {}

    # 1. 提取判定结论（正则匹配）
    judgment_match = re.search(r'综合研判[：:]\s*([^\n]+)', full_text)
    parsed["judgment"] = judgment_match.group(1) if judgment_match else None

    # 2. 提取风险等级
    risk_match = re.search(r'风险等级[：:]\s*([^\n]+)', full_text)
    parsed["risk_level"] = risk_match.group(1) if risk_match else None

    # 3. 提取风险评分
    score_match = re.search(r'风险评分[：:]\s*(\d+)', full_text)
    parsed["risk_score"] = int(score_match.group(1)) if score_match else None

    # 4. 提取IOC列表
    ioc_matches = re.findall(r'(https?://[^\s]+|[a-zA-Z0-9._-]+\.(?:com|org|net|cn)[^\s]*)', full_text)
    parsed["iocs"] = list(set(ioc_matches))

    # 5. 提取资产列表
    asset_matches = re.findall(r'资产[ID指]：?\s*([A-Z0-9_]+)', full_text)
    parsed["assets"] = list(set(asset_matches))

    # 6. 提取CVE列表
    cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', full_text)
    parsed["cves"] = list(set(cve_matches))

    # 7. 提取CVSS评分
    cvss_match = re.search(r'CVSS[3.1]?\s*评分[：:]\s*([\d.]+)', full_text)
    parsed["cvss_score"] = float(cvss_match.group(1)) if cvss_match else None

    # 8. 检查格式合规（必需章节）
    required_sections = ["分析摘要", "资产总览", "关联脆弱性", "关联告警", "修复建议"]
    parsed["missing_sections"] = [s for s in required_sections if s not in full_text]

    return parsed
```

**输出**：结构化解析结果 `List[ParsedResult]`

---

#### 阶段四：计算指标

##### 4.1 F1分数计算

**三分类F1（安全告警/漏洞/钓鱼邮件）**：
```python
def calculate_triple_f1(results: List[dict]) -> float:
    """
    三分类：攻击成功、攻击失败、未知
    """
    labels = ['攻击成功', '攻击失败', '未知']
    f1_scores = []

    for label in labels:
        y_true = [r["expected"]["judgment"] for r in results]
        y_pred = [r["actual"].get("judgment") for r in results]

        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        f1_scores.append(f1)

    # 宏平均F1
    macro_f1 = sum(f1_scores) / len(f1_scores)

    # 转换为百分制得分
    # F1 ≥ 0.85 满分30分，每降低0.01扣0.5分
    score = min(30, 30 * macro_f1 / 0.85)
    return score
```

**二分类F1（沙箱/恶意文件）**：
```python
def calculate_binary_f1(results: List[dict]) -> float:
    """
    二分类：恶意、良性
    """
    y_true = [r["expected"]["judgment"] for r in results]
    y_pred = [r["actual"].get("judgment") for r in results]

    positive = '恶意'
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == positive and p == positive)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t != positive and p == positive)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == positive and p != positive)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # F1 > 0.85 满分30分，每降低0.01扣0.5分
    score = min(30, 30 * f1 / 0.85)
    return score
```

##### 4.2 字段完整率计算

```python
def calculate_field_completeness(results: List[dict], required_fields: List[str]) -> float:
    """
    字段完整率 = 完整用例数 / 总用例数 × 100%
    必填字段示例：["judgment", "risk_level", "affected_assets"]
    """
    complete_count = 0
    for r in results:
        is_complete = all(
            r["actual"].get(field) is not None and r["actual"].get(field) != ""
            for field in required_fields
        )
        if is_complete:
            complete_count += 1

    rate = complete_count / len(results)

    # 完整率100% 满分，少一个字段扣相应分
    score = rate * 10  # 假设字段完整率满分10分
    return score
```

##### 4.3 格式合规率计算

```python
def calculate_format_compliance(results: List[dict]) -> float:
    """
    格式合规率 = 完整章节数 / 必需章节总数
    扣分规则：每缺少一章扣2分
    """
    required_sections_map = {
        "安全告警解读": ["分析摘要", "资产总览", "关联脆弱性", "关联告警", "修复建议"],
        "资产解读": ["资产总览", "关联漏洞", "关联告警", "修复建议"],
        "漏洞解读": ["漏洞概述", "漏洞原理", "风险等级", "影响范围", "修复补丁", "处置建议"],
        "钓鱼邮件解读": ["邮件基本信息", "最终结论", "检测研判摘要", "详细研判依据", "本次解读依据"],
        "沙箱文件解读": ["样本信息", "风险评估", "网络行为分析", "威胁情报判定", "综合结论", "处置建议"]
    }

    required = required_sections_map.get(module, [])
    total_required = len(required)

    compliance_scores = []
    for r in results:
        missing = r["actual"].get("missing_sections", [])
        compliance = (total_required - len(missing)) / total_required
        compliance_scores.append(compliance)

    avg_compliance = sum(compliance_scores) / len(compliance_scores)

    # 100%合规满分，每低1%扣0.1分
    score = avg_compliance * 5
    return score
```

##### 4.4 稳定性计算

```python
def calculate_stability(client, sample: dict, n: int = 10) -> float:
    """
    稳定性 = 关键字段一致次数 / 总调用次数
    """
    key_fields = ["judgment", "risk_level"]  # 关键字段

    results = []
    for _ in range(n):
        response = client.call(sample["input"]["query"])
        parsed = parse_response(response["full_text"])
        key_values = tuple(parsed.get(f) for f in key_fields)
        results.append(key_values)

    # 统计一致次数
    consistent_count = sum(1 for r in results if r == results[0])
    rate = consistent_count / n

    # 100%一致满分，每低10%扣2分
    score = rate * 10
    return score
```

##### 4.5 响应时间计算

```python
def calculate_response_time(results: List[dict]) -> dict:
    """
    计算首包时间和平均响应时间
    """
    first_packet_times = [r["first_packet_time"] for r in results]
    avg_response_times = [r["response_time"] for r in results]

    avg_first_packet = sum(first_packet_times) / len(first_packet_times)
    avg_response = sum(avg_response_times) / len(avg_response_times)

    # 首包时间 <3秒满分，每超0.1秒扣0.5分
    first_packet_score = max(0, 5 - (avg_first_packet - 3) * 5)

    # 平均响应时间 <30秒满分，每超1秒扣0.5分
    response_score = max(0, 5 - (avg_response - 30) / 1 * 0.5)

    return {
        "avg_first_packet_time": avg_first_packet,
        "avg_response_time": avg_response,
        "first_packet_score": first_packet_score,
        "response_score": response_score
    }
```

##### 4.6 评分误差计算（资产/漏洞/钓鱼邮件）

```python
def calculate_score_error(results: List[dict], score_field: str = "risk_score") -> float:
    """
    评分误差 = |预测评分 - 期望评分|的平均值
    """
    errors = []
    for r in results:
        predicted = r["actual"].get(score_field)
        expected = r["expected"].get(score_field)
        if predicted is not None and expected is not None:
            errors.append(abs(predicted - expected))

    avg_error = sum(errors) / len(errors) if errors else 0

    # 误差≤5满分，每超0.5扣1分
    score = max(0, 10 - (avg_error - 5) * 2)
    return score


def calculate_cvss_error(results: List[dict]) -> float:
    """
    CVSS评分误差（漏洞解读）
    误差≤0.3满分，每超0.1扣2分
    """
    errors = []
    for r in results:
        predicted = r["actual"].get("cvss_score")
        expected = r["expected"].get("cvss_score")
        if predicted is not None and expected is not None:
            errors.append(abs(predicted - expected))

    avg_error = sum(errors) / len(errors) if errors else 0

    if avg_error <= 0.3:
        score = 15
    elif avg_error <= 1.5:
        score = 15 - (avg_error - 0.3) * 20
    else:
        score = 0

    return score
```

##### 4.7 IOC提取F1计算

```python
def calculate_ioc_f1(results: List[dict]) -> float:
    """
    IOC提取F1
    """
    f1_scores = []
    for r in results:
        pred_iocs = set(r["actual"].get("iocs", []))
        true_iocs = set(r["expected"].get("iocs", []))

        tp = len(pred_iocs & true_iocs)
        fp = len(pred_iocs - true_iocs)
        fn = len(true_iocs - pred_iocs)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        f1_scores.append(f1)

    avg_f1 = sum(f1_scores) / len(f1_scores)

    # F1 > 0.95满分，每低0.01扣0.2分
    score = min(10, 10 * avg_f1 / 0.95)
    return score
```

##### 4.8 召回率/精确率计算

```python
def calculate_recall_precision(results: List[dict], field: str) -> dict:
    """
    关联资产/漏洞召回率与精确率
    """
    recalls = []
    precisions = []

    for r in results:
        pred_list = set(r["actual"].get(field, []))
        true_list = set(r["expected"].get(field, []))

        if len(true_list) == 0:
            recall = 1.0 if len(pred_list) == 0 else 0.0
        else:
            recall = len(pred_list & true_list) / len(true_list)

        if len(pred_list) == 0:
            precision = 1.0 if len(true_list) == 0 else 0.0
        else:
            precision = len(pred_list & true_list) / len(pred_list)

        recalls.append(recall)
        precisions.append(precision)

    avg_recall = sum(recalls) / len(recalls)
    avg_precision = sum(precisions) / len(precisions)

    # 召回率 ≥90%满分，每低1%扣1分
    recall_score = min(15, 15 * avg_recall / 0.90)

    # 精确率 ≥90%满分，每低1%扣0.5分
    precision_score = min(5, 5 * avg_precision / 0.90)

    return {
        "recall": avg_recall,
        "precision": avg_precision,
        "recall_score": recall_score,
        "precision_score": precision_score
    }
```

##### 4.9 综合评分汇总

```python
def calculate_total_score(metrics: dict) -> float:
    """
    综合评分 = 各指标分项得分之和
    """
    total = sum(metrics.values())
    return total
```

---

#### 阶段五：比对标准

**输入**：计算后的指标结果

**处理逻辑**：
```python
def compare_with_standards(metrics: dict, module: str) -> dict:
    """
    将计算结果与期望值比对，输出通过/失败状态
    """
    standards = {
        "安全告警解读": {"f1": 0.85, "field_completeness": 1.0, "format_compliance": 1.0},
        "资产解读": {"f1": 0.85, "field_completeness": 1.0, "format_compliance": 1.0},
        "漏洞解读": {"cvss_error": 0.3, "recall": 0.90, "precision": 0.90},
        "钓鱼邮件解读": {"f1": 0.90, "ioc_f1": 0.95, "score_error": 10},
        "沙箱文件解读": {"f1": 0.85, "field_completeness": 1.0, "format_compliance": 1.0}
    }

    comparison = {}
    for key, expected in standards[module].items():
        actual = metrics.get(key)
        passed = actual >= expected if key != "cvss_error" and key != "score_error" else actual <= expected
        comparison[key] = {"expected": expected, "actual": actual, "passed": passed}

    return comparison
```

**输出**：比对结果 `Dict[MetricComparison]`

---

#### 阶段六：存储结果

**输入**：计算指标、比对结果

**输出**：JSON格式详细日志

```json
{
  "module": "安全告警解读",
  "timestamp": "2024-01-01 12:00:00",
  "total_cases": 100,
  "metrics": {
    "f1_score": 28.5,
    "field_completeness": 9.8,
    "format_compliance": 4.8,
    "stability": 9.5,
    "first_packet_time": 1.2,
    "avg_response_time": 15.3
  },
  "total_score": 62.9,
  "comparison": {
    "f1_score": {"expected": 0.85, "actual": 0.81, "passed": true}
  }
}
```

---

### 6.2 稳定性测试流程

```
测试样本 ──▶ 连续调用10次 ──▶ 提取关键字段 ──▶ 比对一致性 ──▶ 计算稳定率
                │
                ▼
          记录每次响应
          时间和质量
```

**稳定性计算公式**：
```
稳定性得分 = (一致次数 / 总调用次数) × 10分

示例：
  10次调用中，9次关键字段完全一致 → 稳定性 = 9/10 × 10 = 9分
  10次调用中，7次关键字段完全一致 → 稳定性 = 7/10 × 10 = 7分
```

---

### 6.3 测试报告生成

**输入**：所有模块的测试结果

**输出**：Excel报告

```python
def generate_report(all_results: dict, output_path: str):
    """
    生成综合测试报告
    """
    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        # Sheet1: 各模块评分汇总
        summary = []
        for module, result in all_results.items():
            summary.append({
                "模块": module,
                "F1得分": result["metrics"].get("f1_score", 0),
                "字段完整率": result["metrics"].get("field_completeness", 0),
                "格式合规率": result["metrics"].get("format_compliance", 0),
                "稳定性": result["metrics"].get("stability", 0),
                "响应时间": result["metrics"].get("response_time", 0),
                "总分": result["total_score"]
            })
        pd.DataFrame(summary).to_excel(writer, sheet_name="评分汇总", index=False)

        # Sheet2: 详细指标
        details = []
        for module, result in all_results.items():
            for metric, value in result["metrics"].items():
                details.append({
                    "模块": module,
                    "指标": metric,
                    "得分": value
                })
        pd.DataFrame(details).to_excel(writer, sheet_name="详细指标", index=False)
```

---

## 七、核心代码实现

### 7.1 API调用封装

```python
class AIXDRClient:
    def __init__(self, base_url: str, token: str, flow_id: str):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.flow_id = flow_id

    def call(self, query: str, sys_sessid: str = None) -> dict:
        """调用智能体API，返回拼接后的完整响应"""
        sys_sessid = sys_sessid or str(uuid.uuid4()).replace('-', '')
        payload = {
            "sys_sessid": sys_sessid,
            "sys_poc_version": "BC8Y123",
            "sys_userid": "141",
            "sys_poc": "xdr_mcp",
            "sys_query": query,
            "sys_flow_id": self.flow_id
        }

        response = requests.post(self.base_url, headers=self.headers,
                                  json=payload, stream=True, verify=False, timeout=30)

        stream_texts = []
        for line in response.iter_lines():
            if line:
                content = line.decode('utf-8', errors='replace').strip()
                if content.startswith('data:'):
                    content = content[5:].strip()
                data = json.loads(content)
                first_text = extract_first_text_from_stream(data)
                if first_text:
                    stream_texts.append(first_text)

        return {"full_text": ''.join(stream_texts), "session_id": sys_sessid}
```

### 7.2 指标计算器

```python
class MetricsCalculator:
    def __init__(self, module: str):
        self.module = module
        self.weights = self._get_weights()

    def calculate_all(self, results: List[dict]) -> dict:
        """计算所有指标并返回分项得分"""
        metrics = {}
        metrics['f1_score'] = self._calculate_f1(results)
        metrics['field_completeness'] = self._calculate_field_completeness(results)
        metrics['format_compliance'] = self._calculate_format_compliance(results)
        metrics['stability'] = self._calculate_stability(results)
        metrics['response_time'] = self._calculate_response_time(results)

        total_score = sum(metrics[k] * self.weights.get(k, 0)
                         for k in metrics if k in self.weights)
        metrics['total_score'] = total_score
        return metrics

    def _calculate_f1(self, results: List[dict]) -> float:
        """根据模块类型计算F1"""
        if self.module in ['安全告警解读', '漏洞解读']:
            return calculate_triple_f1(
                [r['expected']['judgment'] for r in results],
                [r['actual']['judgment'] for r in results]
            )
        elif self.module in ['沙箱文件解读', '恶意文件解读']:
            return calculate_binary_f1(
                [r['expected']['judgment'] for r in results],
                [r['actual']['judgment'] for r in results]
            )
        elif self.module == '钓鱼邮件解读':
            return calculate_triple_f1(
                [r['expected']['risk_level'] for r in results],
                [r['actual']['risk_level'] for r in results]
            )
        return 0.0
```

### 7.3 报告生成器

```python
class ReportGenerator:
    def generate_excel(self, metrics: dict, output_path: str):
        """生成Excel格式测试报告"""
        df = pd.DataFrame([
            {"指标": k, "得分": v, "期望值": self.get_expectation(k)}
            for k, v in metrics.items()
        ])
        df.to_excel(output_path, index=False)

    def generate_html(self, metrics: dict, output_path: str):
        """生成HTML可视化报告"""
        html = f"<html><head><title>{self.module} 测试报告</title></head><body>"
        html += f"<h1>{self.module} 自动测试报告</h1>"
        html += "<table border='1'><tr><th>指标</th><th>得分</th><th>期望值</th></tr>"
        for k, v in metrics.items():
            html += f"<tr><td>{k}</td><td>{v}</td><td>{self.get_expectation(k)}</td></tr>"
        html += "</table></body></html>"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
```

---

## 八、测试执行配置

### 8.1 pytest配置示例

```python
import pytest
from aitest.client import AIXDRClient
from aitest.calculator import MetricsCalculator

@pytest.fixture(scope="module")
def client():
    return AIXDRClient(
        base_url="https://10.21.22.52:9443/ai/flowStream",
        token="your_token",
        flow_id="flow-explain-alarm"
    )

@pytest.fixture(scope="module")
def test_data():
    return load_test_data("test_data/安全告警解读/data.xlsx")

def test_f1_score(client, test_data):
    calculator = MetricsCalculator("安全告警解读")
    results = []
    for case in test_data['test_cases']:
        response = client.call(case['input']['query'])
        parsed = parse_response(response['full_text'])
        results.append({
            'expected': case['expected'],
            'actual': parsed
        })
    f1 = calculator._calculate_f1(results)
    assert f1 >= 0.85, f"F1 score {f1} below expectation"

def test_format_compliance(client, test_data):
    calculator = MetricsCalculator("安全告警解读")
    results = []
    for case in test_data['test_cases']:
        response = client.call(case['input']['query'])
        parsed = parse_response(response['full_text'])
        results.append({'actual': parsed})
    compliance = calculator._calculate_format_compliance(results)
    assert compliance >= 1.0, f"Format compliance {compliance} below 100%"
```

---

## 九、预期产出

| 产出物 | 格式 | 说明 |
|--------|------|------|
| 自动化测试脚本 | Python | 完整可运行的测试框架 |
| 测试数据集 | Excel | 各模块标准测试数据 |
| 测试报告 | Excel/HTML | 分模块评分与详细分析 |
| 评测日志 | JSON | 每条测试的详细记录 |

---

## 十、后续优化方向

1. **AI辅助评分**：引入LLM对"整体内容正确性"进行自动化判定，减少人工抽检工作量
2. **实时监控**：对接生产环境，持续采集智能体表现数据
3. **回归测试**：建立版本对比机制，量化性能回归
4. **分布式执行**：支持大规模样本的并行测试，提升测试效率

---

## 十一、项目文件清理计划

### 11.1 当前项目结构

```
AIXDR_auto_ai_test/
├── agents/                          # ✅ AI解读智能体核心代码
│   ├── ai_interpret_agent.py         # 智能体主控制器
│   └── test_case_manager.py          # 测试用例管理器
├── core/                            # ✅ 核心功能模块
│   ├── api_clients/                 # API客户端
│   │   ├── asset_client.py          # 资产详情API
│   │   ├── vuln_client.py            # 漏洞列表API
│   │   ├── alert_client.py           # 告警列表API
│   │   ├── event_client.py           # 事件列表API
│   │   └── base_client.py            # API基类
│   ├── calculators/                  # 指标计算器
│   │   ├── risk_level_calc.py        # 风险等级计算
│   │   ├── vuln_accuracy_calc.py     # 漏洞准确率计算
│   │   └── ...                      # 其他计算器
│   ├── extractors/                  # 数据提取器
│   │   ├── ai_extractor.py          # AI输出提取
│   │   └── text_extractor.py         # 文本提取
│   ├── reporter/                     # 报告生成器
│   │   └── report_generator.py
│   └── config_loader.py             # 配置加载器
├── config/                          # ✅ 配置文件
│   └── config_api.yaml              # API配置
├── test_data/                       # ✅ 测试数据
│   ├── asset/                       # 资产解读测试用例
│   ├── vuln/                        # 漏洞解读测试用例
│   ├── alert/                       # 告警解读测试用例
│   └── event/                       # 事件解读测试用例
├── outputs/                         # ✅ 测试输出（按脚本分类）
│   ├── ai_test_agent/               # run_ai_test_agent.py 生成
│   ├── batch_audit/                 # run_batch_audit.py 生成
│   └── stability_test/              # run_stability_test.py 生成
├── tests/                           # ⚠️ 待清理
│   ├── test_api_pytest.py           # 旧pytest测试
│   ├── test_asset_metrics.py        # 旧单元测试
│   ├── test_response_time.py         # 旧响应时间测试
│   └── test_risk_level_batch.py      # 旧风险等级测试
├── run_ai_test_agent.py             # ✅ 主执行入口
├── batch_ai_interpret.py            # ⚠️ 可能是旧版本
├── test_AI.py                       # ⚠️ 早期测试脚本
├── README.md                         # ⚠️ 需确认是否重复
├── AI_TEST_AGENT_README.md          # ⚠️ 可能重复
├── AIXDR_解读类模块_自动测试设计方案.md  # ✅ 设计文档
└── AIXDR智能体测试评价标准.docx        # ✅ 需求文档
```

### 11.2 待清理文件清单

#### A. 根目录旧测试脚本
| 文件 | 清理建议 | 原因 |
|------|---------|------|
| `test_AI.py` | **删除** | 早期测试脚本，功能已由 `run_ai_test_agent.py` 替代 |
| `batch_ai_interpret.py` | **删除** | 可能是 `run_ai_test_agent.py` 的旧版本 |

#### B. tests/ 目录旧pytest文件
| 文件 | 清理建议 | 原因 |
|------|---------|------|
| `tests/test_api_pytest.py` | **删除** | 早期单元测试，指标计算已集成到 `ai_interpret_agent.py` |
| `tests/test_asset_metrics.py` | **删除** | 旧资产指标测试，功能已迁移 |
| `tests/test_response_time.py` | **删除** | 旧响应时间测试，功能已迁移 |
| `tests/test_risk_level_batch.py` | **删除** | 旧风险等级测试，功能已迁移 |

#### C. 文档文件
| 文件 | 清理建议 | 原因 |
|------|---------|------|
| `README.md` | **合并/删除** | 内容可能与 `AI_TEST_AGENT_README.md` 重复 |
| `AI_TEST_AGENT_README.md` | **合并到主文档** | 建议合并到 `AIXDR_解读类模块_自动测试设计方案.md` |

#### D. 旧输出文件
| 文件 | 清理建议 | 原因 |
|------|---------|------|
| `outputs/metrics_report_*.json` | **删除** | 单资产旧报告，已被 `ai_interpret_test_report.json` 替代 |
| `outputs/risk_level_batch_result.json` | **删除** | 与 `multi_asset_report.json` 功能重复 |

### 11.3 清理执行命令

```bash
# 删除旧测试脚本
rm -f test_AI.py batch_ai_interpret.py

# 删除tests目录下的旧pytest文件
rm -f tests/test_api_pytest.py tests/test_asset_metrics.py tests/test_response_time.py tests/test_risk_level_batch.py

# 删除重复文档
rm -f README.md AI_TEST_AGENT_README.md

# 删除旧输出文件
rm -f outputs/metrics_report_*.json outputs/risk_level_batch_result.json
```

### 11.4 清理后的项目结构

```
AIXDR_auto_ai_test/
├── agents/                          # AI解读智能体核心代码
│   ├── ai_interpret_agent.py         # 智能体主控制器
│   └── test_case_manager.py          # 测试用例管理器
├── core/                            # 核心功能模块
│   ├── api_clients/                 # API客户端
│   ├── calculators/                  # 指标计算器
│   ├── extractors/                  # 数据提取器
│   ├── reporter/                   # 报告生成器
│   └── config_loader.py             # 配置加载器
├── config/                          # 配置文件
├── test_data/                       # 测试数据
│   ├── asset/
│   ├── vuln/
│   ├── alert/
│   └── event/
├── outputs/                         # 测试输出（按脚本分类）
│   ├── ai_test_agent/               # run_ai_test_agent.py 生成
│   ├── batch_audit/                 # run_batch_audit.py 生成
│   └── stability_test/              # run_stability_test.py 生成
├── tests/                           # (空目录，可删除)
├── run_ai_test_agent.py             # 主执行入口
└── AIXDR_解读类模块_自动测试设计方案.md  # 设计文档
```

### 11.5 清理状态

| 类别 | 文件数 | 状态 |
|------|--------|------|
| 核心代码 | 15 | ✅ 保留 |
| 配置文件 | 1 | ✅ 保留 |
| 测试数据 | 4 | ✅ 保留 |
| 输出结果 | 12 | ✅ 保留 |
| 旧测试脚本 | 2 | ⏳ 待清理 |
| 旧pytest | 4 | ⏳ 待清理 |
| 重复文档 | 2 | ⏳ 待清理 |
| 旧输出 | 11 | ⏳ 待清理 |

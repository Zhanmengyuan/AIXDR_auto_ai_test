# 各智能体 StandardResult JSON 示例（v3.0 最简结构）

> 版本：v3.0
> 日期：2026-11-17
> 适用对象：各智能体测试负责人
> 核心原则：**只填指标值，结构字段（key/name_cn/value/accuracy）都由框架根据声明文件自动补全**
> 注：`model` 不放 JSON 里，上传时通过接口参数 `?model=xxx` 传递

---

## JSON最简结构

```json
{
  "category": "detect",
  "total_samples": 600,
  "valid_samples": 600,
  "dimensions": {
    "accuracy": {
      "f1_score": {
        "black_samples": 300,
        "black_correct": 291,
        "white_samples": 300,
        "white_correct": 295
      }
    },
    "performance": {
      "avg_response_time": 9.74
    }
  },
  "failed_samples": [
    {
      "sample_id": "attack_003",
      "reason": "AI调用超时"
    }
  ],
  "invalid_samples": []
}
```

---

## 各字段说明

### 基本字段（必填）

| 字段 | 填什么 | 示例 |
|------|--------|------|
| `category` | 分类：detect/generate/query/qa | "detect" |
| `total_samples` | 总样本数 | 600 |
| `valid_samples` | 有效样本数 | 600 |

> 注：`model` 不放 JSON 里，上传时通过接口参数 `?model=xxx` 传递（180/190/cloud 或具体型号名如 kimi-2.6）。

### dimensions（指标值，按维度组织）

每个维度下，指标key直接对应指标值。**填值规则**：

| 指标类型 | 填什么 | 示例 |
|---------|--------|------|
| 检测类F1 | 一个对象，含4个黑白样本数量 | 见下 |
| 解读类内容合规性 | 一个数字（LLM审查分0~100） | 92 |
| 准确率类 | 一个数字（0~1） | 0.848 |
| 通过率类 | 一个数字（0~1） | 1.0 |
| 性能时间 | 一个数字（秒） | 9.74 |

### failed_samples / invalid_samples（失败溯源，有则填）

```json
"failed_samples": [
  { "sample_id": "attack_003", "reason": "AI调用超时" }
]
```

| 字段 | 填什么 |
|------|--------|
| `sample_id` | 失败样本ID |
| `reason` | 失败原因 |

没有失败样本则填 `[]`。

---

## 一、检测研判类（5个）

### 1. WAF降噪

```json
{
  "category": "detect",
  "total_samples": 600,
  "valid_samples": 600,
  "dimensions": {
    "accuracy": {
      "f1_score": {
        "black_samples": 300,
        "black_correct": 291,
        "white_samples": 300,
        "white_correct": 295
      }
    },
    "performance": {
      "avg_response_time": 9.74
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

### 2. 恶意文件检测

```json
{
  "category": "detect",
  "total_samples": 1000,
  "valid_samples": 1000,
  "dimensions": {
    "accuracy": {
      "f1_score": {
        "black_samples": 500,
        "black_correct": 448,
        "white_samples": 500,
        "white_correct": 499
      }
    },
    "performance": {
      "first_packet_time": 2.01,
      "avg_response_time": 29.51
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

### 3. Webshell检测

```json
{
  "category": "detect",
  "total_samples": 1000,
  "valid_samples": 1000,
  "dimensions": {
    "accuracy": {
      "f1_score": {
        "black_samples": 500,
        "black_correct": 486,
        "white_samples": 500,
        "white_correct": 497
      }
    },
    "performance": {
      "first_packet_time": 1.68,
      "avg_response_time": 31.99
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

### 4. 钓鱼邮件检测

```json
{
  "category": "detect",
  "total_samples": 1200,
  "valid_samples": 1200,
  "dimensions": {
    "accuracy": {
      "f1_score": {
        "black_samples": 600,
        "black_correct": 469,
        "white_samples": 600,
        "white_correct": 494
      }
    },
    "performance": {
      "first_packet_time": 1.93,
      "avg_response_time": 80.78
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

### 5. 本地情报提取

```json
{
  "category": "detect",
  "total_samples": 1000,
  "valid_samples": 1000,
  "dimensions": {
    "accuracy": {
      "f1_score": {
        "black_samples": 997,
        "black_correct": 997,
        "white_samples": 3,
        "white_correct": 2
      }
    },
    "performance": {
      "avg_response_time": 638.07
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

---

## 二、内容生成类（5个）

### 6. 安全告警解读

```json
{
  "category": "generate",
  "total_samples": 50,
  "valid_samples": 47,
  "dimensions": {
    "accuracy": {
      "content_compliance": 92
    },
    "performance": {
      "first_packet_time": 0.2,
      "avg_response_time": 21.2
    }
  },
  "failed_samples": [
    {
      "sample_id": "7927904014451048448-03",
      "reason": "AI调用超时"
    },
    {
      "sample_id": "7927904014451048448-07",
      "reason": "大模型连接异常"
    },
    {
      "sample_id": "7927904014451048448-19",
      "reason": "无AI响应内容"
    }
  ],
  "invalid_samples": []
}
```

> 注：content_compliance 填 LLM 审查分（0~100），框架自动转成 accuracy = 92/100 = 0.92

### 7. 安全事件解读

```json
{
  "category": "generate",
  "total_samples": 50,
  "valid_samples": 48,
  "dimensions": {
    "accuracy": {
      "content_compliance": 91
    },
    "performance": {
      "first_packet_time": 0.2,
      "avg_response_time": 26.6
    }
  },
  "failed_samples": [
    {
      "sample_id": "7951194694177734656-05",
      "reason": "AI调用超时"
    },
    {
      "sample_id": "7951194694177734656-22",
      "reason": "大模型连接异常"
    }
  ],
  "invalid_samples": []
}
```

### 8. 资产解读

```json
{
  "category": "generate",
  "total_samples": 50,
  "valid_samples": 49,
  "dimensions": {
    "accuracy": {
      "content_compliance": 81
    },
    "performance": {
      "first_packet_time": 0.3,
      "avg_response_time": 31.9
    }
  },
  "failed_samples": [
    {
      "sample_id": "2114592165070565415-15",
      "reason": "AI调用超时"
    }
  ],
  "invalid_samples": []
}
```

### 9. 漏洞解读

```json
{
  "category": "generate",
  "total_samples": 50,
  "valid_samples": 50,
  "dimensions": {
    "accuracy": {
      "content_compliance": 92
    },
    "performance": {
      "first_packet_time": 0.3,
      "avg_response_time": 22.1
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

### 10. 沙箱文件解读

```json
{
  "category": "generate",
  "total_samples": 50,
  "valid_samples": 50,
  "dimensions": {
    "accuracy": {
      "content_compliance": 72.7
    },
    "performance": {
      "first_packet_time": 0.5,
      "avg_response_time": 51.7
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

---

## 三、查询类（2个）

### 11. text2sql

```json
{
  "category": "query",
  "total_samples": 400,
  "valid_samples": 392,
  "dimensions": {
    "accuracy": {
      "result_accuracy": 0.848
    },
    "performance": {
      "avg_response_time": 18.6
    }
  },
  "failed_samples": [
    {
      "sample_id": "query_003",
      "reason": "SQL执行超时"
    },
    {
      "sample_id": "query_017",
      "reason": "SQL语法错误"
    },
    {
      "sample_id": "query_045",
      "reason": "SQL执行超时"
    },
    {
      "sample_id": "query_089",
      "reason": "SQL语法错误"
    },
    {
      "sample_id": "query_102",
      "reason": "SQL执行超时"
    },
    {
      "sample_id": "query_156",
      "reason": "SQL语法错误"
    },
    {
      "sample_id": "query_203",
      "reason": "SQL执行超时"
    },
    {
      "sample_id": "query_288",
      "reason": "SQL语法错误"
    }
  ],
  "invalid_samples": []
}
```

### 12. 数字人知识查询

```json
{
  "category": "query",
  "total_samples": 100,
  "valid_samples": 100,
  "dimensions": {
    "accuracy": {
      "fixed_answer_accuracy": 0.931
    },
    "performance": {
      "first_packet_time": 1.27,
      "avg_response_time": 23.37
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

---

## 四、知识问答类（1个）

### 13. RAG检索

```json
{
  "category": "qa",
  "total_samples": 430,
  "valid_samples": 430,
  "dimensions": {
    "accuracy": {
      "answer_correctness": 0.84
    },
    "performance": {
      "first_packet_time": 2.04,
      "avg_response_time": 18.58
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

---

## 五、填值规则速查

| 智能体类型 | 需要填的指标 | 填什么值 |
|-----------|------------|---------|
| 检测研判类 | f1_score | 4个黑白样本数量（对象） |
| 内容生成类 | content_compliance | LLM审查分（0~100的数字） |
| 查询类 text2sql | result_accuracy | 结果准确率（0~1的数字） |
| 查询类 数字人 | fixed_answer_accuracy | 固定答案准确率（0~1的数字） |
| 知识问答类 RAG | answer_correctness | 答案正确性（0~1的数字） |
| 所有智能体 | 性能指标 | 时间值（秒的数字） |

**关键规则**：
- 检测类F1 → 填对象（4个黑白样本数量），框架算F1
- 解读类content_compliance → 填数字（LLM审查分0~100），框架转accuracy
- 准确率类 → 填数字（0~1）
- 通过率类 → 填数字（0~1）
- 性能时间 → 填数字（秒）

---

## 六、上传方式

```bash
curl -X POST "http://10.x.x.x:8080/api/v1/results?agent_id=waf_dedup&run_id=v190_20261117&model=190" \
  -H "Content-Type: application/json" \
  -d @waf_dedup_results.json
```

```python
import requests

resp = requests.post(
    "http://10.x.x.x:8080/api/v1/results",
    params={"agent_id": "waf_dedup", "run_id": "v190_20261117", "model": "190"},
    json=data
)
print(resp.json())
```

上传成功返回：
```json
{
  "status": "ok",
  "agent_id": "waf_dedup",
  "run_id": "v190_20261117",
  "count": 1
}
```

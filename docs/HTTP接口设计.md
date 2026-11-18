# HTTP 接口设计文档

> 版本：v1.0
> 日期：2026-11-17

---

## 一、接口概述

| 项目 | 说明 |
|------|------|
| 协议 | HTTP |
| 数据格式 | JSON |
| 认证 | 暂无（内网使用） |
| 服务端口 | 8080（可配置） |
| 框架 | FastAPI |

---

## 二、接口清单

| 接口 | 方法 | 用途 |
|------|------|------|
| `/api/v1/results` | POST | 上传智能体测试结果 |
| `/api/v1/results/{agent_id}` | GET | 查询某智能体上传结果 |
| `/api/v1/batch/{run_id}/status` | GET | 查询批次上传状态 |
| `/api/v1/health` | GET | 健康检查（服务是否正常） |

---

## 三、POST /api/v1/results — 上传测试结果

### 请求

```
POST /api/v1/results?agent_id={agent_id}&run_id={run_id}&model={model}
Content-Type: application/json
```

**URL参数**：

| 参数 | 必填 | 说明 | 示例 |
|------|:---:|------|------|
| `agent_id` | ✅ | 智能体标识 | waf_dedup |
| `run_id` | ✅ | 批次标识 | v190_20261117 |
| `model` | ✅ | 大模型型号名 | 180 / 190 / cloud / kimi-2.6 / deepseek-v4-pro 等 |

model 取值说明：

| model值 | 含义 |
|---------|------|
| `180` | 180一体机 |
| `190` | 190一体机 |
| `cloud` | 云端大模型 |
| 具体型号名 | 直接填模型型号名，如 `kimi-2.6`、`deepseek-v4-pro`、`glm-5.2` 等 |

**请求体**：一个智能体的汇总JSON对象（v3最简结构，不含 model 字段）

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
    "reliability": {
      "stability_rate": 1.0
    },
    "content_quality": {
      "content_correctness": 0.92
    },
    "performance": {
      "avg_response_time": 9.74
    }
  },
  "failed_samples": [],
  "invalid_samples": []
}
```

### 校验规则

接收端收到请求后，按该智能体的声明文件（`config/agents/{agent_id}.yaml`）校验：

1. **model** 必填，非空即可（180/190/cloud 为固定值，其他为具体模型型号名）
2. **category** 必填，值必须和声明文件一致
3. **total_samples / valid_samples** 必填，valid ≤ total，且为非负整数
4. **dimensions** 必填，至少有一个维度
5. **上传的每个指标**：
   - 指标key必须在声明文件中存在（声明文件没有的指标会被拒绝）
   - 指标维度必须和声明文件一致
   - F1类型（type=f1）：值必须是对象，包含4个黑白样本字段（black_samples/black_correct/white_samples/white_correct），均为非负整数，且 correct ≤ samples
6. **failed_samples / invalid_samples**：每个元素必须有sample_id和reason

> 注：声明文件里的指标不需要全部上传（允许部分参测），但上传的指标必须符合声明文件定义。

### 响应

**成功**：

```json
{
  "status": "ok",
  "agent_id": "waf_dedup",
  "run_id": "v190_20261117",
  "model": "190",
  "saved_to": "outputs/results/v190_20261117/waf_dedup.json"
}
```

**校验失败**：

```json
{
  "status": "error",
  "code": "VALIDATION_ERROR",
  "message": "dimensions.accuracy.f1_score 缺少 black_correct 字段"
}
```

### 错误码

| code | HTTP状态码 | 说明 |
|------|:---:|------|
| `VALIDATION_ERROR` | 400 | 字段校验失败（缺字段、类型错误、值超范围） |
| `INVALID_JSON` | 400 | 请求体不是有效的JSON |
| `INVALID_MODEL` | 400 | model 参数为空 |
| `AGENT_NOT_FOUND` | 404 | agent_id在声明文件中不存在 |
| `NOT_FOUND` | 404 | 未找到指定批次的结果 |

> 注：同一agent_id+run_id重复上传，直接覆盖之前的数据，不返回错误。

---

## 四、GET /api/v1/results/{agent_id} — 查询上传结果

### 请求

```
GET /api/v1/results/{agent_id}?run_id={run_id}
```

### 响应

```json
{
  "status": "ok",
  "agent_id": "waf_dedup",
  "run_id": "v190_20261117",
  "data": { ... 上传的JSON ... }
}
```

---

## 五、GET /api/v1/batch/{run_id}/status — 查询批次状态

### 请求

```
GET /api/v1/batch/v190_20261117/status
```

### 响应

```json
{
  "status": "ok",
  "run_id": "v190_20261117",
  "total_agents": 13,
  "uploaded": 5,
  "pending": 8,
  "agents": [
    {"agent_id": "waf_dedup", "status": "uploaded", "uploaded_at": "2026-11-17 14:30:00"},
    {"agent_id": "ai_interpret_alarm", "status": "uploaded", "uploaded_at": "2026-11-17 14:35:00"},
    {"agent_id": "malfile_detect", "status": "pending"},
    ...
  ]
}
```

| status值 | 含义 |
|----------|------|
| `uploaded` | 已上传 |
| `pending` | 未上传 |

---

## 六、存储路径

```
outputs/results/{run_id}/{agent_id}.json
```

示例：
```
outputs/results/v190_20261117/
├── waf_dedup.json
├── malfile_detect.json
├── ai_interpret_alarm.json
└── ...
```

同一agent_id+run_id重复上传，覆盖之前的数据。

---

## 七、分批上传

样本量大时不需要分批，因为v3结构是汇总对象（一个智能体一个JSON），不是逐样本数组。一个JSON文件通常只有几KB。

---

## 八、上传示例

**curl**：

```bash
curl -X POST "http://10.x.x.x:8080/api/v1/results?agent_id=waf_dedup&run_id=v190_20261117&model=190" \
  -H "Content-Type: application/json" \
  -d @waf_dedup_results.json
```

**Python requests**：

```python
import requests

data = {
    "category": "detect",
    "total_samples": 600,
    "valid_samples": 600,
    "dimensions": {
        "accuracy": {
            "f1_score": {
                "black_samples": 300, "black_correct": 291,
                "white_samples": 300, "white_correct": 295
            }
        },
        "performance": {"avg_response_time": 9.74}
    },
    "failed_samples": [],
    "invalid_samples": []
}

resp = requests.post(
    "http://10.x.x.x:8080/api/v1/results",
    params={"agent_id": "waf_dedup", "run_id": "v190_20261117", "model": "190"},
    json=data
)
print(resp.json())
```

---

## 九、各团队上传前自查清单

上传前各团队对照检查：

- [ ] category 和声明文件一致
- [ ] total_samples 和 valid_samples 已填，valid ≤ total
- [ ] dimensions 至少有一个维度
- [ ] 检测类F1：f1_score 里有4个黑白样本字段
- [ ] 解读类：content_compliance 填了LLM审查分（0~100）
- [ ] 性能：首包/平均响应时间填了秒数
- [ ] failed_samples 里有失败样本ID和原因
- [ ] 没测的维度不传
- [ ] 上传时 model 参数填正确（180/190/cloud 或具体型号名如 kimi-2.6）

---

## 十、GET /api/v1/health — 健康检查

### 请求

```
GET /api/v1/health
```

### 响应

```json
{
  "status": "ok",
  "service": "AI 智能体统一测试框架",
  "version": "1.0",
  "registered_agents": 13,
  "agents": ["waf_dedup", "malfile_detect", "ai_interpret_alarm", "..."]
}
```

用于检查服务是否正常运行，以及哪些智能体已注册可上传。

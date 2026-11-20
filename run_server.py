"""
HTTP 接收端 (FastAPI)

接收各智能体团队上传的测试结果JSON，校验后存储到 outputs/results/{run_id}/{agent_id}.json

启动方式：
    python run_server.py                    # 默认端口8080
    python run_server.py --port 9090        # 指定端口
"""
import os
import sys
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.validator import ManifestRegistry, validate_result
from core.aggregator import merge_result


app = FastAPI(title="AI 智能体统一测试框架", version="1.0")

# 项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "outputs", "results")


# ── 启动时加载声明文件 ──
registry = ManifestRegistry.get_instance()


# ── 接口1：上传测试结果 ──

@app.post("/api/v1/results")
async def upload_results(
    request: Request,
    agent_id: str = Query(..., description="智能体标识"),
    run_id: str = Query(..., description="批次标识"),
    model: str = Query(..., description="大模型标识：180/190/cloud/第三方模型名(minimax/kimi等)"),
):
    """上传智能体测试结果

    agent_id/run_id/model 均通过 query 参数传递，请求体只含测试数据（不含 model 字段）
    model 取值：180 / 190 / cloud / 第三方模型名（如 minimax、kimi、deepseek 等）
    """
    # 校验 model 非空
    if not model or not model.strip():
        raise HTTPException(status_code=400, detail={
            "status": "error",
            "code": "INVALID_MODEL",
            "message": "model 参数不能为空"
        })
    model = model.strip()

    # 校验 run_id 与 model 匹配：run_id 的批次前缀（第一个 _ 之前）必须为 v{model}
    # 例如 model=190 要求 run_id 形如 v190_xxx，防止数据混批
    batch_prefix = run_id.split("_", 1)[0]
    if batch_prefix.lower() != f"v{model.lower()}":
        raise HTTPException(status_code=400, detail={
            "status": "error",
            "code": "MODEL_BATCH_MISMATCH",
            "message": "模型和批次不符，请保证模型和批次吻合"
        })

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={
            "status": "error",
            "code": "INVALID_JSON",
            "message": "请求体不是有效的JSON"
        })

    # 检查 agent_id 是否在声明文件中
    manifest = registry.get_manifest(agent_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail={
            "status": "error",
            "code": "AGENT_NOT_FOUND",
            "message": f"agent_id '{agent_id}' 不在声明文件中，可用：{registry.list_agents()}"
        })

    # 校验数据
    ok, msg = validate_result(agent_id, data, manifest)
    if not ok:
        raise HTTPException(status_code=400, detail={
            "status": "error",
            "code": "VALIDATION_ERROR",
            "message": msg
        })

    # 存储（支持合并：同一 agent_id 多次上传不同维度时合并，而不是覆盖）
    run_dir = os.path.join(RESULTS_DIR, run_id)
    os.makedirs(run_dir, exist_ok=True)
    filepath = os.path.join(run_dir, f"{agent_id}.json")

    # 补充 model 和上传时间
    data["model"] = model
    data["_uploaded_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 如果已存在，按指标类型聚合（样本数累加 / f1 计数累加 / 标量加权平均 / 样本并集）
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            existing = json.load(f)
        data = merge_result(existing, data, manifest)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return {
        "status": "ok",
        "agent_id": agent_id,
        "run_id": run_id,
        "model": model,
        "saved_to": filepath.replace(BASE_DIR + "/", "")
    }


# ── 接口2：查询某智能体上传结果 ──

@app.get("/api/v1/results/{agent_id}")
async def get_results(
    agent_id: str,
    run_id: str = Query(..., description="批次标识"),
):
    """查询某智能体在某批次的上传结果"""
    filepath = os.path.join(RESULTS_DIR, run_id, f"{agent_id}.json")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail={
            "status": "error",
            "code": "NOT_FOUND",
            "message": f"未找到 {agent_id} 在 {run_id} 批次的结果"
        })

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "status": "ok",
        "agent_id": agent_id,
        "run_id": run_id,
        "data": data
    }


# ── 接口3：查询批次上传状态 ──

@app.get("/api/v1/batch/{run_id}/status")
async def get_batch_status(run_id: str):
    """查询某批次的各智能体上传状态"""
    run_dir = os.path.join(RESULTS_DIR, run_id)
    all_agents = registry.list_agents()

    uploaded = []
    pending = []

    for agent_id in all_agents:
        filepath = os.path.join(run_dir, f"{agent_id}.json")
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            uploaded.append({
                "agent_id": agent_id,
                "status": "uploaded",
                "uploaded_at": data.get("_uploaded_at", "unknown")
            })
        else:
            pending.append({
                "agent_id": agent_id,
                "status": "pending"
            })

    return {
        "status": "ok",
        "run_id": run_id,
        "total_agents": len(all_agents),
        "uploaded": len(uploaded),
        "pending": len(pending),
        "agents": uploaded + pending
    }


# ── 接口4：健康检查 ──

@app.get("/api/v1/health")
async def health():
    """健康检查"""
    return {
        "status": "ok",
        "service": "AI 智能体统一测试框架",
        "version": "1.0",
        "registered_agents": len(registry.list_agents()),
        "agents": registry.list_agents()
    }


def main():
    parser = argparse.ArgumentParser(description="AI 智能体统一测试框架 HTTP 服务")
    parser.add_argument("--port", type=int, default=8080, help="服务端口（默认8080）")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址（默认0.0.0.0）")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"🚀 AI 智能体统一测试框架 HTTP 服务")
    print(f"{'='*60}")
    print(f"📂 项目目录: {BASE_DIR}")
    print(f"📁 结果目录: {RESULTS_DIR}")
    print(f"📋 已加载 {len(registry.list_agents())} 个智能体声明文件")
    print(f"🌐 服务地址: http://{args.host}:{args.port}")
    print(f"{'='*60}")
    print(f"接口：")
    print(f"  POST /api/v1/results?agent_id=xxx&run_id=xxx  上传结果")
    print(f"  GET  /api/v1/results/{{agent_id}}?run_id=xxx    查询结果")
    print(f"  GET  /api/v1/batch/{{run_id}}/status           批次状态")
    print(f"  GET  /api/v1/health                            健康检查")
    print(f"{'='*60}\n")

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

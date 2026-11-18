"""
沙箱报告解读API客户端
1. 从 MySQL 按文件哈希/文件名在 EXT_FIELD_ONE 中查找 XDR_DDAN_RESULT.ID（真实 bizId）
2. 用 bizId 调用异步解读接口（submit + 轮询 getResult）
"""
import json
import time
import requests
import urllib3
from typing import Any, Dict, Optional
from .base_client import BaseAPIClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SandboxAPIClient(BaseAPIClient):
    """沙箱报告解读API客户端"""

    SUBMIT_PATH = "/maxs/szr/llmJudge/submit"
    GET_RESULT_PATH = "/maxs/szr/llmJudge/getResult"

    STATUS_PENDING = 0
    STATUS_PROCESSING = 1
    STATUS_SUCCESS = 2
    STATUS_FAILED = 3
    STATUS_STOPPED = 4

    def __init__(self, config=None, auto_auth: bool = True):
        super().__init__(config, auto_auth)

    def _db_config(self) -> Dict[str, Any]:
        """沙箱报告数据库配置（从 config_api.yaml 的 database 段读取，不再硬编码）"""
        defaults = {
            "type": "postgresql",
            "host": "192.168.113.169",
            "port": 15432,
            "user": "root",
            "password": "maxs.PDG~2022",
            "dbname": "ssa",
            "table": "xdr_ddan_result",
            "id_column": "id",
            "search_column": "ext_field_one",
        }
        cfg = dict(defaults)
        if self.config is not None:
            user_cfg = getattr(self.config, "database_config", None)
            if user_cfg:
                cfg.update(user_cfg)
        return cfg

    def _connect_db(self):
        """根据配置中的 type 字段建立数据库连接（支持 mysql / postgresql）"""
        cfg = self._db_config()
        db_type = cfg.get("type", "postgresql").lower()
        try:
            if db_type == "mysql":
                import pymysql
                return pymysql.connect(
                    host=cfg["host"], port=int(cfg["port"]),
                    user=cfg["user"], password=cfg["password"],
                    database=cfg["dbname"], connect_timeout=5,
                    charset="utf8mb4",
                )
            else:
                import psycopg2
                return psycopg2.connect(
                    host=cfg["host"], port=int(cfg["port"]),
                    user=cfg["user"], password=cfg["password"],
                    dbname=cfg["dbname"], connect_timeout=5,
                )
        except ImportError:
            driver = "pymysql" if db_type == "mysql" else "psycopg2"
            print(f"  [错误] 未安装 {driver}，无法查询数据库")
            return None
        except Exception as e:
            print(f"  [数据库连接异常] {e}")
            return None

    def resolve_biz_id(self, file_hash_or_name: str) -> Optional[str]:
        """从沙箱结果表按文件哈希/文件名查找报告 ID

        查找逻辑：在 EXT_FIELD_ONE（沙箱报告 JSON）中模糊匹配
        文件哈希（SHA1/MD5/SHA256）或文件名，找到后返回 ID，未找到返回 None。
        """
        value = file_hash_or_name.strip()
        cfg = self._db_config()
        conn = self._connect_db()
        if conn is None:
            return None

        table = cfg["table"]
        id_col = cfg["id_column"]
        search_col = cfg["search_column"]
        db_type = cfg.get("type", "postgresql").lower()
        like_op = "LIKE" if db_type == "mysql" else "ILIKE"
        query = f"SELECT {id_col} FROM {table} WHERE {search_col} {like_op} %s LIMIT 1"
        try:
            cur = conn.cursor()
            cur.execute(query, (f"%{value}%",))
            row = cur.fetchone()
            conn.close()
            if row:
                return str(row[0])
        except Exception as e:
            print(f"  [数据库查找异常] {e}")
            try:
                conn.close()
            except Exception:
                pass
        return None

    def submit(self, biz_id: str, biz_type: int = 6, re_submit: bool = False) -> Dict[str, Any]:
        """提交沙箱报告解读任务"""
        url = f"{self.base_url}{self.SUBMIT_PATH}"
        payload = {
            "bizType": biz_type,
            "bizId": str(biz_id),
            "reSubmit": re_submit
        }
        try:
            resp = requests.post(
                url, headers=self.headers, json=payload,
                verify=False, timeout=30
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                return {"error": f"HTTP {resp.status_code}", "response": resp.text[:200]}
        except Exception as e:
            return {"error": str(e)}

    def get_result(self, biz_id: str, biz_type: int = 6) -> Optional[Dict[str, Any]]:
        """按业务ID查询解读结果"""
        url = f"{self.base_url}{self.GET_RESULT_PATH}"
        payload = {"bizType": biz_type, "bizId": str(biz_id)}
        try:
            resp = requests.post(
                url, headers=self.headers, json=payload,
                verify=False, timeout=30
            )
            if resp.status_code == 200:
                result = resp.json()
                if result.get("code") == 200:
                    return result.get("data")
            return None
        except Exception:
            return None

    def submit_and_wait(
        self,
        file_hash_or_name: str,
        biz_type: int = 6,
        poll_interval: int = 5,
        max_wait: int = 180
    ) -> Dict[str, Any]:
        """查找bizId → 提交解读任务 → 轮询等待结果

        Args:
            file_hash_or_name: 文件哈希（SHA1/MD5/SHA256）或文件名
            biz_type: 业务类型，沙箱分析报告传6
            poll_interval: 轮询间隔（秒）
            max_wait: 最大等待时间（秒）

        Returns:
            {"success": True, "result": "...", "biz_id": "...", ...}
            {"success": False, "error": "..."}
        """
        start_time = time.time()

        # 第一步：从数据库查找真实 bizId
        biz_id = self.resolve_biz_id(file_hash_or_name)
        if not biz_id:
            return {"success": False, "error": f"数据库中未找到文件 '{file_hash_or_name}' 对应的沙箱报告ID"}

        print(f"  [数据库查找] 文件 '{file_hash_or_name[:20]}...' → bizId={biz_id}")

        # 第二步：提交解读任务
        submit_resp = self.submit(biz_id, biz_type, re_submit=True)
        if "error" in submit_resp:
            return {"success": False, "error": f"提交失败: {submit_resp['error']}"}

        submit_code = submit_resp.get("code")
        if submit_code != 200:
            return {"success": False, "error": f"提交失败: {submit_resp.get('message', '未知错误')}"}

        print(f"  [提交成功] bizId={biz_id}，开始轮询...")

        # 第三步：轮询等待结果
        first_packet_time = None
        while True:
            elapsed = time.time() - start_time
            if elapsed > max_wait:
                return {"success": False, "error": f"轮询超时（{max_wait}秒）", "biz_id": biz_id}

            data = self.get_result(biz_id, biz_type)
            if data is None:
                time.sleep(poll_interval)
                continue

            # 首包时间：首次获取到有效记录的时间（系统已响应）
            if first_packet_time is None:
                first_packet_time = time.time() - start_time
                print(f"  [系统响应] 首包时间={first_packet_time:.1f}s, status={data.get('status')}")

            status = data.get("status")
            if status == self.STATUS_SUCCESS:
                result_text = data.get("result") or ""
                if not result_text.strip():
                    return {"success": False, "error": "解读成功但结果为空", "biz_id": biz_id}
                return {
                    "success": True,
                    "result": result_text,
                    "biz_id": biz_id,
                    "submit_time": data.get("submitTime"),
                    "finish_time": data.get("finishTime"),
                    "first_packet_time": first_packet_time,
                    "total_time": time.time() - start_time
                }
            elif status == self.STATUS_FAILED:
                fail_reason = data.get("result") or "解读失败"
                return {"success": False, "error": f"解读失败: {fail_reason}", "biz_id": biz_id}
            elif status == self.STATUS_STOPPED:
                return {"success": False, "error": "解读任务已停止", "biz_id": biz_id}
            elif status in (self.STATUS_PENDING, self.STATUS_PROCESSING):
                time.sleep(poll_interval)
            else:
                time.sleep(poll_interval)

    def get_sandbox_detail(self, file_hash_or_name: str) -> Dict[str, Any]:
        """从沙箱结果表 EXT_FIELD_ONE 获取沙箱原始报告（基准真值）

        查找逻辑：按文件哈希/文件名 → 找到 EXT_FIELD_ONE（JSON）→ 解析返回
        """
        biz_id = self.resolve_biz_id(file_hash_or_name)
        if not biz_id:
            return {"error": f"数据库中未找到文件 '{file_hash_or_name}'"}

        cfg = self._db_config()
        conn = self._connect_db()
        if conn is None:
            return {"error": "数据库连接失败"}

        table = cfg["table"]
        id_col = cfg["id_column"]
        search_col = cfg["search_column"]
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT {search_col} FROM {table} WHERE {id_col} = %s LIMIT 1", (int(biz_id),))
            row = cur.fetchone()
            conn.close()
            if not row or not row[0]:
                return {"error": "沙箱报告内容为空"}

            raw_json = row[0]
            try:
                biz_content = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            except Exception:
                biz_content = {"raw": raw_json}

            return {
                "biz_content": biz_content,
                "biz_id": biz_id
            }
        except Exception as e:
            return {"error": f"数据库查询异常: {e}"}

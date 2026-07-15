#!/bin/bash
# ============================================================
# 夜间自动化测试 - 批量审查报告
# 触发时间: 每工作日 08:30
# 说明: 调用 run_batch_audit.py，审查 ai_test_agent 生成的解读报告
# 依赖: 需先执行 run_ai_test_agent.sh（02:00任务）生成 raw_md
# ============================================================

# 代理设置：与终端环境保持一致，避免 AI 接口走代理导致失败
export no_proxy=localhost,127.0.0.1,llm.asiainfo-sec.com,::1
export NO_PROXY=localhost,127.0.0.1,llm.asiainfo-sec.com,::1

# 工作日检查（1-5=周一至周五，6-7=周六日）
DOW=$(date +%u)
if [ "$DOW" -gt 5 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [跳过] 周末不执行批量审查" >> /tmp/aixdr_nightly_skip.log
    exit 0
fi

# 项目配置
PROJECT_DIR="/Users/mengyuan/Documents/AIXDR_projects/AIXDR_auto_ai_test"
PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
DATE=$(date +%Y%m%d)
LOG_FILE="$PROJECT_DIR/logs/nightly_batch_audit_${DATE}.log"
START_TIME=$(date +%s)

cd "$PROJECT_DIR" || exit 1

echo "============================================================" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [开始] 批量审查报告 (run_batch_audit.py)" | tee -a "$LOG_FILE"
echo "============================================================" | tee -a "$LOG_FILE"

# 执行批量审查
PYTHONUNBUFFERED=1 "$PYTHON" run_batch_audit.py >> "$LOG_FILE" 2>&1
EXIT_CODE=$?

END_TIME=$(date +%s)
DURATION_SEC=$((END_TIME - START_TIME))
DURATION="${DURATION_SEC}s"

echo "------------------------------------------------------------" | tee -a "$LOG_FILE"
if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [完成] 批量审查成功 (exit=0, 耗时${DURATION})" | tee -a "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [失败] 批量审查异常 (exit=$EXIT_CODE, 耗时${DURATION})" | tee -a "$LOG_FILE"
fi
echo "============================================================" | tee -a "$LOG_FILE"

# 飞书通知
"$PYTHON" -c "
import sys; sys.path.insert(0, '$PROJECT_DIR')
from core.notify.feishu_notify import send_test_result_notify
send_test_result_notify('批量审查报告', $EXIT_CODE, '$LOG_FILE', '$DURATION')
" 2>/dev/null

exit 0

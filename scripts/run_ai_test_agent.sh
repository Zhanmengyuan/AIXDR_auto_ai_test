#!/bin/bash
# ============================================================
# 夜间自动化测试 - 全模块解读 + 批量审查（串行）
# 触发时间: 每工作日 02:00
# 说明: run_ai_test_agent.py 内部已包含审查逻辑，解读完自动审查
# ============================================================

# 代理设置：与终端环境保持一致，避免 AI 接口走代理导致失败
export no_proxy=localhost,127.0.0.1,llm.asiainfo-sec.com,::1
export NO_PROXY=localhost,127.0.0.1,llm.asiainfo-sec.com,::1

# 工作日检查已移除，crontab 中直接控制执行时间

# 项目配置
PROJECT_DIR="/Users/mengyuan/Documents/AIXDR_projects/AIXDR_auto_ai_test"
PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
DATE=$(date +%Y%m%d)
AGENT_LOG="$PROJECT_DIR/logs/nightly_ai_test_agent_${DATE}.log"
START_TIME=$(date +%s)

cd "$PROJECT_DIR" || exit 1

echo "============================================================" | tee -a "$AGENT_LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S') [开始] 全模块解读+审查 (run_ai_test_agent.py --mode all)" | tee -a "$AGENT_LOG"
echo "============================================================" | tee -a "$AGENT_LOG"

# 执行全模块解读（内部自动串行审查）
PYTHONUNBUFFERED=1 "$PYTHON" run_ai_test_agent.py --mode all >> "$AGENT_LOG" 2>&1
EXIT_CODE=$?

END_TIME=$(date +%s)
DURATION_SEC=$((END_TIME - START_TIME))
DURATION_H=$((DURATION_SEC / 3600))
DURATION_M=$(((DURATION_SEC % 3600) / 60))
DURATION_S=$((DURATION_SEC % 60))
if [ $DURATION_H -gt 0 ]; then
    DURATION="${DURATION_H}h${DURATION_M}m${DURATION_S}s"
elif [ $DURATION_M -gt 0 ]; then
    DURATION="${DURATION_M}m${DURATION_S}s"
else
    DURATION="${DURATION_S}s"
fi

echo "------------------------------------------------------------" | tee -a "$AGENT_LOG"
if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [完成] 全流程成功 (exit=0, 耗时${DURATION})" | tee -a "$AGENT_LOG"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [失败] 全流程异常 (exit=$EXIT_CODE, 耗时${DURATION})" | tee -a "$AGENT_LOG"
fi
echo "============================================================" | tee -a "$AGENT_LOG"

# 飞书通知
"$PYTHON" -c "
import sys; sys.path.insert(0, '$PROJECT_DIR')
from core.notify.feishu_notify import send_feishu_message
status = '✅ 成功' if $EXIT_CODE == 0 else '❌ 失败'
lines = [
    '📋 全模块解读 + 批量审查: ' + status,
    '⏱️ 总耗时: $DURATION',
    '📁 日志: $AGENT_LOG',
]
send_feishu_message('AIXDR自动化解读测试报告', lines)
" 2>/dev/null

exit 0

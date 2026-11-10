#!/bin/bash
# ============================================================
# 自动化测试 - 支持传参执行指定模块或全模块
# 用法: run_ai_test_agent.sh [all|asset|vuln|alarm|event|sandbox]
#   默认: all（全模块）
# 说明: run_ai_test_agent.py 内部已包含审查逻辑，解读完自动审查
# ============================================================

# 代理设置：与终端环境保持一致，避免 AI 接口走代理导致失败
export no_proxy=localhost,127.0.0.1,llm.asiainfo-sec.com,::1
export NO_PROXY=localhost,127.0.0.1,llm.asiainfo-sec.com,::1

# 项目配置
PROJECT_DIR="/Users/mengyuan/Documents/AIXDR_projects/AIXDR_auto_ai_test"
PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
DATE=$(date +%Y%m%d)
START_TIME=$(date +%s)

# 模块参数（默认 all）
MODULE="${1:-all}"

# 日志文件名：全模块保持原名，指定模块加模块名区分
if [ "$MODULE" = "all" ]; then
    AGENT_LOG="$PROJECT_DIR/logs/nightly_ai_test_agent_${DATE}.log"
else
    AGENT_LOG="$PROJECT_DIR/logs/nightly_ai_test_agent_${MODULE}_${DATE}.log"
fi

cd "$PROJECT_DIR" || exit 1

echo "============================================================" | tee -a "$AGENT_LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S') [开始] 模块=$MODULE" | tee -a "$AGENT_LOG"
echo "============================================================" | tee -a "$AGENT_LOG"

# 执行测试（全模块用 --mode all，指定模块用 --module）
if [ "$MODULE" = "all" ]; then
    PYTHONUNBUFFERED=1 "$PYTHON" run_ai_test_agent.py --mode all >> "$AGENT_LOG" 2>&1
else
    PYTHONUNBUFFERED=1 "$PYTHON" run_ai_test_agent.py --module "$MODULE" >> "$AGENT_LOG" 2>&1
fi
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
    echo "$(date '+%Y-%m-%d %H:%M:%S') [完成] 模块=$MODULE 成功 (exit=0, 耗时${DURATION})" | tee -a "$AGENT_LOG"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [失败] 模块=$MODULE 异常 (exit=$EXIT_CODE, 耗时${DURATION})" | tee -a "$AGENT_LOG"
fi
echo "============================================================" | tee -a "$AGENT_LOG"

# 飞书通知
"$PYTHON" -c "
import sys; sys.path.insert(0, '$PROJECT_DIR')
from core.notify.feishu_notify import send_feishu_message
status = '✅ 成功' if $EXIT_CODE == 0 else '❌ 失败'
lines = [
    '📋 解读测试(模块=$MODULE): ' + status,
    '⏱️ 总耗时: $DURATION',
    '📁 日志: $AGENT_LOG',
]
send_feishu_message('AIXDR自动化解读测试报告', lines)
" 2>/dev/null

exit 0

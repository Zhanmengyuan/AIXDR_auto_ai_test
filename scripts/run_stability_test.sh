#!/bin/bash
# ============================================================
# 夜间自动化测试 - 稳定性测试
# 触发时间: 每工作日 05:30
# 说明: 调用 run_stability_test.py all，测试告警/事件/漏洞核心结论稳定性
# 独立: 不依赖其他模块，每个测试ID会解读两次
# ============================================================

# 代理设置：与终端环境保持一致，避免 AI 接口走代理导致失败
export no_proxy=localhost,127.0.0.1,llm.asiainfo-sec.com,::1
export NO_PROXY=localhost,127.0.0.1,llm.asiainfo-sec.com,::1

# 工作日检查已移除，crontab 中直接控制执行时间

# 项目配置
PROJECT_DIR="/Users/mengyuan/Documents/AIXDR_projects/AIXDR_auto_ai_test"
PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
DATE=$(date +%Y%m%d)
LOG_FILE="$PROJECT_DIR/logs/nightly_stability_test_${DATE}.log"
START_TIME=$(date +%s)

cd "$PROJECT_DIR" || exit 1

echo "============================================================" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [开始] 稳定性测试 (run_stability_test.py all)" | tee -a "$LOG_FILE"
echo "============================================================" | tee -a "$LOG_FILE"

# 执行全模块稳定性测试
PYTHONUNBUFFERED=1 "$PYTHON" run_stability_test.py all >> "$LOG_FILE" 2>&1
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

echo "------------------------------------------------------------" | tee -a "$LOG_FILE"
if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [完成] 稳定性测试成功 (exit=0, 耗时${DURATION})" | tee -a "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [失败] 稳定性测试异常 (exit=$EXIT_CODE, 耗时${DURATION})" | tee -a "$LOG_FILE"
fi
echo "============================================================" | tee -a "$LOG_FILE"

# 飞书通知
"$PYTHON" -c "
import sys; sys.path.insert(0, '$PROJECT_DIR')
from core.notify.feishu_notify import send_feishu_message
status = '✅ 成功' if $EXIT_CODE == 0 else '❌ 失败'
lines = [
    '📋 稳定性测试: ' + status,
    '⏱️ 总耗时: $DURATION',
    '📁 日志: $LOG_FILE',
]
send_feishu_message('AIXDR自动化解读稳定性报告', lines)
" 2>/dev/null

exit 0

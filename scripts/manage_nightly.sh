#!/bin/bash
# ============================================================
# 夜间自动化测试 crontab 任务管理脚本
#
# 用法:
#   ./manage_nightly.sh install    # 写入 crontab 定时任务（保留其他已有条目）
#   ./manage_nightly.sh status     # 查看 crontab 中的 AIXDR 任务状态
#   ./manage_nightly.sh test <名>  # 立即手动测试某个任务
#                                  #   名: ai_test_agent | batch_audit | stability_test
#   ./manage_nightly.sh logs <名>  # 查看某个任务的最新日志
#   ./manage_nightly.sh uninstall  # 从 crontab 移除 AIXDR 任务（保留其他条目）
#
# 定时计划（仅工作日周一至周五，crontab 1-5 字段 + 脚本内双保险检查）:
#   21:00  ai_test_agent   全模块解读测试

#   2:00  stability_test  稳定性测试

#   5:00  batch_audit     批量审查报告# ============================================================

PROJECT_DIR="/Users/mengyuan/Documents/AIXDR_projects/AIXDR_auto_ai_test"

# 标记行：crontab 中 AIXDR 块的起止标记，确保只增删自己的条目
MARKER_BEGIN="# >>> AIXDR NIGHTLY TEST BEGIN >>>"
MARKER_END="# <<< AIXDR NIGHTLY TEST END <<<"

# 三个任务定义：名称|脚本|cron时间|说明|预估耗时
TASKS=(
    "ai_test_agent|run_ai_test_agent.sh|30 20 * * 1-5|全模块解读+批量审查(串行)|约2.8h→23:20完成"
    "stability_test|run_stability_test.sh|30 3 * * 1-5|稳定性测试|约2.3h(60样本×2)→05:50完成"
)

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

get_field() { echo "$1" | cut -d'|' -f"$2"; }

# ---- 生成 AIXDR crontab 块 ----
build_cron_block() {
    echo "$MARKER_BEGIN"
    echo "# AIXDR 夜间自动化测试（仅工作日周一至周五）"
    echo "# 修改请使用: $PROJECT_DIR/scripts/manage_nightly.sh <命令>"
    echo "#"
    for task in "${TASKS[@]}"; do
        name=$(get_field "$task" 1)
        script=$(get_field "$task" 2)
        cron_time=$(get_field "$task" 3)
        desc=$(get_field "$task" 4)
        # 从 cron_time 提取时分用于注释显示（补零）
        minute=$(echo "$cron_time" | awk '{print $1}')
        hour=$(echo "$cron_time" | awk '{print $2}')
        printf -v minute_padded "%02d" "$minute"
        printf -v hour_padded "%02d" "$hour"
        echo "# ${hour_padded}:${minute_padded} ${name} - ${desc}"
        echo "${cron_time} ${PROJECT_DIR}/scripts/${script}"
    done
    echo "$MARKER_END"
}

# ---- install: 写入 crontab（保留其他已有条目）----
do_install() {
    echo "=== 安装 AIXDR crontab 定时任务 ==="

    # 获取现有 crontab（可能为空）
    existing=$(crontab -l 2>/dev/null || echo "")

    # 如果已有 AIXDR 块，先移除旧的
    if echo "$existing" | grep -q "$MARKER_BEGIN"; then
        existing=$(echo "$existing" | sed "/$MARKER_BEGIN/,/$MARKER_END/d")
        warn "检测到已有 AIXDR 块，已移除旧配置"
    fi

    # 拼接新块
    new_block=$(build_cron_block)
    if [ -n "$existing" ]; then
        # 保留其他条目，末尾追加 AIXDR 块
        printf "%s\n\n%s\n" "$existing" "$new_block" | crontab -
    else
        printf "%s\n" "$new_block" | crontab -
    fi

    for task in "${TASKS[@]}"; do
        name=$(get_field "$task" 1)
        cron_time=$(get_field "$task" 3)
        desc=$(get_field "$task" 4)
        est_time=$(get_field "$task" 5)
        info "$name: $cron_time ($desc, $est_time)"
    done

    echo ""
    echo "安装完成。查看状态: $0 status"
}

# ---- status ----
do_status() {
    echo "=== AIXDR crontab 任务状态 ==="
    printf "%-18s %-18s %-22s %-20s\n" "任务名称" "cron时间" "说明" "预估耗时"
    printf "%-18s %-18s %-22s %-20s\n" "------------------" "------------------" "----------------------" "--------------------"

    current=$(crontab -l 2>/dev/null || echo "")
    if ! echo "$current" | grep -q "$MARKER_BEGIN"; then
        warn "crontab 中未找到 AIXDR 任务（请先执行 install）"
        return
    fi

    for task in "${TASKS[@]}"; do
        name=$(get_field "$task" 1)
        script=$(get_field "$task" 2)
        cron_time=$(get_field "$task" 3)
        desc=$(get_field "$task" 4)
        est_time=$(get_field "$task" 5)

        # 检查 crontab 中是否有对应条目
        if echo "$current" | grep -q "$script"; then
            status="$cron_time"
        else
            status="未安装"
        fi
        printf "%-18s %-18s %-22s %-20s\n" "$name" "$status" "$desc" "$est_time"
    done

    echo ""
    echo "crontab 完整内容（AIXDR 部分）："
    echo "$current" | sed -n "/$MARKER_BEGIN/,/$MARKER_END/p" | head -20
}

# ---- test <name> ----
do_test() {
    local target_name=$1
    local found=""

    for task in "${TASKS[@]}"; do
        name=$(get_field "$task" 1)
        if [ "$name" = "$target_name" ]; then
            found="$task"
            break
        fi
    done

    if [ -z "$found" ]; then
        error "未知任务名: $target_name"
        echo "可用任务: ai_test_agent | batch_audit | stability_test"
        exit 1
    fi

    script=$(get_field "$found" 2)
    script_path="$PROJECT_DIR/scripts/$script"

    echo "=== 立即手动执行: $target_name ==="
    echo "脚本: $script_path"
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "------------------------------------------------------------"
    bash "$script_path"
}

# ---- logs <name> ----
do_logs() {
    local name=$1
    today=$(date +%Y%m%d)
    log_file="$PROJECT_DIR/logs/nightly_${name}_${today}.log"

    if [ -f "$log_file" ]; then
        echo "=== 日志: $log_file ==="
        tail -80 "$log_file"
    else
        warn "今日无日志: $log_file"
        echo "近期日志文件:"
        ls -lt "$PROJECT_DIR"/logs/nightly_${name}_* 2>/dev/null | head -3
    fi
}

# ---- uninstall ----
do_uninstall() {
    echo "=== 从 crontab 移除 AIXDR 任务 ==="

    existing=$(crontab -l 2>/dev/null || echo "")
    if ! echo "$existing" | grep -q "$MARKER_BEGIN"; then
        warn "crontab 中未找到 AIXDR 任务"
        return
    fi

    # 移除 AIXDR 块，保留其他条目
    remaining=$(echo "$existing" | sed "/$MARKER_BEGIN/,/$MARKER_END/d")

    if [ -n "$(echo "$remaining" | tr -d '[:space:]')" ]; then
        echo "$remaining" | crontab -
        info "已移除 AIXDR 任务，保留其他 crontab 条目"
    else
        crontab -r 2>/dev/null
        info "已移除 AIXDR 任务（crontab 已清空）"
    fi
}

# ---- 主入口 ----
case "$1" in
    install)   do_install ;;
    status)    do_status ;;
    test)      do_test "$2" ;;
    logs)      do_logs "$2" ;;
    uninstall) do_uninstall ;;
    *)
        echo "用法: $0 {install|status|test|logs|uninstall}"
        echo ""
        echo "命令说明:"
        echo "  install        写入 crontab 定时任务（保留其他已有条目）"
        echo "  status         查看 crontab 中的 AIXDR 任务状态"
        echo "  test <名>      立即手动测试某个任务"
        echo "     名: ai_test_agent | batch_audit | stability_test"
        echo "  logs <名>      查看某个任务的今日日志"
        echo "  uninstall      从 crontab 移除 AIXDR 任务（保留其他条目）"
        echo ""
        echo "定时计划（仅工作日周一至周五）:"
        echo "  20:30  ai_test_agent   全模块解读+审查(串行)  约2.8h  →23:20完成"
        echo "  03:30  stability_test  稳定性测试             约2.3h  →05:50完成"
        ;;
esac

#!/bin/bash

# 严格模式设置
set -euo pipefail
[[ $- != *i* ]] && cd "$(dirname "$0")"

#################################
CHAIN="BLACKLIST"          # 黑名单链名称（根据需要修改）
DPORTS="80,443"            # 监控的端口（根据需要修改）
#################################
PROTOCOL="tcp"             # 协议类型（tcp/udp）
BLACKLIST_FILE="./blacklist.txt"  # 黑名单IP文件
LOG_FILE="./blacklist.log"        # 日志文件
BACKUP_DIR="./backups"            # 备份目录

# 初始化变量
IP_LIST=()

# 日志记录函数
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE" >&2
}

# IP地址验证
validate_ip() {
    local ip=$1
    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] || {
        log "ERROR" "Invalid IP format: $ip"
        return 1
    }
}

# 协议验证
validate_protocol() {
    [[ "$PROTOCOL" =~ ^(tcp|udp)$ ]] || {
        log "ERROR" "Invalid protocol '$PROTOCOL'"
        exit 1
    }
}

# 检查链是否存在
chain_exists() {
    iptables -w -t filter -nL "$CHAIN" >/dev/null 2>&1
}

# 加载黑名单IP
load_blacklist() {
    IP_LIST=()
    if [[ -f "$BLACKLIST_FILE" ]]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            ip=$(echo "$ip" | xargs)
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            if validate_ip "$ip"; then
                IP_LIST+=("$ip")
                log "INFO" "Loaded blacklist IP: $ip"
            fi
        done < "$BLACKLIST_FILE"
    else
        log "WARN" "Blacklist file not found: $BLACKLIST_FILE"
    fi
}

# 备份规则
backup_rules() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$BACKUP_DIR" || {
        log "ERROR" "Cannot create backup directory"
        exit 1
    }
    iptables-save > "${BACKUP_DIR}/iptables_${timestamp}.bak" && {
        log "INFO" "Rules backed up to ${BACKUP_DIR}/iptables_${timestamp}.bak"
    }
}

# 创建黑名单规则
create_chain() {
    validate_protocol
    
    # 创建链（如果不存在）
    if ! chain_exists; then
        iptables -w -t filter -N "$CHAIN" || {
            log "ERROR" "Failed to create chain $CHAIN"
            exit 1
        }
        log "INFO" "Created chain: $CHAIN"
    fi

    # 清空现有规则（保留链结构）
    iptables -w -t filter -F "$CHAIN"

    # 添加黑名单规则（插入到链顶部）
    for ip in "${IP_LIST[@]}"; do
        iptables -w -t filter -I "$CHAIN" -s "$ip" -j DROP && {
            log "DEBUG" "Blocked IP: $ip"
        }
    done

    # 默认放行规则（必须添加！）
    iptables -w -t filter -A "$CHAIN" -j RETURN && {
        log "DEBUG" "Added default RETURN rule"
    }

    # 挂载到INPUT链
    iptables -w -t filter -I INPUT -p "$PROTOCOL" -m multiport --dports "$DPORTS" -j "$CHAIN" && {
        log "INFO" "Mounted $CHAIN to INPUT chain (Ports: $DPORTS)"
    }
}

# 清理规则
cleanup_chain() {
    # 从INPUT链移除引用
    while iptables -w -t filter -D INPUT -p "$PROTOCOL" -m multiport --dports "$DPORTS" -j "$CHAIN" 2>/dev/null; do
        sleep 0.1
    done

    # 清空并删除链
    iptables -w -t filter -F "$CHAIN" 2>/dev/null || true
    iptables -w -t filter -X "$CHAIN" 2>/dev/null || true
    log "INFO" "Cleaned up chain $CHAIN"
}

# 显示状态
show_status() {
    echo -e "\n当前黑名单状态:"
    echo "===================="
    echo "链 [$CHAIN] 状态:"
    
    if chain_exists; then
        iptables -nL "$CHAIN" --line-numbers
        local blocked_count=$(iptables -nL "$CHAIN" | grep -c DROP)
        echo -e "\n已封禁IP数量: $blocked_count"
    else
        echo "链未激活"
    fi
    
    echo -e "\nINPUT链引用:"
    iptables -nL INPUT | grep "$CHAIN"
    
    echo "===================="
    echo -e "日志文件: $LOG_FILE\n"
}

# 主程序
main() {
    case "${1:-help}" in
        "start")
            log "INFO" "==== 启动黑名单服务 ===="
            backup_rules
            load_blacklist
            create_chain
            show_status
            ;;
        "stop")
            log "INFO" "==== 停止黑名单服务 ===="
            backup_rules
            cleanup_chain
            ;;
        "reload")
            log "INFO" "==== 重新加载黑名单 ===="
            backup_rules
            load_blacklist
            create_chain
            show_status
            ;;
        "status")
            show_status
            ;;
        *)
            echo -e "黑名单防火墙管理脚本\n用法: $0 [命令]"
            echo "命令:"
            echo "  start    启动服务"
            echo "  stop     停止服务"
            echo "  reload   重新加载黑名单"
            echo "  status   查看状态"
            echo "  help     显示帮助"
            ;;
    esac
}

main "$@"

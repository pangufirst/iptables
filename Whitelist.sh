#!/bin/bash

# 严格模式设置
set -euo pipefail

# 自动切换到脚本所在目录
[[ $- != *i* ]] && cd "$(dirname "$0")"

### 配置参数
CHAIN="CUSTOM_FIREWALL"
DPORTS="9200,9201,5900:5950"  # 支持: 单个端口, 逗号分隔列表, 端口范围,iptables有端口数量上限，每个50个端口
PROTOCOLS=("tcp" "udp")  # 支持多协议
####################

# 初始化
IP_LIST=()
BACKUP_DIR="./backups"
IP_FILE="./ip.txt"
LOG_FILE="./firewall.log"

# 日志函数
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE" >&2
}

# IP验证
validate_ip() {
    local ip=$1
    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] || {
        log "ERROR" "无效IP格式: $ip"
        return 1
    }
}

# 协议验证
validate_protocols() {
    for proto in "${PROTOCOLS[@]}"; do
        [[ $proto =~ ^(tcp|udp)$ ]] || {
            log "ERROR" "无效协议 '$proto'，必须是tcp或udp"
            return 1
        }
    done
}

# 检查链是否存在
chain_exists() {
    iptables -w -t filter -nL "$CHAIN" >/dev/null 2>&1
}

# 加载IP列表
load_ip_list() {
    [[ -f "$IP_FILE" ]] || {
        log "WARN" "IP列表文件不存在: $IP_FILE"
        return
    }
    
    [[ -s "$IP_FILE" ]] || {
        log "WARN" "IP列表文件为空: $IP_FILE"
        return
    }

    log "INFO" "正在加载IP列表"
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        ip=$(echo "$ip" | xargs)
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        
        if validate_ip "$ip"; then
            IP_LIST+=("$ip")
            log "DEBUG" "添加IP: $ip"
        fi
    done < <(sort -u "$IP_FILE")
    
    log "INFO" "已加载 ${#IP_LIST[@]} 个有效IP"
}

# 备份规则
backup_rules() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$BACKUP_DIR" || {
        log "ERROR" "无法创建备份目录"
        exit 1
    }
    
    iptables-save > "${BACKUP_DIR}/iptables_${timestamp}.bak" || {
        log "ERROR" "备份失败"
        exit 1
    }
    
    log "INFO" "规则已备份到: ${BACKUP_DIR}/iptables_${timestamp}.bak"
}

# 创建规则链
create_chain() {
    validate_protocols
    
    if chain_exists; then
        log "WARN" "链 $CHAIN 已存在!"
        read -p "是否覆盖现有规则? [y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
        cleanup_chain
    fi

    iptables -w -t filter -N "$CHAIN" || {
        log "ERROR" "创建链失败"
        exit 1
    }
    log "INFO" "已创建链: $CHAIN"

    # 基础规则
    iptables -w -t filter -A "$CHAIN" -m addrtype --src-type LOCAL -j ACCEPT
    log "DEBUG" "添加本地访问规则"

    # IP白名单
    for ip in "${IP_LIST[@]}"; do
        iptables -w -t filter -A "$CHAIN" -s "$ip" -j ACCEPT
    done
    (( ${#IP_LIST[@]} > 0 )) && log "DEBUG" "添加 ${#IP_LIST[@]} 条IP规则"

    # 默认拒绝
    if (( ${#IP_LIST[@]} > 0 )); then
        iptables -w -t filter -A "$CHAIN" -j REJECT
        log "DEBUG" "添加默认拒绝规则"
    fi

    # 挂载到INPUT链
    for proto in "${PROTOCOLS[@]}"; do
        iptables -w -t filter -I INPUT -p "$proto" -m multiport --dports "$DPORTS" -j "$CHAIN"
        log "INFO" "已挂载 $proto/$DPORTS 到 $CHAIN"
    done
}

# 清理规则链
cleanup_chain() {
    log "INFO" "开始清理链 $CHAIN"
    
    # 移除INPUT引用
    for proto in "${PROTOCOLS[@]}"; do
        local removed=0
        while iptables -w -t filter -D INPUT -p "$proto" -m multiport --dports "$DPORTS" -j "$CHAIN" 2>/dev/null; do
            sleep 0.1
            ((removed++))
        done
        (( removed > 0 )) && log "INFO" "移除 $removed 条 $proto 引用"
    done

    # 清空并删除链
    iptables -w -t filter -F "$CHAIN" 2>/dev/null && log "DEBUG" "清空链 $CHAIN"
    iptables -w -t filter -X "$CHAIN" 2>/dev/null && log "INFO" "删除链 $CHAIN" ||
        log "WARN" "链 $CHAIN 不存在"
}

# 显示状态
show_status() {
    echo -e "\n当前防火墙状态:"
    echo "===================="
    echo "链 $CHAIN 状态:"
    
    if chain_exists; then
        iptables -nL "$CHAIN" --line-numbers
        local rule_count=$(iptables -nL "$CHAIN" | wc -l)
        echo -e "\n规则总数: $((rule_count-2))"
    else
        echo "链不存在"
    fi
    
    echo -e "\nINPUT链引用:"
    for proto in "${PROTOCOLS[@]}"; do
        echo -n "$proto 引用: "
        iptables -nL INPUT | grep -cE "$CHAIN.*$proto" || echo 0
    done
    
    echo -e "\n连接统计:"
    for proto in "${PROTOCOLS[@]}"; do
        ss -uln 2>/dev/null | grep -E "$(echo "$DPORTS" | tr ',' '|')" | grep -i "$proto" || true
    done
    
    echo "===================="
    echo -e "日志文件: $LOG_FILE\n"
}

# 显示帮助
show_help() {
    cat <<EOF
防火墙管理脚本 (支持TCP/UDP)

用法: $0 [命令]

命令:
  apply     应用规则 (备份+清理+创建)
  clean     清理规则 (备份+清理)
  backup    仅备份规则
  status    查看状态
  help      显示帮助

配置:
  IP列表:   $IP_FILE
  协议:     ${PROTOCOLS[@]}
  端口:     $DPORTS
EOF
}

# 主程序
main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log "INFO" "启动命令: $0 $*"
    load_ip_list
    
    case "${1:-help}" in
        apply)
            log "INFO" "开始应用规则"
            backup_rules
            create_chain
            log "INFO" "规则应用完成"
            show_status
            ;;
        clean)
            log "INFO" "开始清理规则"
            backup_rules
            cleanup_chain
            log "INFO" "清理完成"
            show_status
            ;;
        backup)
            backup_rules
            ;;
        status)
            show_status
            ;;
        help|*)
            show_help
            ;;
    esac
    
    log "INFO" "脚本执行完成"
}

main "$@"

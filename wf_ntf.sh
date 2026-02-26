#!/bin/bash

# NFTables 防火墙 + 端口转发 一体化管理脚本
# 支持白名单开关、端口转发（TCP+UDP默认）、白名单保护转发端口

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# 配置文件
WHITELIST_FILE="/etc/nftables_whitelist.txt"
FORWARD_FILE="/etc/port_forward_nft.conf"
WHITELIST_ENABLED_FILE="/etc/nftables_whitelist_enabled"

# 表名
NFT_TABLE="unified"

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 请使用root权限运行${NC}"
    exit 1
fi

# 检查nftables
check_nftables() {
    if ! command -v nft &> /dev/null; then
        echo -e "${RED}✗ nftables 未安装${NC}"
        echo "请先安装: apt-get install nftables"
        exit 1
    fi
}

# 初始化配置文件
init_files() {
    [ ! -f "$WHITELIST_FILE" ] && touch "$WHITELIST_FILE"
    [ ! -f "$FORWARD_FILE" ] && touch "$FORWARD_FILE"
    # 默认白名单启用
    [ ! -f "$WHITELIST_ENABLED_FILE" ] && echo "1" > "$WHITELIST_ENABLED_FILE"
}

# 获取白名单开关状态
is_whitelist_enabled() {
    [ -f "$WHITELIST_ENABLED_FILE" ] && [ "$(cat $WHITELIST_ENABLED_FILE)" = "1" ]
}

# 获取SSH IP
get_current_ssh_ip() {
    if [ -n "$SSH_CONNECTION" ]; then
        echo "$SSH_CONNECTION" | awk '{print $1}'
    elif [ -n "$SSH_CLIENT" ]; then
        echo "$SSH_CLIENT" | awk '{print $1}'
    fi
}

# 加载白名单
load_whitelist() {
    [ -f "$WHITELIST_FILE" ] && grep -v '^#' "$WHITELIST_FILE" | grep -v '^$' || true
}

# 添加IP到白名单
add_to_whitelist() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9./]+$ ]] && [[ ! "$ip" =~ ^[0-9a-fA-F:/]+$ ]]; then
        echo -e "${RED}错误: IP格式无效${NC}"
        return 1
    fi
    if grep -qx "$ip" "$WHITELIST_FILE" 2>/dev/null; then
        echo -e "${YELLOW}IP已存在${NC}"
        return 1
    fi
    echo "$ip" >> "$WHITELIST_FILE"
    echo -e "${GREEN}✓ 已添加: $ip${NC}"
}

# 删除白名单IP
remove_from_whitelist() {
    local ip="$1"
    if ! grep -qx "$ip" "$WHITELIST_FILE" 2>/dev/null; then
        echo -e "${RED}IP不存在${NC}"
        return 1
    fi
    grep -vx "$ip" "$WHITELIST_FILE" > "${WHITELIST_FILE}.tmp"
    mv "${WHITELIST_FILE}.tmp" "$WHITELIST_FILE"
    echo -e "${GREEN}✓ 已删除: $ip${NC}"
}

# 显示白名单
show_whitelist() {
    local status
    if is_whitelist_enabled; then
        status="${GREEN}[已启用]${NC}"
    else
        status="${RED}[已关闭]${NC}"
    fi
    echo -e "${BLUE}当前白名单 $status${NC}"
    echo "=========================================="
    if [ ! -s "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}(白名单为空)${NC}"
    else
        local count=1
        while IFS= read -r line; do
            echo -e "${GREEN}[$count]${NC} $line"
            ((count++))
        done < <(load_whitelist)
    fi
    echo "=========================================="
}

# 应用完整规则
apply_all_rules() {
    echo -e "${YELLOW}正在应用防火墙和转发规则...${NC}"
    
    # 清理所有旧表
    nft delete table inet filter 2>/dev/null || true
    nft delete table inet whitelist_filter 2>/dev/null || true
    nft delete table inet port_forward 2>/dev/null || true
    nft delete table inet unified_filter 2>/dev/null || true
    nft delete table inet unified_nat 2>/dev/null || true
    nft delete table inet $NFT_TABLE 2>/dev/null || true
    
    local temp_rules="/tmp/nftables_unified_$$.conf"
    
    if is_whitelist_enabled; then
        # 白名单启用模式：input/forward 默认 drop
        cat > "$temp_rules" << 'RULESET'
table inet unified {
    set allowed_ips {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set allowed_ips_v6 {
        type ipv6_addr
        flags interval
        auto-merge
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
    chain output_nat {
        type nat hook output priority -100; policy accept;
    }
    chain input {
        type filter hook input priority filter; policy drop;
        
        # 本地回环
        iif lo accept
        
        # ICMPv6 必须放行
        ip6 nexthdr icmpv6 accept
        
        # 白名单IP：无条件放行（包括新建连接）
        ip saddr @allowed_ips accept
        ip6 saddr @allowed_ips_v6 accept
        
        # 非白名单IP：只允许已建立连接的回包（VPS主动外出后的响应）
        # new/invalid 状态的包直接 drop
        ct state new,invalid drop
        ct state established,related accept
        
        drop
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        
        # ICMPv6 必须放行（IPv6邻居发现等）
        ip6 nexthdr icmpv6 accept
        
        # 目标服务器返回给VPS的回包（masquerade后源IP是目标服务器，不在白名单）
        # 必须严格限定：只放行已建立连接的回包，且该连接是由DNAT触发的
        ct status dnat ct state established,related accept
        
        # 白名单IP：允许新建连接及后续包
        ip saddr @allowed_ips accept
        ip6 saddr @allowed_ips_v6 accept
        
        drop
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
RULESET
    else
        # 白名单关闭模式：input/forward 全放行，仅做转发NAT
        cat > "$temp_rules" << 'RULESET'
table inet unified {
    set allowed_ips {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set allowed_ips_v6 {
        type ipv6_addr
        flags interval
        auto-merge
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
    chain output_nat {
        type nat hook output priority -100; policy accept;
    }
    chain input {
        type filter hook input priority filter; policy accept;
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
RULESET
    fi

    if ! nft -f "$temp_rules" 2>&1; then
        echo -e "${RED}✗ 规则应用失败${NC}"
        rm -f "$temp_rules"
        return 1
    fi
    
    # 添加白名单IP到集合（即使白名单关闭也加载，方便随时切换）
    local has_whitelist=false
    while IFS= read -r ip; do
        has_whitelist=true
        if [[ "$ip" =~ .*:.* ]]; then
            nft add element inet $NFT_TABLE allowed_ips_v6 { "$ip" } 2>/dev/null
        else
            nft add element inet $NFT_TABLE allowed_ips { "$ip" } 2>/dev/null
        fi
    done < <(load_whitelist)
    
    if is_whitelist_enabled && [ "$has_whitelist" = false ]; then
        echo -e "${RED}警告: 白名单已启用但为空，所有访问将被拒绝！${NC}"
    fi
    
    # 重新加载端口转发规则（统一 TCP+UDP）
    if [ -s "$FORWARD_FILE" ]; then
        while IFS='|' read -r lport tip tport; do
            add_forward_rules_internal "tcp" "$lport" "$tip" "$tport"
            add_forward_rules_internal "udp" "$lport" "$tip" "$tport"
        done < "$FORWARD_FILE"
    fi
    
    # 保存持久化配置
    mkdir -p /etc/nftables.d
    nft list table inet $NFT_TABLE > /etc/nftables.d/unified.nft
    
    if [ -f /etc/nftables.conf ]; then
        if ! grep -q "include \"/etc/nftables.d/unified.nft\"" /etc/nftables.conf; then
            echo 'include "/etc/nftables.d/unified.nft"' >> /etc/nftables.conf
        fi
    else
        echo 'include "/etc/nftables.d/unified.nft"' > /etc/nftables.conf
    fi
    
    systemctl enable nftables 2>/dev/null || true
    
    rm -f "$temp_rules"

    if is_whitelist_enabled; then
        echo -e "${GREEN}✓ 规则已应用 - 白名单模式${GREEN}[启用]${GREEN}，转发TCP+UDP均已生效${NC}"
    else
        echo -e "${GREEN}✓ 规则已应用 - 白名单模式${RED}[关闭]${GREEN}，转发TCP+UDP均已生效${NC}"
    fi
}

# 内部添加转发规则 (NAT逻辑)
add_forward_rules_internal() {
    local proto=$1
    local lport=$2
    local tip=$3
    local tport=$4
    
    local handle="${proto}_${lport}"
    local ip_family="ip"
    [[ "$tip" =~ : ]] && ip_family="ip6"
    
    # DNAT 规则
    nft add rule inet $NFT_TABLE prerouting $ip_family daddr != $tip $proto dport $lport counter dnat to $tip:$tport comment \"$handle\" 2>/dev/null
    nft add rule inet $NFT_TABLE output_nat $ip_family daddr != $tip $proto dport $lport counter dnat to $tip:$tport comment \"$handle\" 2>/dev/null
    # Masquerade 确保回包经过VPS
    nft add rule inet $NFT_TABLE postrouting $ip_family daddr $tip $proto dport $tport counter masquerade comment \"$handle\" 2>/dev/null
}

# 清除规则
clear_all_rules() {
    echo -e "\n${BLUE}【清除规则】${NC}"
    echo -e "${GREEN}1.${NC} 清除所有白名单IP"
    echo -e "${GREEN}2.${NC} 清除所有转发端口"
    echo -e "${GREEN}3.${NC} 清除全部（白名单+转发）"
    echo -e "${GREEN}0.${NC} 取消"
    echo -ne "${YELLOW}选择: ${NC}"
    read clear_choice

    case $clear_choice in
        1)
            echo -ne "${RED}确认清除所有白名单IP? [y/N]: ${NC}"
            read confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                > "$WHITELIST_FILE"
                apply_all_rules
                echo -e "${GREEN}✓ 已清除所有白名单IP${NC}"
            fi
            ;;
        2)
            echo -ne "${RED}确认清除所有转发端口? [y/N]: ${NC}"
            read confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                > "$FORWARD_FILE"
                apply_all_rules
                echo -e "${GREEN}✓ 已清除所有转发端口${NC}"
            fi
            ;;
        3)
            echo -ne "${RED}确认清除全部规则（白名单+转发+nftables表）? [y/N]: ${NC}"
            read confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                nft delete table inet $NFT_TABLE 2>/dev/null || true
                nft delete table inet filter 2>/dev/null || true
                nft delete table inet whitelist_filter 2>/dev/null || true
                nft delete table inet port_forward 2>/dev/null || true
                > "$WHITELIST_FILE"
                > "$FORWARD_FILE"
                rm -f /etc/nftables.d/*.nft
                sed -i '\|/etc/nftables.d/|d' /etc/nftables.conf 2>/dev/null
                echo -e "${GREEN}✓ 已清除全部规则${NC}"
            fi
            ;;
        0) return ;;
        *) echo -e "${RED}无效选择${NC}" ;;
    esac
}

# 启用IP转发
enable_ip_forward() {
    echo -e "${YELLOW}正在启用IP转发...${NC}"
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1
    
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    else
        sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    fi
    
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    else
        sed -i 's/^net.ipv6.conf.all.forwarding=.*/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
    fi
    
    echo -e "${GREEN}✓ IP转发已启用（IPv4 + IPv6）${NC}"
}

# 添加单个端口转发
add_forward_single() {
    echo -e "\n${BLUE}【添加单端口转发】${NC}"
    
    echo -ne "${YELLOW}目标IP: ${NC}"
    read target_ip
    if [ -z "$target_ip" ]; then
        echo -e "${RED}错误: 目标IP不能为空${NC}"
        return
    fi
    
    echo -ne "${YELLOW}目标端口: ${NC}"
    read target_port
    if ! [[ "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        echo -e "${RED}错误: 无效目标端口${NC}"
        return
    fi
    
    echo -ne "${YELLOW}本地端口: ${NC}"
    read local_port
    if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [ "$local_port" -lt 1 ] || [ "$local_port" -gt 65535 ]; then
        echo -e "${RED}错误: 无效本地端口${NC}"
        return
    fi
    
    if grep -q "^${local_port}|" "$FORWARD_FILE" 2>/dev/null; then
        echo -e "${RED}错误: 本地端口 $local_port 已存在转发规则${NC}"
        return
    fi
    
    echo -e "\n${YELLOW}确认添加:${NC}"
    echo -e "  本地端口 ${GREEN}$local_port${NC} → 目标 ${GREEN}$target_ip:$target_port${NC}  [TCP+UDP]"
    if is_whitelist_enabled; then
        echo -e "  ${RED}注意: 只有白名单IP才能访问此转发${NC}"
    fi
    echo -ne "确认? [Y/n]: "
    read confirm
    
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
        echo "$local_port|$target_ip|$target_port" >> "$FORWARD_FILE"
        apply_all_rules
        echo -e "${GREEN}✓ 已添加${NC}"
    fi
}

# 添加端口段转发
add_forward_range() {
    echo -e "\n${BLUE}【添加端口段转发】${NC}"
    
    echo -ne "${YELLOW}目标IP: ${NC}"
    read target_ip
    if [ -z "$target_ip" ]; then
        echo -e "${RED}错误: 目标IP不能为空${NC}"
        return
    fi
    
    echo -ne "${YELLOW}目标起始端口: ${NC}"
    read target_port_start
    echo -ne "${YELLOW}目标结束端口: ${NC}"
    read target_port_end
    
    if ! [[ "$target_port_start" =~ ^[0-9]+$ ]] || ! [[ "$target_port_end" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误: 无效端口${NC}"
        return
    fi
    if [ "$target_port_start" -ge "$target_port_end" ]; then
        echo -e "${RED}错误: 起始端口必须小于结束端口${NC}"
        return
    fi
    
    echo -ne "${YELLOW}本地起始端口: ${NC}"
    read local_port_start
    echo -ne "${YELLOW}本地结束端口: ${NC}"
    read local_port_end
    
    if ! [[ "$local_port_start" =~ ^[0-9]+$ ]] || ! [[ "$local_port_end" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误: 无效端口${NC}"
        return
    fi
    if [ "$local_port_start" -ge "$local_port_end" ]; then
        echo -e "${RED}错误: 起始端口必须小于结束端口${NC}"
        return
    fi
    
    local local_range=$((local_port_end - local_port_start))
    local target_range=$((target_port_end - target_port_start))
    if [ "$local_range" -ne "$target_range" ]; then
        echo -e "${RED}错误: 端口段数量必须相同（本地 $((local_range+1)) 个 vs 目标 $((target_range+1)) 个）${NC}"
        return
    fi
    
    local lport="${local_port_start}-${local_port_end}"
    local tport="${target_port_start}-${target_port_end}"
    
    if grep -q "^${lport}|" "$FORWARD_FILE" 2>/dev/null; then
        echo -e "${RED}错误: 本地端口段 $lport 已存在转发规则${NC}"
        return
    fi
    
    echo -e "\n${YELLOW}确认添加:${NC}"
    echo -e "  本地端口段 ${GREEN}$lport${NC} → 目标 ${GREEN}$target_ip:$tport${NC}  [TCP+UDP]"
    if is_whitelist_enabled; then
        echo -e "  ${RED}注意: 只有白名单IP才能访问此转发${NC}"
    fi
    echo -ne "确认? [Y/n]: "
    read confirm
    
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
        echo "$lport|$target_ip|$tport" >> "$FORWARD_FILE"
        apply_all_rules
        echo -e "${GREEN}✓ 已添加${NC}"
    fi
}

# 删除端口转发
delete_forward() {
    if [ ! -s "$FORWARD_FILE" ]; then
        echo -e "${RED}无转发规则${NC}"
        return
    fi
    
    echo -e "\n${BLUE}【当前转发规则】${NC}"
    local index=1
    while IFS='|' read -r lport tip tport; do
        echo -e "${GREEN}$index.${NC} [TCP+UDP] 本地:$lport → $tip:$tport"
        ((index++))
    done < "$FORWARD_FILE"
    
    echo -ne "\n${YELLOW}删除序号 (0取消): ${NC}"
    read rule_num
    
    if [ "$rule_num" = "0" ]; then
        return
    fi
    
    if [[ "$rule_num" =~ ^[0-9]+$ ]] && [ "$rule_num" -ge 1 ]; then
        sed -i "${rule_num}d" "$FORWARD_FILE"
        apply_all_rules
        echo -e "${GREEN}✓ 已删除${NC}"
    else
        echo -e "${RED}无效序号${NC}"
    fi
}

# 切换白名单开关
toggle_whitelist() {
    echo -e "\n${BLUE}【白名单开关】${NC}"
    if is_whitelist_enabled; then
        echo -e "当前状态: ${GREEN}已启用${NC}"
        echo -e "${YELLOW}关闭后所有IP均可访问本机及转发端口（不受限制）${NC}"
        echo -ne "${RED}确认关闭白名单? [y/N]: ${NC}"
        read confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            echo "0" > "$WHITELIST_ENABLED_FILE"
            apply_all_rules
            echo -e "${GREEN}✓ 白名单已关闭 - 所有IP均可访问${NC}"
        fi
    else
        echo -e "当前状态: ${RED}已关闭${NC}"
        local wl_count=$(load_whitelist | wc -l)
        echo -e "白名单中有 ${WHITE}$wl_count${NC} 个IP"
        if [ "$wl_count" -eq 0 ]; then
            echo -e "${RED}警告: 白名单为空！启用后将拒绝所有访问（包括当前SSH连接）！${NC}"
            local ssh_ip=$(get_current_ssh_ip)
            if [ -n "$ssh_ip" ]; then
                echo -e "当前SSH IP: ${GREEN}$ssh_ip${NC}"
                echo -ne "是否先将当前SSH IP加入白名单? [Y/n]: "
                read add_ssh
                if [[ ! "$add_ssh" =~ ^[Nn]$ ]]; then
                    add_to_whitelist "$ssh_ip"
                fi
            fi
        fi
        echo -ne "${YELLOW}确认启用白名单? [Y/n]: ${NC}"
        read confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            echo "1" > "$WHITELIST_ENABLED_FILE"
            apply_all_rules
            echo -e "${GREEN}✓ 白名单已启用${NC}"
        fi
    fi
}

# 显示所有规则
show_all_rules() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           当前防火墙和转发规则                     ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${BLUE}═══ 白名单 ═══${NC}"
    show_whitelist
    
    echo -e "\n${BLUE}═══ 端口转发 ═══${NC}"
    if [ ! -s "$FORWARD_FILE" ]; then
        echo -e "${YELLOW}(无转发规则)${NC}"
    else
        local index=1
        while IFS='|' read -r lport tip tport; do
            echo -e "${GREEN}[$index]${NC} [TCP+UDP] 本地:$lport → $tip:$tport"
            ((index++))
        done < "$FORWARD_FILE"
    fi
    
    echo -e "\n${BLUE}═══ 系统状态 ═══${NC}"
    local forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
    if [ "$forward" = "1" ]; then
        echo -e "IPv4转发: ${GREEN}✓ 已启用${NC}"
    else
        echo -e "IPv4转发: ${RED}✗ 未启用${NC}"
    fi
    
    local forward_v6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)
    if [ "$forward_v6" = "1" ]; then
        echo -e "IPv6转发: ${GREEN}✓ 已启用${NC}"
    else
        echo -e "IPv6转发: ${RED}✗ 未启用${NC}"
    fi
    
    local nat_count=$(nft list table inet $NFT_TABLE 2>/dev/null | grep -c "dnat to" || echo 0)
    echo -e "活动转发: ${WHITE}$nat_count 条${NC}"
    
    local whitelist_count=$(load_whitelist | wc -l)
    echo -e "白名单IP: ${WHITE}$whitelist_count 个${NC}"
    
    if is_whitelist_enabled; then
        echo -e "\n${RED}重要: 白名单已启用 - 只有白名单IP才能访问VPS（包括转发端口）${NC}"
    else
        echo -e "\n${YELLOW}提示: 白名单已关闭 - 所有IP均可访问（转发端口无限制）${NC}"
    fi
}

# 主菜单
main_menu() {
    while true; do
        clear
        
        # 白名单状态
        local wl_status
        if is_whitelist_enabled; then
            wl_status="${GREEN}[白名单: 启用]${NC}"
        else
            wl_status="${RED}[白名单: 关闭]${NC}"
        fi
        
        echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║   nftable白名单IP+端口转发脚本         ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
        echo -e "  状态: $wl_status"
        echo ""
        echo -e "${BLUE}【白名单管理】${NC}"
        echo -e "${GREEN}1.${NC} 添加IP到白名单"
        echo -e "${GREEN}2.${NC} 删除白名单IP"
        echo -e "${GREEN}3.${NC} 启用/关闭白名单"
        echo ""
        echo -e "${BLUE}【端口转发】${NC}"
        echo -e "${GREEN}4.${NC} 添加单端口转发"
        echo -e "${GREEN}5.${NC} 添加端口段转发"
        echo -e "${GREEN}6.${NC} 删除端口转发"
        echo -e "${GREEN}7.${NC} 启用IP转发(sysctl)"
        echo ""
        echo -e "${BLUE}【系统】${NC}"
        echo -e "${GREEN}8.${NC} 应用所有规则"
        echo -e "${GREEN}9.${NC} 查看所有规则"
        echo -e "${GREEN}10.${NC} 清除所有规则"
        echo -e "${GREEN}11.${NC} 导出配置"
        echo -e "${GREEN}12.${NC} 导入配置"
        echo -e "${GREEN}0.${NC} 退出"
        echo ""
        echo -ne "选择 [0-12]: "
        read choice
        
        case $choice in
            1)
                echo ""
                echo -ne "输入IP/CIDR: "
                read ip
                [ -n "$ip" ] && add_to_whitelist "$ip" && apply_all_rules
                ;;
            2)
                echo ""
                show_whitelist
                echo -ne "输入序号或IP: "
                read input
                if [[ "$input" =~ ^[0-9]+$ ]]; then
                    local ip=$(load_whitelist | sed -n "${input}p")
                    [ -n "$ip" ] && remove_from_whitelist "$ip" && apply_all_rules
                else
                    remove_from_whitelist "$input" && apply_all_rules
                fi
                ;;
            3) toggle_whitelist ;;
            4) add_forward_single ;;
            5) add_forward_range ;;
            6) delete_forward ;;
            7) enable_ip_forward ;;
            8) apply_all_rules ;;
            9) show_all_rules ;;
            10) clear_all_rules ;;
            11)
                local backup="nftables_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                tar -czf "$backup" "$WHITELIST_FILE" "$FORWARD_FILE" "$WHITELIST_ENABLED_FILE" 2>/dev/null
                echo -e "${GREEN}✓ 已导出: $backup${NC}"
                ;;
            12)
                echo -ne "备份文件路径: "
                read backup_file
                if [ -f "$backup_file" ]; then
                    tar -xzf "$backup_file" -C / 2>/dev/null
                    apply_all_rules
                    echo -e "${GREEN}✓ 已导入${NC}"
                else
                    echo -e "${RED}文件不存在${NC}"
                fi
                ;;
            0) echo ""; exit 0 ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
        
        echo ""
        echo -n "按回车继续..."
        read
    done
}

# 初始化向导
initial_setup() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              初始化向导                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local current_ip=$(get_current_ssh_ip)
    if [ -n "$current_ip" ]; then
        echo -e "检测到你的SSH连接IP: ${GREEN}$current_ip${NC}"
        echo ""
        echo -e "${YELLOW}强烈建议将此IP添加到白名单！${NC}"
        echo -ne "是否添加? [Y/n]: "
        read answer
        if [[ ! "$answer" =~ ^[Nn]$ ]]; then
            add_to_whitelist "$current_ip"
            echo ""
        fi
    else
        echo -e "${YELLOW}未检测到SSH连接IP${NC}"
        echo "请手动添加你的IP地址"
        echo ""
    fi
    
    echo -e "${RED}重要提示:${NC}"
    echo "1. 白名单默认启用，应用规则后只有白名单IP才能访问VPS"
    echo "2. 端口转发也受白名单限制（白名单启用时）"
    echo "3. 可随时在菜单中启用/关闭白名单，不影响转发规则"
    echo "4. 请确保至少添加一个可信IP"
    echo ""
    echo -n "按回车继续..."
    read
}

# 主程序
main() {
    check_nftables
    init_files
    
    # 首次运行向导
    if [ ! -s "$WHITELIST_FILE" ]; then
        initial_setup
    fi
    
    main_menu
}

main

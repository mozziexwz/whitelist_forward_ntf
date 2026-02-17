#!/bin/bash

# NFTables 防火墙 + 端口转发 一体化管理脚本 (IPv6修复版)
# 核心规则：只有白名单IP才能访问VPS（包括转发端口）

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
    echo -e "${BLUE}当前白名单:${NC}"
    echo "=========================================="
    if [ ! -s "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}(空白名单 - 警告: 所有访问将被拒绝)${NC}"
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
    
    cat > "$temp_rules" << 'RULESET'
# 统一表 - 包含 NAT 和 Filter
table inet unified {
    # 白名单集合
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
    
    # NAT链 - 端口转发
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
    
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
    
    chain output_nat {
        type nat hook output priority -100; policy accept;
    }
    
    # Filter链 - 白名单控制 (本机服务)
    chain input {
        type filter hook input priority filter; policy drop;
        
        # 本地回环
        iif lo accept
        
        # 允许已建立的连接 (包括VPS主动访问外部后的回包)
        ct state established,related accept
        
        # 允许ICMPv6 (必需，否则IPv6邻居发现等功能会失效)
        ip6 nexthdr icmpv6 accept
        
        # 白名单IP允许访问本机服务
        ip saddr @allowed_ips accept
        ip6 saddr @allowed_ips_v6 accept
        
        # 拒绝其他所有
        drop
    }
    
    # Forward链 - 转发控制 (关键修复：默认Drop，只允许白名单)
    chain forward {
        type filter hook forward priority filter; policy drop;
        
        # 允许已建立的转发连接 (双向通信)
        ct state established,related accept
        
        # 允许ICMPv6转发 (用于IPv6路径MTU发现等)
        ip6 nexthdr icmpv6 accept
        
        # 只允许白名单IP进行转发访问
        ip saddr @allowed_ips accept
        ip6 saddr @allowed_ips_v6 accept
        
        # 拒绝其他所有转发请求
        drop
    }
    
    chain output {
        type filter hook output priority filter; policy accept;
        
        # 允许所有出站连接 (VPS主动访问外部)
        # 回包通过 input 链的 ct state established,related 处理
    }
}
RULESET

    if ! nft -f "$temp_rules" 2>&1; then
        echo -e "${RED}✗ 规则应用失败${NC}"
        rm -f "$temp_rules"
        return 1
    fi
    
    # 添加白名单IP到集合
    local has_whitelist=false
    while IFS= read -r ip; do
        has_whitelist=true
        if [[ "$ip" =~ .*:.* ]]; then
            nft add element inet $NFT_TABLE allowed_ips_v6 { "$ip" } 2>/dev/null
        else
            nft add element inet $NFT_TABLE allowed_ips { "$ip" } 2>/dev/null
        fi
    done < <(load_whitelist)
    
    if [ "$has_whitelist" = false ]; then
        echo -e "${RED}警告: 白名单为空，所有访问将被拒绝！${NC}"
    fi
    
    # 重新加载端口转发规则
    if [ -s "$FORWARD_FILE" ]; then
        while IFS='|' read -r proto lport tip tport; do
            if [ "$proto" = "both" ]; then
                add_forward_rules_internal "tcp" "$lport" "$tip" "$tport"
                add_forward_rules_internal "udp" "$lport" "$tip" "$tport"
            else
                add_forward_rules_internal "$proto" "$lport" "$tip" "$tport"
            fi
        done < "$FORWARD_FILE"
    fi
    
    # 保存持久化配置
    mkdir -p /etc/nftables.d
    nft list table inet $NFT_TABLE > /etc/nftables.d/unified.nft
    
    if [ -f /etc/nftables.conf ]; then
        # 确保不重复include
        if ! grep -q "include \"/etc/nftables.d/unified.nft\"" /etc/nftables.conf; then
            echo 'include "/etc/nftables.d/unified.nft"' >> /etc/nftables.conf
        fi
    else
        echo 'include "/etc/nftables.d/unified.nft"' > /etc/nftables.conf
    fi
    
    systemctl enable nftables 2>/dev/null || true
    
    rm -f "$temp_rules"
    echo -e "${GREEN}✓ 规则已应用 - 防火墙与转发均已生效${NC}"
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
    
    # 添加DNAT规则
    nft add rule inet $NFT_TABLE prerouting $ip_family daddr != $tip $proto dport $lport counter dnat to $tip:$tport comment \"$handle\" 2>/dev/null
    nft add rule inet $NFT_TABLE output_nat $ip_family daddr != $tip $proto dport $lport counter dnat to $tip:$tport comment \"$handle\" 2>/dev/null
    # 添加Masquerade (SNAT) 规则，确保回包经过VPS
    nft add rule inet $NFT_TABLE postrouting $ip_family daddr $tip $proto dport $tport counter masquerade comment \"$handle\" 2>/dev/null
}

# 清除所有规则
clear_all_rules() {
    echo -e "${RED}警告: 将清除所有防火墙和转发规则！${NC}"
    echo -ne "确认清除? [y/N]: "
    read -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        nft delete table inet $NFT_TABLE 2>/dev/null || true
        nft delete table inet filter 2>/dev/null || true
        nft delete table inet whitelist_filter 2>/dev/null || true
        nft delete table inet port_forward 2>/dev/null || true
        rm -f /etc/nftables.d/*.nft
        sed -i '\|/etc/nftables.d/|d' /etc/nftables.conf 2>/dev/null
        echo -e "${GREEN}✓ 已清除所有规则${NC}"
    fi
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
    
    echo -e "${GREEN}✓ IP转发已启用${NC}"
}

# 添加端口转发
add_forward() {
    echo -e "\n${BLUE}【添加端口转发】${NC}"
    echo -e "${GREEN}1.${NC} TCP"
    echo -e "${GREEN}2.${NC} UDP"
    echo -e "${GREEN}3.${NC} TCP+UDP"
    echo -ne "${YELLOW}协议: ${NC}"
    read proto_choice
    
    local protocol
    case $proto_choice in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        3) protocol="both" ;;
        *) echo -e "${RED}无效选择${NC}"; return ;;
    esac
    
    echo -ne "${YELLOW}是否添加端口段? [y/N]: ${NC}"
    read is_range
    
    if [[ "$is_range" =~ ^[Yy]$ ]]; then
        # 端口段
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
        
        echo -ne "${YELLOW}目标IP: ${NC}"
        read target_ip
        
        echo -ne "${YELLOW}目标端口段与本地相同? [Y/n]: ${NC}"
        read same_ports
        
        if [[ "$same_ports" =~ ^[Nn]$ ]]; then
            echo -ne "${YELLOW}目标起始端口: ${NC}"
            read target_port_start
            echo -ne "${YELLOW}目标结束端口: ${NC}"
            read target_port_end
            
            local local_range=$((local_port_end - local_port_start))
            local target_range=$((target_port_end - target_port_start))
            
            if [ "$local_range" -ne "$target_range" ]; then
                echo -e "${RED}错误: 端口段数量必须相同${NC}"
                return
            fi
        else
            target_port_start=$local_port_start
            target_port_end=$local_port_end
        fi
        
        local lport="${local_port_start}-${local_port_end}"
        local tport="${target_port_start}-${target_port_end}"
        
        echo -e "\n${YELLOW}确认添加:${NC}"
        echo -e "协议: ${GREEN}$protocol${NC}"
        echo -e "本地: ${GREEN}$lport${NC} → 目标: ${GREEN}$target_ip:$tport${NC}"
        echo -e "${RED}注意: 只有白名单IP才能访问此转发${NC}"
        echo -ne "确认? [Y/n]: "
        read confirm
        
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            echo "$protocol|$lport|$target_ip|$tport" >> "$FORWARD_FILE"
            apply_all_rules
            echo -e "${GREEN}✓ 已添加${NC}"
        fi
    else
        # 单个端口
        echo -ne "${YELLOW}本地端口: ${NC}"
        read local_port
        
        if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [ "$local_port" -lt 1 ] || [ "$local_port" -gt 65535 ]; then
            echo -e "${RED}错误: 无效端口${NC}"
            return
        fi
        
        if grep -q "|${local_port}|" "$FORWARD_FILE" 2>/dev/null; then
            echo -e "${RED}错误: 端口已存在${NC}"
            return
        fi
        
        echo -ne "${YELLOW}目标IP: ${NC}"
        read target_ip
        echo -ne "${YELLOW}目标端口: ${NC}"
        read target_port
        
        if ! [[ "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
            echo -e "${RED}错误: 无效端口${NC}"
            return
        fi
        
        echo -e "\n${YELLOW}确认添加:${NC}"
        echo -e "协议: ${GREEN}$protocol${NC}"
        echo -e "本地: ${GREEN}$local_port${NC} → 目标: ${GREEN}$target_ip:$target_port${NC}"
        echo -e "${RED}注意: 只有白名单IP才能访问此转发${NC}"
        echo -ne "确认? [Y/n]: "
        read confirm
        
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            echo "$protocol|$local_port|$target_ip|$target_port" >> "$FORWARD_FILE"
            apply_all_rules
            echo -e "${GREEN}✓ 已添加${NC}"
        fi
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
    while IFS='|' read -r proto lport tip tport; do
        echo -e "${GREEN}$index.${NC} [$proto] $lport → $tip:$tport"
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
        while IFS='|' read -r proto lport tip tport; do
            echo -e "${GREEN}[$index]${NC} [$proto] $lport → $tip:$tport"
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
    
    echo -e "\n${RED}重要: 只有白名单IP才能访问VPS（包括转发端口）${NC}"
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║   NFTables 防火墙+转发 一体化管理工具 (IPv6修复)   ║${NC}"
        echo -e "${CYAN}║   规则: 只有白名单IP可访问VPS                     ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${BLUE}【白名单管理】${NC}"
        echo -e "${GREEN}1.${NC} 添加IP到白名单"
        echo -e "${GREEN}2.${NC} 删除白名单IP"
        echo ""
        echo -e "${BLUE}【端口转发】${NC}"
        echo -e "${GREEN}3.${NC} 添加端口转发 (支持端口段)"
        echo -e "${GREEN}4.${NC} 删除端口转发"
        echo -e "${GREEN}5.${NC} 启用IP转发"
        echo ""
        echo -e "${BLUE}【系统】${NC}"
        echo -e "${GREEN}6.${NC} 应用所有规则"
        echo -e "${GREEN}7.${NC} 查看所有规则"
        echo -e "${GREEN}8.${NC} 清除所有规则"
        echo -e "${GREEN}9.${NC} 导出配置"
        echo -e "${GREEN}10.${NC} 导入配置"
        echo -e "${GREEN}0.${NC} 退出"
        echo ""
        echo -ne "选择 [0-10]: "
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
            3) add_forward ;;
            4) delete_forward ;;
            5) enable_ip_forward ;;
            6) apply_all_rules ;;
            7) show_all_rules ;;
            8) clear_all_rules ;;
            9)
                local backup="nftables_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                tar -czf "$backup" "$WHITELIST_FILE" "$FORWARD_FILE" 2>/dev/null
                echo -e "${GREEN}✓ 已导出: $backup${NC}"
                ;;
            10)
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
    echo "1. 应用规则后，只有白名单IP才能访问VPS"
    echo "2. 端口转发也受白名单限制"
    echo "3. 请确保至少添加一个可信IP"
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

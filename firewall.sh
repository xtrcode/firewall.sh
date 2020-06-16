#!/bin/bash -e

# IPs & SUBNETs
PUBLIC_IP4=""
PUBLIC_IP6=""
FLOATING_IP4=""
FLOATING_IP6=""

INTERNAL_IP4=""
INTERNAL_NET="10.0.0.0/24"

MANAGEMENT_IPS=(10.0.0.250 10.0.0.2)
MONITORING_IPS=("${MANAGEMENT_IPS[*]}" 10.0.0.80)


# PORTs
OPEN_TCP_PUBLIC_V4=(1)
OPEN_UDP_PUBLIC_V4=(2)
OPEN_TCP_PUBLIC_V6=(3)
OPEN_UDP_PUBLIC_V6=(4)

OPEN_TCP_FLOATING_V4=(5)
OPEN_UDP_FLOATING_V4=(6)
OPEN_TCP_FLOATING_V6=(7)
OPEN_UDP_FLOATING_V6=(8)

OPEN_TCP_INTERNAL_V4=(9)
OPEN_UDP_INTERNAL_V4=(10)

OPEN_TCP_MANAGEMENT_V4=(11)
OPEN_UDP_MANAGEMENT_V4=(12)

OPEN_TCP_MONITORING_V4=(13)
OPEN_UDP_MONITORING_V4=(14)

# DONT TOUCH
ipt4() {
    echo /sbin/iptables "$@"
}

ipt6() {
    echo /sbin/ip6tables "$@"
}

ipt() {
    ipt4 "$@"
    ipt6 "$@"
}

ipt46="ipt  "

pre_start() {
    if systemctl list-units | grep -Fq 'docker'; then    
        systemctl stop docker
    fi
}

post_start() {
    if systemctl list-units | grep -Fq 'docker'; then    
        systemctl start docker
    fi
}


iptables_reset() {
    # delete everything
    $ipt46 -F
    $ipt46 -X
    $ipt46 -Z

    # set default policy
    $ipt46 -P INPUT DROP
    $ipt46 -P FORWARD DROP
    $ipt46 -P OUTPUT ACCEPT

    # enable loopback
    $ipt46 -A OUTPUT -o lo -j ACCEPT
    $ipt46 -A INPUT -i lo -j ACCEPT

    # allow established connections
    $ipt46 -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    $ipt46 -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # allow icmp
    $ipt4 -A OUTPUT -m state --state NEW -p icmp --icmp-type echo-request -j ACCEPT
    $ipt4 -A INPUT -m state --state NEW -p icmp --icmp-type echo-request -j ACCEPT
    $ipt6 -A INPUT -p ipv6-icmp -j ACCEPT
}

iptables_open_ports_caller() {
    declare -a ports=("${!1}")

    for port in ${ports[*]}
    do
        ($2 "-A INPUT -m state --state NEW -p $3 $4 --dport $port -j ACCEPT ");
    done
}

iptables_open_ports() {
    # OPEN PORTs FOR PUBLIC IPs
    iptables_open_ports_caller OPEN_TCP_PUBLIC_V4[@] ipt4 "tcp" "-d $PUBLIC_IP4"
    iptables_open_ports_caller OPEN_UDP_PUBLIC_V4[@] ipt4 "udp" "-d $PUBLIC_IP4"
    iptables_open_ports_caller OPEN_TCP_PUBLIC_V6[@] ipt6 "tcp" "-d $PUBLIC_IP6"
    iptables_open_ports_caller OPEN_UDP_PUBLIC_V6[@] ipt6 "udp" "-d $PUBLIC_IP6"

    # OPEN PORTs FOR FLOATING IPs
    iptables_open_ports_caller OPEN_TCP_FLOATING_V4[@] ipt4 "tcp" "-d $FLOATING_IP4"
    iptables_open_ports_caller OPEN_UDP_FLOATING_V4[@] ipt4 "udp" "-d $FLOATING_IP4"
    iptables_open_ports_caller OPEN_TCP_FLOATING_V6[@] ipt6 "tcp" "-d $FLOATING_IP6"
    iptables_open_ports_caller OPEN_UDP_FLOATING_V6[@] ipt6 "udp" "-d $FLOATING_IP6"

    # OPEN PORTs FOR INTERNAL NET
    iptables_open_ports_caller OPEN_TCP_INTERNAL_V4[@] ipt4 "tcp" "-d $INTERNAL_IP4"
    iptables_open_ports_caller OPEN_UDP_INTERNAL_V4[@] ipt4 "udp" "-d $INTERNAL_IP4"

    # OPEN PORTs FOR MONITORING IPs
    for ip in ${MONITORING_IPS[*]}
    do
        iptables_open_ports_caller OPEN_TCP_MONITORING_V4[@] ipt4 "tcp" "-s $ip"
        iptables_open_ports_caller OPEN_UDP_MONITORING_V4[@] ipt4 "udp" "-s $ip"
    done

    # OPEN PORTs FOR MANAGEMENT IPs
    for ip in ${MANAGEMENT_IPS[*]}
    do
        iptables_open_ports_caller OPEN_TCP_MANAGEMENT_V4[@] ipt4 "tcp" "-s $ip"
        iptables_open_ports_caller OPEN_UDP_MANAGEMENT_V4[@] ipt4 "udp" "-s $ip"
    done
}

iptables_open_ports
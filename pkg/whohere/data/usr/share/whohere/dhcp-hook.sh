#!/bin/sh
# dnsmasq 的 dhcp-script 钩子。
#
# 注意: 这个脚本是被 /usr/lib/dnsmasq/dhcp-script.sh 用 `.` source 进去执行的,
# 且整个 dnsmasq 跑在 ujail 里 —— 除了被 RW 挂载的少数路径外什么都写不了。
# 所以这里只能通过 jail 内可用的 ubus 把数据送出去, 不能落文件, 也不能 exit。

case "$1" in
	add|old)
		[ -n "$2" ] || return 0
		ubus send whohere.dhcp "{ \
\"mac\":\"$2\", \
\"ip\":\"$3\", \
\"host\":\"${4:-$DNSMASQ_SUPPLIED_HOSTNAME}\", \
\"vendor\":\"$DNSMASQ_VENDOR_CLASS\", \
\"opts\":\"$DNSMASQ_REQUESTED_OPTIONS\" }" 2>/dev/null
		;;
esac

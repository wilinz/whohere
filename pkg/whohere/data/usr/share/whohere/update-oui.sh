#!/bin/sh
# 更新 OUI 厂商库(LuCI 上的「更新 OUI 库」按钮 / 定时任务都走这里)。
#
# 主源是本项目 oui 分支上的紧凑表(gz): 由 CI 每 3 天从 IEEE 抓一次转好,
# 路由器这边不用做解析, 也不用受 IEEE 官网时好时坏的罪。
# IEEE 官网留作兜底, 拿到的是原始格式, 在这里现转。
# 需要 https, 因此依赖 libustream-* (opkg install libustream-mbedtls)。
set -u
DST="$(uci -q get whohere.global.oui_db)"
[ -n "$DST" ] || DST=/usr/share/whohere/oui.txt
TMP="/tmp/whohere-oui.$$"

# 主源是压缩表(380K, 而不是 IEEE 原始表的 5M), 省流量也省闪存写入
URLS="https://raw.githubusercontent.com/wilinz/whohere/oui/oui.txt.gz
https://standards-oui.ieee.org/oui/oui.txt"

fetch() {
	if command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O "$1" "$2"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$1" "$2"
	else
		wget -q -O "$1" "$2"
	fi
}

ok=0
for u in $URLS; do
	if fetch "$TMP.raw" "$u" && [ -s "$TMP.raw" ]; then ok=1; break; fi
done
[ "$ok" = 1 ] || { echo '{"ok":false,"error":"下载失败, 检查网络与 libustream-mbedtls"}'; rm -f "$TMP".*; exit 1; }

# oui 分支上的是 gz, 先解开; IEEE 兜底那份是明文, 解压会失败, 原样往下走
# (不用 gzip -t 判断 —— busybox 的 gzip 未必带 -t)
if gzip -dc "$TMP.raw" > "$TMP.plain" 2>/dev/null && [ -s "$TMP.plain" ]; then
	mv "$TMP.plain" "$TMP.raw"
fi

if grep -q '(hex)' "$TMP.raw"; then
	# IEEE 原始表:  28-6F-B9     (hex)		Nokia Shanghai Bell Co., Ltd.
	# split 的分隔符是正则, "(hex)" 会被当成捕获组只匹配 hex, 前缀会多带个
	# 左括号, 所以按第一个 "(" 截断再滤掉非十六进制字符。
	awk -F'\t' '/\(hex\)/ {
		p = substr($1, 1, index($1, "(") - 1)
		gsub(/[^0-9A-Fa-f]/, "", p)
		name = $NF
		gsub(/^[ \t]+|[ \t\r]+$/, "", name)
		if (length(p) == 6 && name != "") print tolower(p) "\t" name
	}' "$TMP.raw" | sort -u > "$TMP.out"
else
	# 已经是紧凑格式(oui 分支), 原样收下
	cat "$TMP.raw" > "$TMP.out"
fi

n=$(grep -c "	" "$TMP.out")
if [ "$n" -lt 1000 ]; then
	echo "{\"ok\":false,\"error\":\"解析结果只有 $n 条, 格式可能变了, 已放弃\"}"
	rm -f "$TMP".*; exit 1
fi
mkdir -p "$(dirname "$DST")"
mv "$TMP.out" "$DST"
rm -f "$TMP".*
echo "{\"ok\":true,\"entries\":$n,\"path\":\"$DST\"}"

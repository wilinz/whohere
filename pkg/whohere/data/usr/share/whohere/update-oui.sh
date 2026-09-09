#!/bin/sh
# 把 IEEE 的 OUI 登记表转成紧凑格式: aabbcc<TAB>厂商名
#
# 刻意不在包里预置 OUI 数据 —— 凭空编一张 OUI 表只会得到一堆看着像真的错答案。
# 需要 https, 因此依赖 libustream-* (opkg install libustream-mbedtls)。
set -u
DST="$(uci -q get whohere.global.oui_db)"
[ -n "$DST" ] || DST=/usr/share/whohere/oui.txt
TMP="/tmp/whohere-oui.$$"

URLS="https://standards-oui.ieee.org/oui/oui.txt
https://raw.githubusercontent.com/silverwind/oui/master/oui.txt"

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

# IEEE 行长这样:  28-6F-B9     (hex)		Nokia Shanghai Bell Co., Ltd.
# split 的分隔符是正则, "(hex)" 会被当成捕获组只匹配 hex, 前缀会多带个左括号,
# 所以按第一个 "(" 截断再滤掉非十六进制字符。
awk -F'\t' '/\(hex\)/ {
	p = substr($1, 1, index($1, "(") - 1)
	gsub(/[^0-9A-Fa-f]/, "", p)
	name = $NF
	gsub(/^[ \t]+|[ \t\r]+$/, "", name)
	if (length(p) == 6 && name != "") print tolower(p) "\t" name
}' "$TMP.raw" | sort -u > "$TMP.out"

n=$(wc -l < "$TMP.out")
if [ "$n" -lt 1000 ]; then
	echo "{\"ok\":false,\"error\":\"解析结果只有 $n 条, 格式可能变了, 已放弃\"}"
	rm -f "$TMP".*; exit 1
fi
mkdir -p "$(dirname "$DST")"
mv "$TMP.out" "$DST"
rm -f "$TMP".*
echo "{\"ok\":true,\"entries\":$n,\"path\":\"$DST\"}"

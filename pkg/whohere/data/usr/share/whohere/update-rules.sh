#!/bin/sh
# 从指定 URL 拉一份新的指纹规则库。规则是数据不是代码, 单独更新, 不用换二进制。
set -u
DST="$(uci -q get whohere.global.rules)"
[ -n "$DST" ] || DST=/usr/share/whohere/rules.json
URL="${1:-$(uci -q get whohere.global.rules_url)}"
[ -n "$URL" ] || { echo '{"ok":false,"error":"未配置 rules_url"}'; exit 1; }
TMP="/tmp/whohere-rules.$$"

if command -v uclient-fetch >/dev/null 2>&1; then uclient-fetch -q -O "$TMP" "$URL"
elif command -v curl >/dev/null 2>&1; then curl -fsSL -o "$TMP" "$URL"
else wget -q -O "$TMP" "$URL"; fi

[ -s "$TMP" ] || { echo '{"ok":false,"error":"下载失败"}'; rm -f "$TMP"; exit 1; }
# 换上去之前先确认是合法 JSON 且确实含 dns 规则, 免得把好规则库换成一坨垃圾
if ! jsonfilter -i "$TMP" -e '@.dns[0].id' >/dev/null 2>&1; then
	echo '{"ok":false,"error":"内容不是合法的规则库"}'; rm -f "$TMP"; exit 1
fi
mv "$TMP" "$DST"
echo "{\"ok\":true,\"path\":\"$DST\"}"

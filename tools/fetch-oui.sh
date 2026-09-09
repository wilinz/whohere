#!/bin/sh
# 构建期抓取 IEEE 官方 OUI 登记表, 转成紧凑格式打进包里, 保证开箱即用。
# 装到路由器上之后, 用户还能用 update-oui.sh / LuCI 按钮 / 定时任务再更新。
set -eu
DST="${1:-pkg/whohere/data/usr/share/whohere/oui.txt}"
# GNU mktemp 的 -t 模板必须带 X(BSD 不需要), 直接给完整模板, 两边都认
TMP="$(mktemp "${TMPDIR:-/tmp}/whohere-oui.XXXXXX")"
URLS="https://standards-oui.ieee.org/oui/oui.txt
http://standards-oui.ieee.org/oui/oui.txt"

got=0
for u in $URLS; do
	if curl -fsSL --connect-timeout 20 --max-time 300 -o "$TMP" "$u" && [ -s "$TMP" ]; then
		got=1; break
	fi
	echo "  拉取失败, 换下一个源: $u" >&2
done
[ "$got" = 1 ] || { echo "无法获取 IEEE OUI 表" >&2; rm -f "$TMP"; exit 1; }

{
	echo "# IEEE OUI registry, 由 tools/fetch-oui.sh 于 $(date -u +%Y-%m-%d) 转换"
	echo "# 格式: <6位十六进制前缀>\t<厂商名>"
	# 行长这样:  28-6F-B9     (hex)\t\tNokia Shanghai Bell Co., Ltd.
	# 注意 split 的第三个参数是正则, 不能直接写 "(hex)" —— 那会被当成捕获组
	# 只匹配 hex 三个字母, 前缀里会多留一个左括号。直接按 "(" 截断最稳。
	awk -F'\t' '/\(hex\)/ {
		p = substr($1, 1, index($1, "(") - 1)
		gsub(/[^0-9A-Fa-f]/, "", p)
		name = $NF
		gsub(/^[ \t]+|[ \t\r]+$/, "", name)
		if (length(p) == 6 && name != "") print tolower(p) "\t" name
	}' "$TMP" | sort -u
} > "$DST"

rm -f "$TMP"
n=$(grep -c "	" "$DST" || true)
echo "  OUI: $n 条 -> $DST ($(du -h "$DST" | cut -f1))"
[ "$n" -gt 20000 ] || { echo "条目数异常偏少, 可能是源格式变了" >&2; exit 1; }

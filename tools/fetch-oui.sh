#!/bin/sh
# 构建期取 OUI 厂商库, 打进 ipk 里, 保证开箱即用。
#
# 只从本仓库的 oui 分支拉 —— 那份由 .github/workflows/oui.yml 每 3 天从 IEEE
# 抓一次并转成紧凑格式。构建不碰 IEEE 官网: 它时不时连不上, 之前几次 release
# 就是被它拖挂的; 抓不动的风险集中在那一条定时任务里, 挂了也不影响发版。
# 分支上只存 gz(2M -> 380K), 这里解开再打包, 引擎读的是明文表。
set -eu
DST="${1:-pkg/whohere/data/usr/share/whohere/oui.txt}"
SRC="${OUI_URL:-https://raw.githubusercontent.com/wilinz/whohere/oui/oui.txt.gz}"
TMP="$(mktemp "${TMPDIR:-/tmp}/whohere-oui.XXXXXX")"   # GNU mktemp 的模板必须带 X
mkdir -p "$(dirname "$DST")"

curl -fsSL --retry 3 --retry-connrefused --retry-delay 3 \
	--connect-timeout 20 --max-time 300 -o "$TMP" "$SRC" \
	|| { echo "拉不到 OUI 表: $SRC" >&2; rm -f "$TMP"; exit 1; }

gzip -dc "$TMP" > "$DST" || { echo "解压失败: $SRC" >&2; rm -f "$TMP"; exit 1; }
rm -f "$TMP"
n=$(grep -c "	" "$DST" || true)
echo "  OUI: $n 条 -> $DST ($(du -h "$DST" | cut -f1))"
[ "$n" -gt 20000 ] || { echo "条目数异常偏少, oui 分支的数据可能有问题" >&2; exit 1; }

#!/usr/bin/awk -f
# IEEE 的 oui.txt -> 紧凑格式 "aabbcc<TAB>厂商名"
#
# IEEE 行长这样:  28-6F-B9     (hex)\t\tNokia Shanghai Bell Co., Ltd.
# 注意 split 的分隔符是正则, 不能直接写 "(hex)" —— 那会被当成捕获组只匹配
# hex 三个字母, 前缀里会多留一个左括号。直接按 "(" 截断最稳。
BEGIN { FS = "\t"; print "# IEEE OUI registry, 由 tools/oui-convert.awk 转换" }
/\(hex\)/ {
	p = substr($1, 1, index($1, "(") - 1)
	gsub(/[^0-9A-Fa-f]/, "", p)
	name = $NF
	gsub(/^[ \t]+|[ \t\r]+$/, "", name)
	if (length(p) == 6 && name != "") print tolower(p) "\t" name | "sort -u"
}

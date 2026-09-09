// OUI 厂商查询。
//
// 刻意不内置数据: 凭记忆编 OUI 前缀只会得到一张似是而非的错表。
// 数据由 `whohere update-oui` 从 IEEE 拉取后转成紧凑格式:
//     aabbcc<TAB>厂商名
// 查询时按需扫一遍文件(设备数最多几十个, 一次扫描就够), 不整表读进内存,
// 免得在小内存路由器上白占几 MB。

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};

pub const DEFAULT_DB: &str = "/usr/share/whohere/oui.txt";

pub fn lookup_many(db: &str, prefixes: &HashSet<String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if prefixes.is_empty() {
        return out;
    }
    let f = match std::fs::File::open(db) {
        Ok(f) => f,
        Err(_) => return out,
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if line.starts_with('#') {
            continue;
        }
        let (p, v) = match line.split_once('\t') {
            Some(x) => x,
            None => continue,
        };
        let p = p.trim().to_ascii_lowercase();
        if prefixes.contains(&p) {
            out.insert(p, v.trim().to_string());
            if out.len() == prefixes.len() {
                break;
            }
        }
    }
    out
}

pub fn count(db: &str) -> usize {
    std::fs::File::open(db)
        .map(|f| {
            BufReader::new(f)
                .lines()
                .map_while(Result::ok)
                .filter(|l| !l.starts_with('#') && l.contains('\t'))
                .count()
        })
        .unwrap_or(0)
}

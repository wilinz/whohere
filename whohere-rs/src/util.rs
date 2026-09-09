// 通用小工具: UCI 读取、外部命令、时间、MAC 规整。

use std::process::Command;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 执行命令取 stdout; 失败返回空串(路由器上工具缺失是常态, 不该 panic)
pub fn run(prog: &str, args: &[&str]) -> String {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub fn uci_get(path: &str) -> String {
    run("uci", &["-q", "get", path]).trim().to_string()
}

pub fn uci_get_or(path: &str, dflt: &str) -> String {
    let v = uci_get(path);
    if v.is_empty() {
        dflt.to_string()
    } else {
        v
    }
}

pub fn uci_bool(path: &str, dflt: bool) -> bool {
    match uci_get(path).as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => dflt,
    }
}

pub fn uci_num(path: &str, dflt: u64, min: u64) -> u64 {
    uci_get(path).parse::<u64>().unwrap_or(dflt).max(min)
}

/// 统一成小写冒号分隔; 非法输入返回 None
pub fn norm_mac(s: &str) -> Option<String> {
    let hex: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 {
        return None;
    }
    let b: Vec<String> = (0..6).map(|i| hex[i * 2..i * 2 + 2].to_string()).collect();
    Some(b.join(":"))
}

/// 本地管理位(第一字节 bit1)置位 = 随机/私有 MAC, OUI 查询无意义
pub fn is_random_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16)
        .map(|b| b & 0x02 != 0)
        .unwrap_or(false)
}

/// "aabbcc" 形式的 OUI 前缀
pub fn oui_prefix(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect()
}

/// 域名规整: 去尾点、转小写
pub fn norm_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn atomic_write(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = format!("{path}.tmp");
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// 解析 IPv6 文本地址为 16 字节。只认十六进制段和 "::" 压缩,
/// 不处理 "::ffff:1.2.3.4" 这种内嵌 v4 的写法(邻居表里不会出现)。
pub fn parse_v6(s: &str) -> Option<[u8; 16]> {
    let s = s.split('%').next()?; // 去掉 fe80::1%br-lan 的 zone
    let (head, tail) = match s.split_once("::") {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let split = |p: &str| -> Option<Vec<u16>> {
        if p.is_empty() {
            return Some(Vec::new());
        }
        p.split(':')
            .map(|g| u16::from_str_radix(g, 16).ok())
            .collect()
    };
    let (h, t) = (split(head)?, split(tail.unwrap_or(""))?);
    if h.len() + t.len() > 8 || (tail.is_none() && h.len() != 8) {
        return None;
    }
    let mut groups = [0u16; 8];
    groups[..h.len()].copy_from_slice(&h);
    groups[8 - t.len()..].copy_from_slice(&t);
    let mut out = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    Some(out)
}

/// 按 RFC 5952 输出: 小写、去前导零、最长的一段零用 "::" 压掉。
/// 必须和 `ip -6 neigh` 的写法一致, 否则同一个地址在两处对不上。
pub fn fmt_v6(b: &[u8; 16]) -> String {
    let g: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]))
        .collect();
    let (mut best, mut best_len, mut cur, mut cur_len) = (usize::MAX, 0usize, usize::MAX, 0usize);
    for i in 0..8 {
        if g[i] == 0 {
            if cur_len == 0 {
                cur = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best = cur;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    // 只压缩长度 >= 2 的零段, 单个零直接写 0
    if best_len < 2 {
        best = usize::MAX;
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", g[i]));
        i += 1;
    }
    if out.is_empty() {
        "::".to_string()
    } else {
        out
    }
}

/// SLAAC 的 EUI-64 接口标识里嵌着网卡 MAC:
///   MAC aa:bb:cc:dd:ee:ff -> 接口标识 a8bb:ccff:fedd:eeff (第 7 位翻转)
/// 于是不查邻居表也能把一个 v6 地址反推回设备。只有 EUI-64 生成的地址才有
/// 这个结构; RFC7217 稳定隐私地址和临时地址是随机的, 推不出来也不该硬推。
pub fn mac_from_eui64(ip: &str) -> Option<String> {
    let b = parse_v6(ip)?;
    if b[11] != 0xff || b[12] != 0xfe {
        return None;
    }
    let m = [b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]];
    Some(
        m.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod v6_tests {
    use super::*;

    #[test]
    fn v6_roundtrip_matches_iproute_style() {
        for s in [
            "fe80::329c:23ff:fec1:dd70",
            "2408:8207:1234:5678::1",
            "::1",
            "fd5e:a2fd:b8e::1",
            "2001:db8:0:1:1:1:1:1",
        ] {
            let b = parse_v6(s).unwrap_or_else(|| panic!("parse failed: {s}"));
            assert_eq!(fmt_v6(&b), s, "roundtrip mismatch for {s}");
        }
        assert_eq!(parse_v6("fe80::1%br-lan").map(|b| fmt_v6(&b)).unwrap(), "fe80::1");
        assert!(parse_v6("not an address").is_none());
        assert!(parse_v6("1:2:3:4:5:6:7").is_none());
    }

    #[test]
    fn eui64_addresses_reveal_the_mac() {
        // 会话里实测过的两个: AP 的链路本地地址和它的网卡 MAC
        assert_eq!(
            mac_from_eui64("fe80::2ad1:27ff:fe1c:4809").unwrap(),
            "28:d1:27:1c:48:09"
        );
        assert_eq!(
            mac_from_eui64("fe80::329c:23ff:fec1:dd70").unwrap(),
            "30:9c:23:c1:dd:70"
        );
        // 临时地址 / RFC7217 是随机的, 不能硬推
        assert!(mac_from_eui64("2408:8207:1:2:9c4d:1a2b:3c4d:5e6f").is_none());
        assert!(mac_from_eui64("172.16.0.5").is_none());
    }
}

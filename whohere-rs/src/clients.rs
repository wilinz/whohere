// 客户端在线信息采集: DHCP 租约 + 邻居表 + 无线关联表 + UCI 静态绑定。
// 这些是"谁在网上"的事实来源, 与品牌识别无关。

use crate::util::*;
use std::collections::HashMap;

#[derive(Default, Clone)]
pub struct Seen {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub dhcp_name: Option<String>,
    pub lease_expire: u64,
    /// 关联的接口名(wlan0 / br-lan ...)
    pub iface: Option<String>,
    pub band: Option<String>,
    pub signal: Option<i32>,
    pub reachable: bool,
}

fn ins<'a>(map: &'a mut HashMap<String, Seen>, mac: &str) -> &'a mut Seen {
    map.entry(mac.to_string()).or_default()
}

/// /tmp/dhcp.leases: <到期时间戳> <mac> <ip> <主机名> <client-id>
fn from_leases(map: &mut HashMap<String, Seen>) {
    let txt = std::fs::read_to_string("/tmp/dhcp.leases").unwrap_or_default();
    for line in txt.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let mac = match norm_mac(f[1]) {
            Some(m) => m,
            None => continue,
        };
        let e = ins(map, &mac);
        e.lease_expire = f[0].parse().unwrap_or(0);
        if f[2].contains(':') {
            if !e.ipv6.contains(&f[2].to_string()) {
                e.ipv6.push(f[2].to_string());
            }
        } else if !e.ipv4.contains(&f[2].to_string()) {
            e.ipv4.push(f[2].to_string());
        }
        if f[3] != "*" && !f[3].is_empty() {
            e.dhcp_name = Some(f[3].to_string());
        }
    }
}

/// ip neigh: 只认 REACHABLE/STALE/DELAY/PROBE, FAILED 的不算在线
fn from_neigh(map: &mut HashMap<String, Seen>) {
    for ver in ["-4", "-6"] {
        let out = run("ip", &[ver, "neigh", "show"]);
        for line in out.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 {
                continue;
            }
            let ip = f[0];
            let mac = match f.iter().position(|&x| x == "lladdr") {
                Some(i) => match f.get(i + 1).and_then(|m| norm_mac(m)) {
                    Some(m) => m,
                    None => continue,
                },
                None => continue,
            };
            let state = f.last().copied().unwrap_or("");
            if state == "FAILED" || state == "INCOMPLETE" {
                continue;
            }
            let dev = f
                .iter()
                .position(|&x| x == "dev")
                .and_then(|i| f.get(i + 1))
                .map(|s| s.to_string());
            let e = ins(map, &mac);
            if ip.contains(':') {
                if !e.ipv6.contains(&ip.to_string()) {
                    e.ipv6.push(ip.to_string());
                }
            } else if !e.ipv4.contains(&ip.to_string()) {
                e.ipv4.push(ip.to_string());
            }
            if e.iface.is_none() {
                e.iface = dev;
            }
            if state == "REACHABLE" || state == "DELAY" || state == "PROBE" {
                e.reachable = true;
            }
        }
    }
}

/// iwinfo <dev> assoclist -> 无线关联的 MAC / 信号 / 频段
fn from_wifi(map: &mut HashMap<String, Seen>) {
    let devs = run("iwinfo", &[]);
    let mut names: Vec<String> = Vec::new();
    for line in devs.lines() {
        // 形如 "wlan0     ESSID: \"xxx\"" —— 接口名顶格, 后续详情行都有缩进
        if !line.starts_with(char::is_whitespace) && line.contains("ESSID") {
            let name = line.split_whitespace().next().unwrap_or("");
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
    }
    for dev in names {
        // 频段来自 info 里的 "Channel: 34 (5.170 GHz)" —— 注意不是 "Frequency:",
        // 真机上 iwinfo 并不输出那个字段。
        let info = run("iwinfo", &[&dev, "info"]);
        let band = info
            .split_once("GHz")
            .and_then(|(head, _)| {
                let n: String = head
                    .chars()
                    .rev()
                    .skip_while(|c| c.is_whitespace())
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                n.chars().rev().collect::<String>().parse::<f32>().ok()
            })
            .map(|ghz| {
                if ghz >= 5.9 {
                    "6G"
                } else if ghz >= 4.9 {
                    "5G"
                } else {
                    "2.4G"
                }
            })
            .map(|s| s.to_string());

        let out = run("iwinfo", &[&dev, "assoclist"]);
        for line in out.lines() {
            let t = line.trim();
            // 形如 "AA:BB:CC:DD:EE:FF  -55 dBm / -95 dBm (SNR 40)  0 ms ago"
            let first = t.split_whitespace().next().unwrap_or("");
            let mac = match norm_mac(first) {
                Some(m) if first.len() == 17 => m,
                _ => continue,
            };
            let sig = t
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<i32>().ok());
            let e = ins(map, &mac);
            e.iface = Some(dev.clone());
            e.band = band.clone();
            e.signal = sig;
            e.reachable = true;
        }
    }
}

/// /etc/config/dhcp 里的静态绑定, 给设备一个稳定的人工名字
pub fn static_names() -> HashMap<String, String> {
    let mut out = HashMap::new();
    let txt = run("uci", &["-q", "show", "dhcp"]);
    let mut macs: HashMap<String, String> = HashMap::new();
    let mut names: HashMap<String, String> = HashMap::new();
    for line in txt.lines() {
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let v = v.trim_matches('\'');
        if let Some(sec) = k.strip_suffix(".mac") {
            macs.insert(sec.to_string(), v.to_string());
        } else if let Some(sec) = k.strip_suffix(".name") {
            names.insert(sec.to_string(), v.to_string());
        }
    }
    for (sec, mac) in macs {
        if let (Some(m), Some(n)) = (norm_mac(&mac), names.get(&sec)) {
            out.insert(m, n.clone());
        }
    }
    out
}

/// 本路由器负责的内网网段。
///
/// 判断哪些接口算"内网"不能靠名字猜: 上游接口叫 wan / ont / wwan / pppoe-x
/// 的都有, 一台真机上就见过叫 `ont` 的。也不能靠默认路由 —— 上游接口的
/// route[] 经常是空的。
///
/// 语义上真正对的定义是: **我给它发 DHCP 的网段, 才是我的客户端所在的网段**。
/// 所以从 /etc/config/dhcp 里取出未被 ignore 的 dhcp 段所绑定的接口, 再问 ubus
/// 要这些接口的 IPv4 网段。
fn lan_ifaces() -> Vec<String> {
    let txt = run("uci", &["-q", "show", "dhcp"]);
    let mut iface: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut ignored: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in txt.lines() {
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let v = v.trim_matches('\'');
        if let Some(sec) = k.strip_suffix(".interface") {
            iface.insert(sec.to_string(), v.to_string());
        } else if let Some(sec) = k.strip_suffix(".ignore") {
            if v == "1" {
                ignored.insert(sec.to_string());
            }
        }
    }
    iface
        .into_iter()
        .filter(|(sec, _)| !ignored.contains(sec))
        .map(|(_, n)| n)
        .collect()
}

/// 内网接口对应的二层设备名(br-lan 之类)。抓包要绑到二层设备上,
/// uci 里的 "lan" 是逻辑接口名, 不能直接用。
pub fn lan_devices() -> Vec<String> {
    let want = lan_ifaces();
    let txt = run("ubus", &["call", "network.interface", "dump"]);
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    if let Some(list) = v.get("interface").and_then(|x| x.as_array()) {
        for i in list {
            let name = i.get("interface").and_then(|x| x.as_str()).unwrap_or("");
            if !want.iter().any(|w| w == name) {
                continue;
            }
            for key in ["l3_device", "device"] {
                if let Some(d) = i.get(key).and_then(|x| x.as_str()) {
                    if !d.is_empty() && !out.iter().any(|o| o == d) {
                        out.push(d.to_string());
                        break;
                    }
                }
            }
        }
    }
    out
}

pub fn lan_nets() -> Vec<(u32, u32)> {
    let want = lan_ifaces();
    let txt = run("ubus", &["call", "network.interface", "dump"]);
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
    let mut out = Vec::new();
    if let Some(list) = v.get("interface").and_then(|x| x.as_array()) {
        for i in list {
            let name = i.get("interface").and_then(|x| x.as_str()).unwrap_or("");
            if name == "loopback" {
                continue;
            }
            // 拿不到 DHCP 配置时退回名字启发式, 总比一台都不过滤强
            let keep = if want.is_empty() {
                !name.starts_with("wan") && !name.contains("wwan")
            } else {
                want.iter().any(|w| w == name)
            };
            if !keep {
                continue;
            }
            for a in i
                .get("ipv4-address")
                .and_then(|x| x.as_array())
                .map(|v| v.as_slice())
                .unwrap_or(&[])
            {
                let addr = a.get("address").and_then(|x| x.as_str()).unwrap_or("");
                let bits = a.get("mask").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                if let (Some(ip), 1..=32) = (v4_to_u32(addr), bits) {
                    let mask = u32::MAX << (32 - bits);
                    out.push((ip & mask, mask));
                }
            }
        }
    }
    out
}

pub fn v4_to_u32(s: &str) -> Option<u32> {
    let p: Vec<u8> = s.split('.').filter_map(|x| x.parse::<u8>().ok()).collect();
    if p.len() != 4 {
        return None;
    }
    Some(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
}

pub fn in_lan(nets: &[(u32, u32)], ip: &str) -> bool {
    // 拿不到网段信息时不做过滤, 宁可多显示也不要把真设备藏起来
    if nets.is_empty() {
        return true;
    }
    match v4_to_u32(ip) {
        Some(a) => nets.iter().any(|(n, m)| a & m == *n),
        None => true,
    }
}

pub fn collect() -> HashMap<String, Seen> {
    let mut map = HashMap::new();
    from_leases(&mut map);
    from_neigh(&mut map);
    from_wifi(&mut map);
    // 路由器自己的 MAC 不该出现在客户端列表里
    let own: Vec<String> = run("ip", &["-o", "link"])
        .lines()
        .filter_map(|l| {
            l.split_whitespace()
                .skip_while(|w| *w != "link/ether")
                .nth(1)
                .and_then(norm_mac)
        })
        .collect();
    for m in own {
        map.remove(&m);
    }
    // 丢掉不在内网网段里的邻居(上游网关、运营商同网段的陌生设备)
    let nets = lan_nets();
    if !nets.is_empty() {
        map.retain(|_, s| s.ipv4.is_empty() || s.ipv4.iter().any(|ip| in_lan(&nets, ip)));
    }
    map
}

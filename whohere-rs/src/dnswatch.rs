// DNS 查询来源。三种实现, 统一吐出 (客户端 IP, 查询域名, 查询类型, 源端口)。
// 后两项只有 dnsmasq 日志给得全, 另外两路给不出的填空值。
//
//  dnsmasq_log : tail /tmp/whohere-dns.log。OpenWrt 的 dnsmasq 用
//                --log-queries=extra, 行里既有 "<ip>/<port>" 前缀也有结尾的
//                "from <ip>", 我们认后者, 两种格式都能吃。
//  singbox_log : 路由器上跑 sing-box 并由它接管 DNS 时用。sing-box 不在同一行
//                里同时给出客户端和域名, 得靠行首的请求 id 把两行关联起来。
//  dnstap      : 通用结构化来源(unbound/smartdns 等)。注意 dnsmasq 至今不支持
//                dnstap, 所以在原版 OpenWrt 上这条永远不会生效。

use crate::event::Event;
use crate::tail::Tail;
use crate::util::norm_domain;
use std::collections::VecDeque;
use std::sync::mpsc::Sender;

pub const DEFAULT_LOG: &str = "/tmp/whohere-dns.log";

/// 路由器自己(dnsmasq 替本机转发时日志里写的是 127.0.0.1 / ::1)不是客户端
fn is_loopback(ip: &str) -> bool {
    ip == "::1" || ip.starts_with("127.")
}

fn is_ipish(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
}

/// 只保留有判别力的类型, 其余归到 OTHER, 免得 map 被畸形日志撑大
pub fn norm_qtype(t: &str) -> String {
    let t = t.trim().to_ascii_uppercase();
    match t.as_str() {
        "A" | "AAAA" | "HTTPS" | "SVCB" | "PTR" | "SRV" | "TXT" | "CNAME" | "NS" | "MX"
        | "SOA" | "ANY" => t,
        _ => "OTHER".to_string(),
    }
}

/// "... 40 172.16.0.5/52442 query[A] captive.apple.com from 172.16.0.5"
///
/// 三样都要: 域名、查询类型、源端口。后两样以前被丢掉了, 但它们各自
/// 独立于域名内容 —— 一台只查过几个 Google 域名的机器, 域名规则一条都
/// 命不中, 靠 qtype 画像和端口复用模式仍然能定出系统大类。
pub fn parse_dnsmasq(line: &str) -> Option<(String, String, String, u16)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let qi = f.iter().position(|w| w.starts_with("query["))?;
    let domain = norm_domain(f.get(qi + 1)?);
    if domain.is_empty() {
        return None;
    }
    let qtype = norm_qtype(
        f[qi]
            .trim_start_matches("query[")
            .trim_end_matches(']'),
    );
    // --log-queries=extra 的 "<ip>/<port>" 前缀; 只有它带源端口
    let prefix = qi.checked_sub(1).and_then(|i| f.get(i)).copied();
    let sport = prefix
        .and_then(|p| p.rsplit_once('/'))
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(0);
    let ip = match f.iter().position(|w| *w == "from") {
        Some(i) => f.get(i + 1)?.to_string(),
        None => prefix?.rsplit_once('/').map(|(h, _)| h)?.to_string(),
    };
    if !is_ipish(&ip) {
        return None;
    }
    Some((ip, domain, qtype, sport))
}

/// sing-box 日志: 用 "[<id> ...]" 把 "from <ip>:<port>" 和 "dns: exchange <域名>" 关联起来
pub struct SingboxState {
    ids: VecDeque<String>,
    map: std::collections::HashMap<String, (String, u16)>,
    cap: usize,
}

impl SingboxState {
    pub fn new() -> Self {
        SingboxState {
            ids: VecDeque::new(),
            map: std::collections::HashMap::new(),
            cap: 4096,
        }
    }

    fn remember(&mut self, id: String, ip: String, sport: u16) {
        if self.map.insert(id.clone(), (ip, sport)).is_none() {
            self.ids.push_back(id);
            while self.ids.len() > self.cap {
                if let Some(old) = self.ids.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    pub fn feed(&mut self, line: &str) -> Option<(String, String, String, u16)> {
        let id = line
            .split_once('[')
            .and_then(|(_, r)| r.split_once(']').map(|(inner, _)| inner))
            .and_then(|inner| inner.split_whitespace().next())
            .filter(|s| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty())?
            .to_string();

        if let Some(i) = line.find(" from ") {
            let rest = &line[i + 6..];
            let hostport = rest.split_whitespace().next().unwrap_or("");
            // 172.16.0.5:52341 / [fe80::1]:53
            let (ip, port) = if let Some(r) = hostport.strip_prefix('[') {
                let (h, rest) = r.split_once(']').unwrap_or((r, ""));
                (h.to_string(), rest.trim_start_matches(':'))
            } else {
                let (h, p) = hostport.rsplit_once(':')?;
                (h.to_string(), p)
            };
            if is_ipish(&ip) {
                self.remember(id.clone(), ip, port.parse().unwrap_or(0));
            }
        }

        for marker in [" dns: exchange ", " dns: exchanged ", " dns: lookup "] {
            if let Some(i) = line.find(marker) {
                let d = norm_domain(line[i + marker.len()..].split_whitespace().next()?);
                if d.is_empty() {
                    return None;
                }
                let (ip, sport) = self.map.get(&id)?.clone();
                // sing-box 的 exchange 行不带查询类型
                return Some((ip, d, String::new(), sport));
            }
        }
        None
    }
}

// ---------------- dnstap (Frame Streams + protobuf) ----------------

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    while *i < b.len() {
        let byte = b[*i];
        *i += 1;
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// 只取需要的两个字段: Dnstap.message(14) -> Message.query_address(4) / query_message(10)
fn pb_fields(b: &[u8], want: &[u32]) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = match varint(b, &mut i) {
            Some(k) => k,
            None => break,
        };
        let field = (key >> 3) as u32;
        match key & 7 {
            0 => {
                if varint(b, &mut i).is_none() {
                    break;
                }
            }
            1 => i += 8,
            5 => i += 4,
            2 => {
                let len = match varint(b, &mut i) {
                    Some(l) => l as usize,
                    None => break,
                };
                if i + len > b.len() {
                    break;
                }
                if want.contains(&field) {
                    out.push((field, b[i..i + len].to_vec()));
                }
                i += len;
            }
            _ => break,
        }
    }
    out
}

fn dnstap_decode(payload: &[u8]) -> Option<(String, String)> {
    let msg = pb_fields(payload, &[14]).into_iter().next()?.1;
    let mut ip = String::new();
    let mut dom = String::new();
    for (f, v) in pb_fields(&msg, &[4, 10]) {
        match f {
            4 => {
                ip = match v.len() {
                    4 => format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]),
                    16 => {
                        let seg: Vec<String> = v
                            .chunks(2)
                            .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                            .collect();
                        seg.join(":")
                    }
                    _ => String::new(),
                }
            }
            10 => dom = crate::dnsmsg::first_question(&v).unwrap_or_default(),
            _ => {}
        }
    }
    if ip.is_empty() || dom.is_empty() {
        None
    } else {
        Some((ip, dom))
    }
}

fn fstrm_serve(stream: &mut std::os::unix::net::UnixStream, tx: &Sender<Event>) {
    use std::io::{Read, Write};
    let rd = |s: &mut std::os::unix::net::UnixStream, n: usize| -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        s.read_exact(&mut b).ok()?;
        Some(b)
    };
    loop {
        let hdr = match rd(stream, 4) {
            Some(h) => h,
            None => return,
        };
        let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        if len == 0 {
            // 控制帧: 长度 + 类型(+ 可选字段)
            let clen = match rd(stream, 4) {
                Some(c) => u32::from_be_bytes([c[0], c[1], c[2], c[3]]) as usize,
                None => return,
            };
            let body = match rd(stream, clen) {
                Some(b) => b,
                None => return,
            };
            if body.len() < 4 {
                return;
            }
            let ctype = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            // READY(4) -> 回 ACCEPT(1); STOP(3) -> 回 FINISH(5) 并收工
            let reply = match ctype {
                4 => Some(1u32),
                3 => Some(5u32),
                _ => None,
            };
            if let Some(r) = reply {
                let mut frame = vec![0u8, 0, 0, 0];
                frame.extend_from_slice(&4u32.to_be_bytes());
                frame.extend_from_slice(&r.to_be_bytes());
                if stream.write_all(&frame).is_err() {
                    return;
                }
                if r == 5 {
                    return;
                }
            }
            continue;
        }
        if len > 1 << 20 {
            return;
        }
        let payload = match rd(stream, len as usize) {
            Some(p) => p,
            None => return,
        };
        if let Some((ip, domain)) = dnstap_decode(&payload) {
            if is_loopback(&ip) {
                continue;
            }
            let _ = tx.send(Event::Dns {
                ip,
                domain,
                qtype: String::new(),
                sport: 0,
            });
        }
    }
}

pub fn spawn_dnstap(sock: String, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let _ = std::fs::remove_file(&sock);
        let listener = match std::os::unix::net::UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => {
                let _ = tx.send(Event::SourceInfo {
                    kind: "dns",
                    state: "listen_failed",
                    info: format!("dnstap {sock}: {e}"),
                });
                return;
            }
        };
        let _ = std::fs::set_permissions(
            &sock,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o666),
        );
        let _ = tx.send(Event::SourceInfo {
            kind: "dns",
            state: "listening",
            info: format!("dnstap {sock}"),
        });
        for s in listener.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut s = s;
                fstrm_serve(&mut s, &tx);
            });
        }
    });
}

pub fn spawn_logtail(mode: String, path: String, max_kb: u64, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let mut tail = Tail::new(&path);
        let mut sb = SingboxState::new();
        let _ = tx.send(Event::SourceInfo {
            kind: "dns",
            state: "reading_log",
            info: format!("{mode} {path}"),
        });
        loop {
            for line in tail.read_lines() {
                let hit = if mode == "singbox_log" {
                    sb.feed(&line)
                } else {
                    parse_dnsmasq(&line)
                };
                if let Some((ip, domain, qtype, sport)) = hit {
                    if is_loopback(&ip) {
                        continue;
                    }
                    let _ = tx.send(Event::Dns {
                        ip,
                        domain,
                        qtype,
                        sport,
                    });
                }
            }
            // 原始日志用完即焚
            if max_kb > 0 && tail.size() > max_kb * 1024 {
                tail.truncate();
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    });
}

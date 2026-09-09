// 被动监听 mDNS(5353) 与 SSDP(1900) 组播。
//
// 这是四路信号里唯一能直接拿到具体型号字符串的一路: Apple 设备会在
// _device-info._tcp 的 TXT 里报 model=iPhone15,2, 打印机报 ty=..., Chromecast 报 md=...。
// 组播天然会送到路由器网卡上, 不需要抓包也不需要主动扫描。
//
// 端口用 SO_REUSEADDR + SO_REUSEPORT 绑定, 以便和已有的 umdns/avahi 共存。

use crate::event::Event;
use crate::util::norm_domain;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::Sender;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// 本机各接口的 IPv4, 用来逐接口加入组播组(只在默认接口加入会漏掉 LAN 桥)
fn local_v4() -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = crate::util::run("ip", &["-4", "-o", "addr", "show"])
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let i = f.iter().position(|w| *w == "inet")?;
            f.get(i + 1)?
                .split('/')
                .next()?
                .parse::<Ipv4Addr>()
                .ok()
                .filter(|a| !a.is_loopback())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn bind_multicast(port: u16, group: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    // 与 umdns / avahi 共存的关键
    let _ = sock.set_reuse_port(true);
    sock.bind(&SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into())?;
    let ifaces = local_v4();
    let mut joined = false;
    for a in &ifaces {
        if sock.join_multicast_v4(&group, a).is_ok() {
            joined = true;
        }
    }
    if !joined {
        sock.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
    }
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    Ok(sock.into())
}

/// 从一个 mDNS 响应里榨出主机名 / 型号 / 服务类型
fn parse_mdns(buf: &[u8]) -> (String, String, Vec<String>) {
    let mut name = String::new();
    let mut model = String::new();
    let mut services: Vec<String> = Vec::new();

    for r in crate::dnsmsg::parse_records(buf) {
        match r.rtype {
            crate::dnsmsg::T_PTR => {
                // _airplay._tcp.local -> 服务类型; 目标是实例名
                if r.name.starts_with('_') && !r.name.starts_with("_services.") {
                    let svc = r.name.trim_end_matches(".local").to_string();
                    if !services.contains(&svc) {
                        services.push(svc);
                    }
                }
            }
            crate::dnsmsg::T_SRV => {
                if r.name.starts_with('_') || r.name.contains("._tcp") || r.name.contains("._udp") {
                    if let Some(i) = r.name.find("._") {
                        let svc = r.name[i + 1..].trim_end_matches(".local").to_string();
                        if !svc.is_empty() && !services.contains(&svc) {
                            services.push(svc);
                        }
                    }
                }
                if name.is_empty() && !r.target.is_empty() {
                    name = r.target.trim_end_matches(".local").to_string();
                }
            }
            crate::dnsmsg::T_TXT => {
                for kv in &r.txt {
                    let (k, v) = match kv.split_once('=') {
                        Some(x) => x,
                        None => continue,
                    };
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim();
                    if v.is_empty() {
                        continue;
                    }
                    // model= Apple/通用; md= Chromecast; ty= 打印机型号; am= AirPlay 机型
                    if matches!(k.as_str(), "model" | "md" | "ty" | "am") && model.is_empty() {
                        model = v.to_string();
                    }
                    if k == "fn" && name.is_empty() {
                        name = v.to_string();
                    }
                }
            }
            crate::dnsmsg::T_A => {
                if name.is_empty() && r.name.ends_with(".local") {
                    name = r.name.trim_end_matches(".local").to_string();
                }
            }
            _ => {}
        }
    }
    (norm_domain(&name), model, services)
}

/// 构造一个 mDNS PTR 查询
fn dns_query(qname: &str) -> Vec<u8> {
    let mut p: Vec<u8> = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in qname.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&12u16.to_be_bytes()); // PTR
    p.extend_from_slice(&1u16.to_be_bytes()); // IN
    p
}

pub fn spawn_mdns(tx: Sender<Event>) {
    std::thread::spawn(move || {
        let sock = match bind_multicast(5353, MDNS_GROUP) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(Event::SourceInfo {
                    kind: "mdns",
                    state: "listen_failed",
                    info: format!("5353: {e}"),
                });
                return;
            }
        };
        let _ = tx.send(Event::SourceInfo {
            kind: "mdns",
            state: "listening",
            info: "5353".into(),
        });
        // 开机先主动问一轮, 不然只能等设备自己广播
        probe_mdns(&sock);
        let mut buf = [0u8; 9000];
        let mut last_probe = std::time::Instant::now();
        loop {
            if let Ok((n, src)) = sock.recv_from(&mut buf) {
                let ip = match src {
                    SocketAddr::V4(a) => a.ip().to_string(),
                    SocketAddr::V6(a) => a.ip().to_string(),
                };
                let (name, model, services) = parse_mdns(&buf[..n]);
                if !name.is_empty() || !model.is_empty() || !services.is_empty() {
                    let _ = tx.send(Event::Mdns {
                        ip,
                        name,
                        model,
                        services,
                    });
                }
            }
            // 每 30 分钟补一次主动查询, 覆盖那些安静的设备
            if last_probe.elapsed() > std::time::Duration::from_secs(1800) {
                probe_mdns(&sock);
                last_probe = std::time::Instant::now();
            }
        }
    });
}

pub fn probe_mdns(sock: &UdpSocket) {
    let dst = SocketAddrV4::new(MDNS_GROUP, 5353);
    for q in [
        "_services._dns-sd._udp.local",
        "_device-info._tcp.local",
        "_airplay._tcp.local",
        "_googlecast._tcp.local",
        "_ipp._tcp.local",
        "_miio._udp.local",
    ] {
        let _ = sock.send_to(&dns_query(q), dst);
    }
}

pub fn spawn_ssdp(tx: Sender<Event>) {
    std::thread::spawn(move || {
        let sock = match bind_multicast(1900, SSDP_GROUP) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(Event::SourceInfo {
                    kind: "ssdp",
                    state: "listen_failed",
                    info: format!("1900: {e}"),
                });
                return;
            }
        };
        let _ = tx.send(Event::SourceInfo {
            kind: "ssdp",
            state: "listening",
            info: "1900".into(),
        });
        probe_ssdp(&sock);
        let mut buf = [0u8; 4096];
        let mut last_probe = std::time::Instant::now();
        loop {
            if let Ok((n, src)) = sock.recv_from(&mut buf) {
                let ip = match src {
                    SocketAddr::V4(a) => a.ip().to_string(),
                    SocketAddr::V6(a) => a.ip().to_string(),
                };
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    let low = line.to_ascii_lowercase();
                    if low.starts_with("server:") || low.starts_with("user-agent:") {
                        let v = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                        if !v.is_empty() {
                            let _ = tx.send(Event::Ssdp {
                                ip: ip.clone(),
                                server: v.to_string(),
                            });
                        }
                        break;
                    }
                }
            }
            if last_probe.elapsed() > std::time::Duration::from_secs(1800) {
                probe_ssdp(&sock);
                last_probe = std::time::Instant::now();
            }
        }
    });
}

pub fn probe_ssdp(sock: &UdpSocket) {
    let msg = "M-SEARCH * HTTP/1.1\r\n\
               HOST: 239.255.255.250:1900\r\n\
               MAN: \"ssdp:discover\"\r\n\
               MX: 2\r\n\
               ST: ssdp:all\r\n\r\n";
    let _ = sock.send_to(msg.as_bytes(), SocketAddrV4::new(SSDP_GROUP, 1900));
}

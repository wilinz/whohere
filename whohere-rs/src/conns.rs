// 从 conntrack 读「这台设备长期连着谁的什么端口」。
//
// 为什么需要这一路: 有一类设备把前面所有信号都躲开了 —— 开机解析一次 DNS
// 之后再不查(或者干脆写死 IP), 只挂一条长连接到云端, 不开任何监听端口。
// 实测一个向日葵远程插座就是这样: DNS 日志里零条、没有 TCP 可抓、端口探测
// 一个不开, 四路信号加抓包全部失明, 只剩一个 Espressif 的 OUI。
//
// 但它那条长连的对端端口躲不掉。UDP/12312 之于向日葵、TCP/5228 之于安卓推送、
// TCP/5223 之于苹果推送, 都是很硬的特征。
//
// 隐私上与 DNS 一路同规格: 只记「命中了哪条规则」, 对端 IP 不落盘;
// 只有显式打开 keep_unmatched 时才留未命中的 端口 样本用来补规则。

use crate::event::Event;
use std::sync::mpsc::Sender;

const CONNTRACK: &str = "/proc/net/nf_conntrack";
/// 包数低于这个的不算「长连」, 滤掉一次性的短连接
const MIN_PACKETS: u64 = 20;

/// 一行 conntrack -> (客户端 IP, 协议, 对端 IP, 对端端口, 包数)
fn parse_line(line: &str) -> Option<(String, String, String, u16, u64)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let proto = *f.get(2)?;
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    // 只看正向元组: 第一个 src=/dst=/dport=/packets=
    let get = |k: &str| -> Option<&str> {
        f.iter()
            .find(|x| x.starts_with(k))
            .map(|x| &x[k.len()..])
    };
    let src = get("src=")?.to_string();
    let dst = get("dst=")?.to_string();
    let dport: u16 = get("dport=")?.parse().ok()?;
    let packets: u64 = get("packets=")?.parse().unwrap_or(0);
    Some((src, proto.to_string(), dst, dport, packets))
}

/// 组播和广播不是"长连对端"。mDNS 的 224.0.0.251:5353 每台设备都在发,
/// 混进来只会让每台设备的未命中样本里都堆一条 udp/5353。
fn is_uninteresting(ip: &str) -> bool {
    if ip.starts_with("127.") || ip == "255.255.255.255" {
        return true;
    }
    // 224.0.0.0/4 组播
    match ip.split('.').next().and_then(|x| x.parse::<u8>().ok()) {
        Some(first) => (224..=239).contains(&first),
        None => ip.starts_with("ff"), // v6 组播
    }
}

pub fn spawn(tx: Sender<Event>, interval: u64) {
    std::thread::spawn(move || {
        if std::fs::metadata(CONNTRACK).is_err() {
            let _ = tx.send(Event::SourceInfo {
                kind: "conns",
                state: "unavailable",
                info: CONNTRACK.to_string(),
            });
            return;
        }
        let _ = tx.send(Event::SourceInfo {
            kind: "conns",
            state: "reading",
            info: CONNTRACK.to_string(),
        });
        loop {
            if let Ok(text) = std::fs::read_to_string(CONNTRACK) {
                for line in text.lines() {
                    if let Some((ip, proto, remote, port, packets)) = parse_line(line) {
                        if packets < MIN_PACKETS || is_uninteresting(&remote) {
                            continue;
                        }
                        let _ = tx.send(Event::Peer {
                            ip,
                            proto,
                            remote,
                            port,
                        });
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(interval.max(30)));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_forward_tuple_only() {
        let l = "ipv4     2 udp      17 153 src=172.16.1.111 dst=114.55.107.162 \
                 sport=16155 dport=12312 packets=6230 bytes=475480 \
                 src=114.55.107.162 dst=172.16.1.111 sport=12312 dport=16155 packets=6100";
        let (ip, proto, remote, port, packets) = parse_line(l).unwrap();
        assert_eq!(ip, "172.16.1.111");
        assert_eq!(proto, "udp");
        assert_eq!(remote, "114.55.107.162");
        assert_eq!(port, 12312, "必须取正向元组的 dport, 反向的是临时端口");
        assert_eq!(packets, 6230);
    }

    #[test]
    fn multicast_and_broadcast_are_not_peers() {
        for ip in ["224.0.0.251", "239.255.255.250", "255.255.255.255", "127.0.0.1", "ff02::fb"] {
            assert!(is_uninteresting(ip), "{ip} 不该被当成长连对端");
        }
        for ip in ["114.55.107.162", "172.16.0.1", "8.8.8.8"] {
            assert!(!is_uninteresting(ip), "{ip} 是正常对端");
        }
    }

    #[test]
    fn ignores_non_tcp_udp() {
        assert!(parse_line("ipv4 2 icmp 1 29 src=1.2.3.4 dst=5.6.7.8 type=8 code=0").is_none());
        assert!(parse_line("").is_none());
    }
}

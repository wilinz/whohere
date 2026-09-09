// 主动端口探测。这是全项目唯一会主动连客户端的一路, 所以默认关闭,
// 且只在用户点「立即探测」时跑一次, 不做后台周期扫描。
//
// 为什么需要它: 一台安静的服务器可能既不广播 mDNS/SSDP, 也不用路由器的 DNS,
// 于是前面所有被动信号全是空的 —— PVE 宿主机就是典型。但它监听着 8006,
// SSH banner 里还直接写着发行版和版本号:
//   SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
//
// 克制原则: 端口表是固定的一小串"能说明身份"的端口, 不是全端口扫描;
// 超时很短; 并发有上限; 只连已经在设备表里的内网地址。

use crate::event::Event;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use std::time::Duration;

/// 探测端口表。
///
/// 选取标准是「开着就能说明身份」, 不是「常见」。8080、8443 这类什么都可能是的
/// 端口刻意不收 —— 它们只会给出一堆无法归因的开放端口, 反而稀释结论。
pub const PORTS: [u16; 36] = [
    22,    // SSH —— banner 里有发行版和版本
    23,    // Telnet, 老式嵌入式设备
    53,    // DNS, 说明它自己在做解析器(旁路由 / 漏配的 AP)
    80,    // HTTP —— Server 头
    111,   // rpcbind, NFS 服务端
    135,   // MSRPC, Windows 独有
    139,   // NetBIOS 会话
    445,   // SMB
    515,   // LPD, 打印机
    548,   // AFP, 苹果 / NAS
    554,   // RTSP, 摄像机
    631,   // IPP, 打印机
    873,   // rsync
    902,   // VMware ESXi authd
    1883,  // MQTT, 智能家居中枢
    2049,  // NFS
    3260,  // iSCSI
    3389,  // RDP
    3689,  // DAAP, 苹果媒体共享
    5000,  // 群晖 DSM
    5001,  // 群晖 DSM (https)
    5357,  // WSD, Windows / 网络打印机
    5555,  // ADB over TCP, 安卓(电视盒子常年开着)
    5900,  // VNC
    5985,  // WinRM
    7547,  // TR-069, 运营商管理的光猫 / CPE
    8000,  // 海康服务端口
    8006,  // Proxmox VE
    8007,  // Proxmox Backup Server
    8096,  // Jellyfin
    8123,  // Home Assistant
    9090,  // Cockpit, 红帽系 Web 控制台
    9100,  // JetDirect, 打印机
    32400, // Plex
    // 443/8443 本身不说明厂商, 但很多设备的管理界面只在 https 上
    // (PiKVM 就是: 80 口的 nginx 只回 404, 界面在 443)
    443,
    8443,
];

const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
const READ_TIMEOUT: Duration = Duration::from_millis(700);

/// 连上以后尽量拿一句能说明身份的话。
/// SSH 一连上就自报 banner; HTTP 要先问一句才答。
fn banner(mut s: TcpStream, port: u16, host: &str) -> String {
    let _ = s.set_read_timeout(Some(READ_TIMEOUT));
    if port != 80 {
        // SSH 一连上就自报家门, 不用问
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).unwrap_or(0);
        let _ = s.shutdown(Shutdown::Both);
        return String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .chars()
            .take(120)
            .collect();
    }

    // HTTP: 用 GET 而不是 HEAD —— 路由器/摄像机/打印机的身份主要写在
    // 登录页的 <title> 里, HEAD 拿不到正文。为了不真的"访问"什么, 只请求
    // 根路径, 而且读到 8KB 就断开, 不会把整页拉完。
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    let _ = s.write_all(req.as_bytes());
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while buf.len() < 8192 {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let _ = s.shutdown(Shutdown::Both);
    http_identity(&buf)
}

/// 从 HTTP 响应里榨出能说明身份的几样, 拼成一行。
///
/// 只读 Server 头是不够的: 路由器和摄像机的 Web 服务大多是 uhttpd/lighttpd/
/// GoAhead 这类通用服务器, Server 头看不出厂商。真正带厂商信息的是:
///   * <title> —— "TP-LINK Wireless Router" / "OpenWrt - LuCI" / "小米路由器"
///   * WWW-Authenticate 的 realm —— 老设备的 Basic 认证域常是型号
///   * 重定向 Location —— 常指向 /cgi-bin/luci、/webpages/index.html 之类特征路径
fn http_identity(buf: &[u8]) -> String {
    let text = String::from_utf8_lossy(buf);
    let mut bits: Vec<String> = Vec::new();

    let head_end = text.find("\r\n\r\n").unwrap_or(text.len());
    for line in text[..head_end].split("\r\n") {
        let (k, v) = match line.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match k.trim().to_ascii_lowercase().as_str() {
            "server" => bits.push(v.chars().take(60).collect()),
            "www-authenticate" => bits.push(format!("realm={}", v.chars().take(60).collect::<String>())),
            "location" => bits.push(format!("->{}", v.chars().take(60).collect::<String>())),
            _ => {}
        }
    }

    // <title>…</title>, 大小写不敏感, 折行和多余空白压平
    let lower = text.to_ascii_lowercase();
    if let Some(a) = lower.find("<title") {
        if let Some(gt) = lower[a..].find('>') {
            let start = a + gt + 1;
            if let Some(len) = lower[start..].find("</title") {
                let t: String = text[start..start + len].split_whitespace().collect::<Vec<_>>().join(" ");
                let t = t.trim();
                if !t.is_empty() {
                    bits.push(format!("title={}", t.chars().take(80).collect::<String>()));
                }
            }
        }
    }
    bits.join(" | ").chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_identity_prefers_the_login_page_title() {
        // 典型的路由器登录页: Server 头是通用的 uhttpd, 厂商信息在 title 里
        let r = b"HTTP/1.1 200 OK\r\nServer: uhttpd\r\nContent-Type: text/html\r\n\r\n<html><head><TITLE>\n  TP-LINK Wireless N Router WR841N \n</TITLE></head>";
        let id = http_identity(r);
        assert!(id.contains("uhttpd"), "{id}");
        assert!(id.contains("title=TP-LINK Wireless N Router WR841N"), "{id}");
    }

    #[test]
    fn http_identity_picks_up_auth_realm_and_redirect() {
        let r = b"HTTP/1.1 401 Unauthorized\r\nServer: GoAhead-Webs\r\nWWW-Authenticate: Basic realm=\"DS-2CD2032-I\"\r\n\r\n";
        let id = http_identity(r);
        assert!(id.contains("GoAhead"), "{id}");
        assert!(id.contains("DS-2CD2032-I"), "{id}");

        let r2 = b"HTTP/1.1 302 Found\r\nLocation: /cgi-bin/luci\r\n\r\n";
        assert!(http_identity(r2).contains("->/cgi-bin/luci"), "{}", http_identity(r2));
    }

    #[test]
    fn http_identity_is_empty_when_nothing_identifying() {
        assert_eq!(http_identity(b"HTTP/1.1 200 OK\r\n\r\n<html><body>hi</body></html>"), "");
    }
}

/// 挑一个同网段内、不在设备表里的地址做对照。
///
/// 任何在**这个地址上也"开着"**的端口都不可能是设备属性 —— 它只能是网络在
/// 中间接管了连接。实测这台路由器上跑着 sing-box + tun0, 它的 DNS 劫持让
/// 到任意地址 53 端口的连接都能成功, 于是手机和摄像头都"开着 53"。
/// 这比"多数设备都开着"的比例判据更硬, 而且设备很少时也成立。
fn control_ip(ips: &[String]) -> Option<String> {
    let first = ips.first()?;
    let mut oct: Vec<u8> = first
        .split('.')
        .map(|x| x.parse::<u8>().ok())
        .collect::<Option<Vec<u8>>>()?;
    if oct.len() != 4 {
        return None;
    }
    for last in [253u8, 252, 251, 250, 249] {
        oct[3] = last;
        let cand = format!("{}.{}.{}.{}", oct[0], oct[1], oct[2], oct[3]);
        if !ips.iter().any(|x| *x == cand) {
            return Some(cand);
        }
    }
    None
}

/// 扁平任务队列 + 固定线程数。
///
/// 原来是「每台机器顺序试完所有端口」, 端口表一长就慢得没法用: 全部关闭的主机
/// 每个端口都要等满超时。改成把 (地址, 端口) 摊平成任务, 由固定数量的工作线程
/// 抢着做 —— 线程数有上限, 免得在弱路由器上把 conntrack 打满。
const WORKERS: usize = 32;

pub fn run(ips: Vec<String>, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let n = ips.len();
        let _ = tx.send(Event::SourceInfo {
            kind: "ports",
            state: "probing",
            info: n.to_string(),
        });

        // 对照地址和真实设备一起排进队列, 用同样的超时和并发条件
        let control = control_ip(&ips);
        let mut targets = ips.clone();
        if let Some(c) = &control {
            targets.push(c.clone());
        }
        let tasks: Vec<(String, u16)> = targets
            .iter()
            .flat_map(|ip| PORTS.iter().map(move |p| (ip.clone(), *p)))
            .collect();
        let queue = std::sync::Arc::new(std::sync::Mutex::new(tasks));
        // ip -> (开放端口, 各端口的 banner)
        // banner 按端口分开存: SSH 说系统, HTTP 的登录页说厂商和型号,
        // 早先让 22 口覆盖 80 口, 结果两个都开的路由器丢掉了更有用的那份。
        let found: std::sync::Arc<
            std::sync::Mutex<HashMap<String, (Vec<u16>, Vec<(u16, String)>)>>,
        > =
            std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

        let mut hs = Vec::new();
        for _ in 0..WORKERS.min(queue.lock().map(|q| q.len()).unwrap_or(0).max(1)) {
            let (queue, found) = (queue.clone(), found.clone());
            hs.push(std::thread::spawn(move || loop {
                let task = match queue.lock() {
                    Ok(mut q) => q.pop(),
                    Err(_) => return,
                };
                let (ip, port) = match task {
                    Some(t) => t,
                    None => return,
                };
                let addr: SocketAddr = match format!("{ip}:{port}").parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let s = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let b = if port == 22 || port == 80 {
                    banner(s, port, &ip)
                } else {
                    String::new()
                };
                if let Ok(mut f) = found.lock() {
                    let e = f.entry(ip).or_insert_with(|| (Vec::new(), Vec::new()));
                    e.0.push(port);
                    if !b.is_empty() {
                        e.1.push((port, b));
                    }
                }
            }));
        }
        for h in hs {
            let _ = h.join();
        }

        // 透明劫持自检。
        //
        // 实测这台路由器上有 DNS 透明重定向, 于是连"任何" IP 的 53 端口都能连上,
        // 全网 12 台设备无一例外 —— 手机、摄像头也"开着 53", 直接把两台服务器
        // 误判成了网络设备。同类陷阱还有强制门户对 80/443 的劫持。
        //
        // 判据: 一个端口在绝大多数设备上都"开着", 那它多半不是设备的属性,
        // 而是网络的属性。这个自检不需要知道防火墙规则, 换一张网也成立。
        let mut artifacts: Vec<u16> = Vec::new();
        if let Ok(mut f) = found.lock() {
            // 对照地址上"开着"的端口, 一律是网络侧接管
            if let Some(c) = &control {
                if let Some((open, _)) = f.remove(c) {
                    artifacts.extend(open);
                }
            }
            // 没有对照地址可用时(网段占满), 退回比例判据
            if artifacts.is_empty() && n >= 5 {
                let mut count: HashMap<u16, usize> = HashMap::new();
                for (open, _) in f.values() {
                    for p in open {
                        *count.entry(*p).or_insert(0) += 1;
                    }
                }
                let threshold = (n * 7) / 10;
                artifacts = count
                    .into_iter()
                    .filter(|(_, c)| *c > threshold.max(4))
                    .map(|(p, _)| p)
                    .collect();
            }
            artifacts.sort_unstable();
            artifacts.dedup();
            if !artifacts.is_empty() {
                for (open, _) in f.values_mut() {
                    open.retain(|p| !artifacts.contains(p));
                }
            }
            // 对**每一台探过的设备**都发结果, 哪怕一个端口都没开。
            // 只发有结果的会让上一轮的旧数据一直挂着 —— 实测就因此把已经
            // 判定为劫持、本该剔除的 53 留在了两台设备上。
            for ip in &ips {
                let (mut open, bs) = f.remove(ip).unwrap_or_default();
                open.sort_unstable();
                let mut bs = bs;
                bs.sort_by_key(|(p, _)| *p);
                let banner = bs
                    .into_iter()
                    .map(|(_, b)| b)
                    .collect::<Vec<_>>()
                    .join(" | ");
                let _ = tx.send(Event::Ports {
                    ip: ip.clone(),
                    open,
                    banner,
                });
            }
        }
        // 结果只发一条 —— sources 里同一个 kind 只保留最后一条, 分两条发
        // 后面那条会把前面的盖掉
        let (state, info) = if artifacts.is_empty() {
            ("done", n.to_string())
        } else {
            let list: Vec<String> = artifacts.iter().map(|p| p.to_string()).collect();
            ("done_redirected", format!("{n};{}", list.join(",")))
        };
        let _ = tx.send(Event::SourceInfo {
            kind: "ports",
            state,
            info,
        });
    });
}

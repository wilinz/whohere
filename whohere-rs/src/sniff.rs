// 被动抓包: 从 TCP SYN 取协议栈指纹, 从 TLS ClientHello 取 SNI, 从明文 HTTP 取 Host。
//
// 为什么值得做: DNS 那一路对走 DoH/DoT 的设备完全失效, 而 SNI 在 ClientHello 里
// 仍是明文(ECH 尚未普及), 于是同一份域名规则库可以原样复用到 SNI 上。TCP 栈指纹
// 则完全不依赖设备查了什么 —— 初始 TTL 一项就能三分天下(64=Linux/Android/macOS,
// 128=Windows, 255=部分嵌入式)。
//
// 实现选择:
//  * AF_PACKET + 内核 cBPF 过滤, 不引 libpcap。过滤在内核做, 不匹配的包根本不会
//    复制到用户态, 这是 CPU 开销可控的关键。
//  * IPv4 和 IPv6 都处理。v6 只认「下一个头就是 TCP」的情形 —— 带扩展头的包
//    长度不定, 内核过滤器里没法定位 TCP 头, 直接放过。客户端发起的普通连接
//    不带扩展头, 实际影响很小。
//    (这一路对 v6 很关键: 实测 39 台设备里 32 台有 v6 地址, 只有 17 台有 v4,
//     纯 v4 的抓包会漏掉一多半设备。)
//  * 不开混杂模式: 路由器是客户端的下一跳, 转发流量本来就会送到本机协议栈。
//
// 隐私: 与 DNS 一路完全相同 —— 只记「命中了哪条规则」, 不落原始域名;
// 只有显式打开 keep_unmatched 时才保留未命中样本。

use crate::event::Event;
use crate::util::norm_domain;
use std::sync::mpsc::Sender;

const ETH_HDR: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_ALL: u16 = 0x0003;

// ---------------- cBPF 汇编 ----------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_B_IND: u16 = 0x50;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;

/// 跳转目标用名字表示, 偏移在 build() 里统一算。
/// 手数跳转偏移是这类代码最常见的错误来源, 所以一条都不手写。
#[derive(Clone, Copy)]
enum T {
    Accept,
    Drop,
    Next,
    To(&'static str),
}

struct Asm {
    out: Vec<(u16, T, T, u32)>,
    labels: Vec<(&'static str, usize)>,
}

impl Asm {
    fn new() -> Asm {
        Asm {
            out: Vec::new(),
            labels: Vec::new(),
        }
    }
    fn label(&mut self, name: &'static str) {
        self.labels.push((name, self.out.len()));
    }
    fn op(&mut self, code: u16, k: u32) {
        self.out.push((code, T::Next, T::Next, k));
    }
    fn jmp(&mut self, code: u16, k: u32, jt: T, jf: T) {
        self.out.push((code, jt, jf, k));
    }
    fn build(self) -> Vec<SockFilter> {
        let accept = self.out.len();
        let drop = accept + 1;
        let resolve = |from: usize, t: &T| -> u8 {
            let to = match t {
                T::Accept => accept,
                T::Drop => drop,
                T::Next => from + 1,
                T::To(name) => self
                    .labels
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, i)| *i)
                    .expect("undefined bpf label"),
            };
            (to - from - 1) as u8
        };
        let mut v: Vec<SockFilter> = self
            .out
            .iter()
            .enumerate()
            .map(|(i, (code, jt, jf, k))| SockFilter {
                code: *code,
                jt: resolve(i, jt),
                jf: resolve(i, jf),
                k: *k,
            })
            .collect();
        // 262144: 单包最多复制这么多字节到用户态, 足够放下 ClientHello
        v.push(SockFilter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: 262144,
        });
        v.push(SockFilter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: 0,
        });
        v
    }
}

/// 放行条件: IPv4 且 TCP 且非分片, 并且
///   (a) 带 SYN —— 用来取栈指纹; 或者
///   (b) 目的端口 80/443 且带 PSH 且整包 < 1400 字节 —— ClientHello 和 HTTP 请求
///       都落在这个范围内, 而满 MTU 的批量传输段会被挡掉, 上送流量降一个数量级。
fn filter_prog() -> Vec<SockFilter> {
    // IPv6 里各字段的绝对偏移: 头是固定 40 字节
    const V6_NEXTHDR: u32 = (ETH_HDR + 6) as u32;
    const V6_PLEN: u32 = (ETH_HDR + 4) as u32;
    const V6_TCP: usize = ETH_HDR + 40;

    let mut a = Asm::new();
    a.op(LD_H_ABS, 12); // ethertype
    a.jmp(JEQ_K, ETH_P_IPV6 as u32, T::To("v6"), T::Next);
    a.jmp(JEQ_K, ETH_P_IP as u32, T::Next, T::Drop);

    // ---- IPv4 ----
    a.op(LD_B_ABS, 23); // ip proto
    a.jmp(JEQ_K, 6, T::Next, T::Drop);
    a.op(LD_H_ABS, 20); // 分片偏移
    a.jmp(JSET_K, 0x1fff, T::Drop, T::Next);
    a.op(LDX_B_MSH, 14); // X = IP 头长度
    a.op(LD_B_IND, (ETH_HDR + 13) as u32); // TCP flags
    a.jmp(JSET_K, 0x02, T::Accept, T::Next); // SYN
    a.jmp(JSET_K, 0x08, T::Next, T::Drop); // 必须带 PSH
    a.op(LD_H_IND, (ETH_HDR + 2) as u32); // 目的端口
    a.jmp(JEQ_K, 443, T::To("len4"), T::Next);
    a.jmp(JEQ_K, 80, T::To("len4"), T::Next);
    // 1883: 明文 MQTT。CONNECT 包里的 ClientID 是明文的, 常带厂商和型号。
    a.jmp(JEQ_K, 1883, T::To("len4"), T::Drop);
    a.label("len4");
    a.op(LD_H_ABS, 16); // IP 总长
    a.jmp(JGE_K, 1400, T::Drop, T::Accept);

    // ---- IPv6 ----
    a.label("v6");
    a.op(LD_B_ABS, V6_NEXTHDR);
    a.jmp(JEQ_K, 6, T::Next, T::Drop); // 只认紧跟着 TCP 的
    a.op(LD_B_ABS, (V6_TCP + 13) as u32); // TCP flags
    a.jmp(JSET_K, 0x02, T::Accept, T::Next);
    a.jmp(JSET_K, 0x08, T::Next, T::Drop);
    a.op(LD_H_ABS, (V6_TCP + 2) as u32); // 目的端口
    a.jmp(JEQ_K, 443, T::To("len6"), T::Next);
    a.jmp(JEQ_K, 80, T::To("len6"), T::Next);
    a.jmp(JEQ_K, 1883, T::To("len6"), T::Drop);
    a.label("len6");
    a.op(LD_H_ABS, V6_PLEN); // 载荷长度(不含 40 字节头)
    a.jmp(JGE_K, 1360, T::Drop, T::Accept);

    a.build()
}

// ---------------- 报文解析 ----------------

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

/// SYN 包里能拿到的栈特征, 拼成一个可比对的串:
///   `<初始TTL/跳数限制>:<MSS>:<窗口>:<窗口缩放>:<选项顺序>:<df|v6>`
/// v4/v6 共用: 最后一段 v4 写 df/-, v6 写 v6(没有分片标志这一说)。
/// 规则匹配的是中间的**选项顺序**子串, 两种版本都能命中同一条规则。
/// 例如 macOS 是 `64:1460:65535:6:mss,nop,ws,ts,sok,eol:df`
///
/// 选项的**顺序**比选项本身更有判别力 —— 各家 TCP 实现拼选项的次序是固定的,
/// 而且这个特征不受随机 MAC、加密 DNS 影响。
fn tcp_fingerprint(ttl: u8, df: &str, tcp: &[u8]) -> Option<String> {
    if tcp.len() < 20 {
        return None;
    }
    let win = be16(tcp, 14);
    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < 20 || doff > tcp.len() {
        return None;
    }
    let (mut mss, mut ws) = (0u16, 255u8);
    let mut names: Vec<&str> = Vec::new();
    let mut i = 20;
    while i < doff {
        let kind = tcp[i];
        match kind {
            0 => {
                names.push("eol");
                break;
            }
            1 => {
                names.push("nop");
                i += 1;
                continue;
            }
            _ => {}
        }
        if i + 1 >= doff {
            break;
        }
        let len = tcp[i + 1] as usize;
        if len < 2 || i + len > doff {
            break;
        }
        match kind {
            2 if len == 4 => {
                mss = be16(tcp, i + 2);
                names.push("mss");
            }
            3 if len == 3 => {
                ws = tcp[i + 2];
                names.push("ws");
            }
            4 => names.push("sok"),
            8 => names.push("ts"),
            _ => names.push("opt"),
        }
        i += len;
    }
    Some(format!(
        "{}:{}:{}:{}:{}:{}",
        ttl,
        mss,
        win,
        if ws == 255 { "-".into() } else { ws.to_string() },
        names.join(","),
        df
    ))
}

/// 从 TLS ClientHello 里取 SNI。只读长度前缀, 不做任何解密。
fn tls_sni(p: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2)
    if p.len() < 43 || p[0] != 0x16 {
        return None;
    }
    let mut i = 5;
    if p.get(i)? != &0x01 {
        return None; // 必须是 ClientHello
    }
    i += 4; // handshake type + length
    i += 2 + 32; // client version + random
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    let cs = be16(p.get(i..i + 2)?, 0) as usize;
    i += 2 + cs;
    let comp = *p.get(i)? as usize;
    i += 1 + comp;
    let ext_total = be16(p.get(i..i + 2)?, 0) as usize;
    i += 2;
    let end = (i + ext_total).min(p.len());
    while i + 4 <= end {
        let etype = be16(p, i);
        let elen = be16(p, i + 2) as usize;
        i += 4;
        if i + elen > end {
            break;
        }
        if etype == 0 {
            // server_name: list_len(2) type(1) name_len(2) name
            if elen >= 5 && p[i + 2] == 0 {
                let nlen = be16(p, i + 3) as usize;
                let s = p.get(i + 5..i + 5 + nlen)?;
                return Some(norm_domain(&String::from_utf8_lossy(s)));
            }
            return None;
        }
        i += elen;
    }
    None
}

/// 明文 HTTP 请求里的 Host 和 User-Agent。
/// UA 的信息量比 Host 大得多 —— `Dalvik/2.1.0 (Linux; U; Android 14; ...)`
/// 直接写着系统版本, 但只有不走 TLS 的流量才有, 如今主要是 IoT 设备。
fn http_fields(p: &[u8]) -> Option<(String, String)> {
    const METHODS: [&[u8]; 6] = [b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"CONN"];
    if !METHODS.iter().any(|m| p.starts_with(m)) {
        return None;
    }
    let text = String::from_utf8_lossy(&p[..p.len().min(2048)]);
    let (mut host, mut ua) = (String::new(), String::new());
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (k, v) = match line.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" if host.is_empty() => host = norm_domain(v.split(':').next().unwrap_or(v)),
            "user-agent" if ua.is_empty() => ua = v.chars().take(200).collect(),
            _ => {}
        }
    }
    if host.is_empty() && ua.is_empty() {
        None
    } else {
        Some((host, ua))
    }
}

/// MQTT CONNECT 的 ClientID。
///
/// 明文 MQTT(1883) 的第一个包就是 CONNECT, 里面的 ClientID 由设备固件自己拼,
/// 常见形如 `midea_ac_1234`、`ESP_78:3C:80`、`tasmota_A1B2C3`, 厂商和型号都写在里面。
/// 这跟 TLS 的 SNI 是同一类东西: 协议规定的明文字段, 白拿。
fn mqtt_client_id(p: &[u8]) -> Option<String> {
    // 固定头: 0x10 = CONNECT
    if p.first()? & 0xf0 != 0x10 {
        return None;
    }
    // 剩余长度是 1~4 字节的变长整数
    let mut i = 1;
    let mut mult = 1u32;
    let mut len = 0u32;
    loop {
        let b = *p.get(i)?;
        len += (b & 0x7f) as u32 * mult;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        mult = mult.checked_mul(128)?;
        if i > 4 {
            return None;
        }
    }
    if len == 0 || p.len() < i + 2 {
        return None;
    }
    // 协议名: "MQTT"(3.1.1/5.0) 或 "MQIsdp"(3.1)
    let pn_len = be16(p, i) as usize;
    i += 2;
    let pn = p.get(i..i + pn_len)?;
    if pn != b"MQTT" && pn != b"MQIsdp" {
        return None;
    }
    i += pn_len;
    i += 1 + 1 + 2; // 协议版本 + 连接标志 + keepalive
    let id_len = be16(p.get(i..i + 2)?, 0) as usize;
    i += 2;
    if id_len == 0 || id_len > 128 {
        return None;
    }
    let id = p.get(i..i + id_len)?;
    let s: String = String::from_utf8_lossy(id)
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 一个以太网帧 -> 若干事件。v4/v6 只有取源地址和定位 TCP 头的方式不同,
/// 后面的解析完全共用。
fn handle(frame: &[u8], tx: &Sender<Event>) {
    if frame.len() < ETH_HDR + 20 {
        return;
    }
    let (src, tcp) = match be16(frame, 12) {
        ETH_P_IP => {
            let ip = &frame[ETH_HDR..];
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ip.len() < ihl + 20 {
                return;
            }
            let total = be16(ip, 2) as usize;
            (
                format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]),
                &ip[ihl..ip.len().min(total.max(ihl + 20))],
            )
        }
        ETH_P_IPV6 => {
            let ip = &frame[ETH_HDR..];
            if ip.len() < 40 + 20 || ip[6] != 6 {
                return;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&ip[8..24]);
            let end = (40 + be16(ip, 4) as usize).min(ip.len());
            (crate::util::fmt_v6(&a), &ip[40..end.max(60)])
        }
        _ => return,
    };
    if tcp.len() < 20 {
        return;
    }
    let flags = tcp[13];

    // SYN 且非 SYN-ACK: 这是客户端主动发起的连接
    if flags & 0x02 != 0 && flags & 0x10 == 0 {
        let ip = &frame[ETH_HDR..];
        let (ttl, df) = if be16(frame, 12) == ETH_P_IP {
            (ip[8], if be16(ip, 6) & 0x4000 != 0 { "df" } else { "-" })
        } else {
            (ip[7], "v6") // v6 的跳数限制
        };
        if let Some(fp) = tcp_fingerprint(ttl, df, tcp) {
            let _ = tx.send(Event::TcpFp { ip: src, fp });
        }
        return;
    }

    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < 20 || tcp.len() <= doff {
        return;
    }
    let payload = &tcp[doff..];
    if let Some(id) = mqtt_client_id(payload) {
        let _ = tx.send(Event::Conn {
            ip: src,
            host: String::new(),
            ua: id,
            via: "mqtt",
        });
    } else if let Some(host) = tls_sni(payload) {
        if !host.is_empty() {
            let _ = tx.send(Event::Conn {
                ip: src,
                host,
                ua: String::new(),
                via: "sni",
            });
        }
    } else if let Some((host, ua)) = http_fields(payload) {
        let _ = tx.send(Event::Conn {
            ip: src,
            host,
            ua,
            via: "http",
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn(_ifaces: Vec<String>, tx: Sender<Event>) {
    let _ = tx.send(Event::SourceInfo {
        kind: "sniff",
        state: "unsupported",
        info: String::new(),
    });
}

#[cfg(target_os = "linux")]
fn if_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let n = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

/// 绑到某个接口的 AF_PACKET 裸套接字, 并把过滤器装进内核。
#[cfg(target_os = "linux")]
fn open_socket(iface: &str) -> std::io::Result<libc::c_int> {
    let idx = if_index(iface)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such interface"))?;
    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (ETH_P_ALL as u16).to_be() as libc::c_int,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // 先装过滤器再绑接口, 避免绑定到装载之间漏进无关流量
        let prog = filter_prog();
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = idx as i32;
        if libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
pub fn spawn(ifaces: Vec<String>, tx: Sender<Event>) {
    for iface in ifaces {
        let tx = tx.clone();
        std::thread::spawn(move || match open_socket(&iface) {
            Err(e) => {
                let _ = tx.send(Event::SourceInfo {
                    kind: "sniff",
                    state: "listen_failed",
                    info: format!("{iface}: {e}"),
                });
            }
            Ok(fd) => {
                let _ = tx.send(Event::SourceInfo {
                    kind: "sniff",
                    state: "listening",
                    info: iface.clone(),
                });
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = unsafe {
                        libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                    };
                    if n < 0 {
                        let e = std::io::Error::last_os_error();
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        let _ = tx.send(Event::SourceInfo {
                            kind: "sniff",
                            state: "listen_failed",
                            info: format!("{iface}: {e}"),
                        });
                        return;
                    }
                    handle(&buf[..n as usize], &tx);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拼一个以太网 + IPv4 + TCP 的帧
    fn frame(src: [u8; 4], dport: u16, flags: u8, opts: &[u8], payload: &[u8]) -> Vec<u8> {
        let doff = 20 + opts.len();
        assert_eq!(doff % 4, 0, "TCP options must be padded to 4 bytes");
        let mut f = vec![0u8; ETH_HDR];
        f[12] = 0x08;
        f[13] = 0x00;
        let total = 20 + doff + payload.len();
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[6] = 0x40; // DF
        ip[8] = 64; // TTL
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&src);
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[12] = ((doff / 4) as u8) << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        f.extend_from_slice(&ip);
        f.extend_from_slice(&tcp);
        f.extend_from_slice(opts);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn bpf_program_has_no_dangling_jumps() {
        let p = filter_prog();
        for (i, ins) in p.iter().enumerate() {
            // 只有跳转类(BPF_JMP)指令才用 jt/jf; ret 的这两个字段无意义
            if ins.code & 0x07 != 0x05 {
                continue;
            }
            let (jt, jf) = (i + 1 + ins.jt as usize, i + 1 + ins.jf as usize);
            assert!(jt < p.len(), "insn {i} jt out of range");
            assert!(jf < p.len(), "insn {i} jf out of range");
        }
        // 每条跳转最终都要能走到某个 ret, 不允许原地打转
        assert!(p.len() >= 3);
        // 末尾必须是 accept / drop 两条返回
        assert_eq!(p[p.len() - 1].k, 0);
        assert!(p[p.len() - 2].k > 0);
    }

    #[test]
    fn syn_options_order_is_captured() {
        // mss=1460, sackOK, timestamps, nop, wscale=7  —— Linux 的典型顺序
        let opts = [
            2, 4, 0x05, 0xb4, // mss 1460
            4, 2, // sack permitted
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // timestamps
            1, // nop
            3, 3, 7, // wscale 7
        ];
        let f = frame([172, 16, 0, 9], 443, 0x02, &opts, &[]);
        let ip = &f[ETH_HDR..];
        let tcp = &ip[20..];
        let fp = tcp_fingerprint(ip[8], "df", tcp).unwrap();
        assert_eq!(fp, "64:1460:65535:7:mss,sok,ts,nop,ws:df");
    }

    /// 造一个 IPv6 + TCP 的帧
    fn frame6(src: [u8; 16], dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR];
        f[12] = 0x86;
        f[13] = 0xdd;
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60; // version 6
        ip[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip[6] = 6; // next header = TCP
        ip[7] = 64; // hop limit
        ip[8..24].copy_from_slice(&src); // v6 源地址在 8..24, 24..40 是目的地址
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        f.extend_from_slice(&ip);
        f.extend_from_slice(&tcp);
        f.extend_from_slice(payload);
        f
    }

    /// 这张网上客户端没有 v6 流量, 真机验不了, 只能靠构造报文验。
    #[test]
    fn ipv6_frames_are_parsed_and_source_is_formatted_like_iproute() {
        let (tx, rx) = std::sync::mpsc::channel();
        let src = crate::util::parse_v6("fe80::329c:23ff:fec1:dd70").unwrap();

        // SYN -> 栈指纹, 末段标成 v6
        handle(&frame6(src, 443, 0x02, &[]), &tx);
        match rx.try_recv().expect("SYN should produce a fingerprint") {
            Event::TcpFp { ip, fp } => {
                assert_eq!(ip, "fe80::329c:23ff:fec1:dd70");
                assert!(fp.ends_with(":v6"), "got {fp}");
                assert!(fp.starts_with("64:"), "hop limit should lead: {fp}");
            }
            _ => panic!("wrong event"),
        }

        // 带载荷的 PSH -> 走 SNI 解析, 和 v4 完全同一套
        let hello = client_hello(b"api.snapcraft.io");
        handle(&frame6(src, 443, 0x18, &hello), &tx);
        match rx.try_recv().expect("ClientHello should produce a Conn") {
            Event::Conn { ip, host, via, .. } => {
                assert_eq!(ip, "fe80::329c:23ff:fec1:dd70");
                assert_eq!(host, "api.snapcraft.io");
                assert_eq!(via, "sni");
            }
            _ => panic!("wrong event"),
        }
    }

    fn client_hello(host: &[u8]) -> Vec<u8> {
        let mut ext = vec![0x00, 0x00]; // extension type server_name
        let mut sn = vec![0x00]; // name type host_name
        sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sn.extend_from_slice(host);
        let mut list = (sn.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&sn);
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut hs = vec![0x03, 0x03]; // client version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session id len
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        hs.extend_from_slice(&[0x01, 0x00]); // compression
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut rec = vec![0x16, 0x03, 0x01];
        let body_len = 4 + hs.len();
        rec.extend_from_slice(&(body_len as u16).to_be_bytes());
        rec.push(0x01); // handshake: client hello
        rec.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        rec.extend_from_slice(&hs);

        rec
    }

    #[test]
    fn tls_client_hello_sni_is_extracted() {
        assert_eq!(tls_sni(&client_hello(b"api.snapcraft.io")).unwrap(), "api.snapcraft.io");
        // 不是 ClientHello 的记录不能误报
        assert_eq!(tls_sni(b"not tls at all............................"), None);
    }

    #[test]
    fn mqtt_connect_client_id_is_extracted() {
        // CONNECT: 固定头 + 剩余长度 + "MQTT" + ver + flags + keepalive + ClientID
        let cid = b"midea_ac_3d8769";
        let mut var = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c];
        var.extend_from_slice(&(cid.len() as u16).to_be_bytes());
        var.extend_from_slice(cid);
        let mut pkt = vec![0x10u8];
        let mut n = var.len();
        loop {
            let mut b = (n % 128) as u8;
            n /= 128;
            if n > 0 {
                b |= 0x80;
            }
            pkt.push(b);
            if n == 0 {
                break;
            }
        }
        pkt.extend_from_slice(&var);
        assert_eq!(mqtt_client_id(&pkt).unwrap(), "midea_ac_3d8769");

        // 老版本协议名
        let mut p2 = pkt.clone();
        p2[2] = 0x00;
        p2[3] = 0x06;
        assert!(mqtt_client_id(&p2).is_none(), "协议名对不上就不该认");
        // 不是 CONNECT 的不能误报
        assert!(mqtt_client_id(b"GET / HTTP/1.1\r\n").is_none());
        assert!(mqtt_client_id(&[0x10]).is_none());
    }

    #[test]
    fn http_host_and_user_agent_are_extracted() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: ota.example.com:80\r\n\
                    User-Agent: Dalvik/2.1.0 (Linux; U; Android 14; Redmi Build/x)\r\n\r\n";
        let (host, ua) = http_fields(req).unwrap();
        assert_eq!(host, "ota.example.com");
        assert!(ua.contains("Android 14"), "got {ua}");
        assert_eq!(http_fields(b"\x16\x03\x01 binary junk"), None);
    }
}

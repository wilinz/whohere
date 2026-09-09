// 各采集线程 -> 主循环 的统一事件

pub enum Event {
    Dns {
        ip: String,
        domain: String,
        /// 查询类型(A/AAAA/HTTPS/PTR/SRV...)。日志里本来就有, 是一条独立信号:
        /// 只有 Apple 系统栈和现代浏览器会查 HTTPS(RR 65), Windows 严格成对发 A+AAAA。
        qtype: String,
        /// 客户端源端口。复用模式能区分"每次新建 socket"(Apple/glibc)、
        /// "常驻 socket"(Windows DNS Client) 和"端口粘死"(嵌入式栈)。
        sport: u16,
    },
    Dhcp {
        mac: String,
        ip: String,
        host: String,
        vendor: String,
        opts: String,
    },
    Mdns {
        ip: String,
        name: String,
        model: String,
        services: Vec<String>,
    },
    /// TCP SYN 的协议栈指纹
    TcpFp {
        ip: String,
        fp: String,
    },
    /// 设备主动连接的目标主机名。via="sni"(TLS ClientHello) 或 "http"(明文 Host)。
    /// 走 DoH/DoT 的设备在 DNS 那一路是完全空白的, 这里仍能看到它在连谁。
    Conn {
        ip: String,
        host: String,
        ua: String,
        via: &'static str,
    },
    /// conntrack 里看到的长连接对端
    Peer {
        ip: String,
        proto: String,
        remote: String,
        port: u16,
    },
    /// 主动端口探测的结果
    Ports {
        ip: String,
        open: Vec<u16>,
        banner: String,
    },
    Ssdp {
        ip: String,
        server: String,
    },
    /// 采集源状态变化, 用于在界面上说明"DNS 这一路到底通没通"
    SourceInfo {
        kind: &'static str,
        /// 机器可读的状态码。界面文案由 LuCI 自己映射, 守护进程不出中文。
        /// reading_log | listening | listen_failed | subscribed | disabled
        state: &'static str,
        /// 状态的参数: 路径 / 端口 / 错误原文
        info: String,
    },
}

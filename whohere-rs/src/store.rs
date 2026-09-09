// 设备档案 + 多信号融合打分 + 持久化。
//
// 隐私约定: dns_hits 只记「命中了哪条规则 / 命中几次」, 不落原始域名。
// 只有显式打开 keep_unmatched 时才会保留未命中的域名样本(用于补规则)。

use crate::rules::Rules;
use crate::util::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 一条 DNS 规则的命中记录。
///
/// 光记次数是不够的: 设备换固件、改用途、拆了重装之后, 旧行为会永远挂在档案里。
/// 记下"最后一次是什么时候", 打分时按半衰期衰减, 行为停了证据就会自己淡出。
#[derive(Serialize, Clone, Copy, Default)]
pub struct Hit {
    pub n: u32,
    pub last: u64,
}

/// 旧档案里这里存的是一个裸整数, 得能读回来
#[derive(Deserialize)]
#[serde(untagged)]
enum HitRepr {
    Count(u32),
    Full {
        n: u32,
        #[serde(default)]
        last: u64,
    },
}

impl<'de> Deserialize<'de> for Hit {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Hit, D::Error> {
        Ok(match HitRepr::deserialize(d)? {
            // last=0 表示来自旧档案, 由 Store::load 统一迁移成"当前时间"
            HitRepr::Count(n) => Hit { n, last: 0 },
            HitRepr::Full { n, last } => Hit { n, last },
        })
    }
}

impl Hit {
    /// 半衰期衰减系数。halflife=0 关闭衰减。
    pub fn decay(&self, now: u64, halflife: u64) -> f32 {
        if halflife == 0 || self.last == 0 {
            return 1.0;
        }
        let age = now.saturating_sub(self.last) as f32;
        0.5f32.powf(age / halflife as f32)
    }
}

/// 衰减到这个比例以下就不再参与打分(约 2.7 个半衰期)
pub const DECAY_MUTE: f32 = 0.15;
/// 衰减到这个比例以下直接从档案里删掉(约 4.3 个半衰期)
pub const DECAY_DROP: f32 = 0.05;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Device {
    pub mac: String,
    #[serde(default)]
    pub ipv4: Vec<String>,
    #[serde(default)]
    pub ipv6: Vec<String>,
    #[serde(default)]
    pub dhcp_name: String,
    #[serde(default)]
    pub static_name: String,
    #[serde(default)]
    pub mdns_name: String,
    #[serde(default)]
    pub mdns_model: String,
    #[serde(default)]
    pub mdns_services: Vec<String>,
    #[serde(default)]
    pub upnp_server: String,
    /// DHCP option 60
    #[serde(default)]
    pub dhcp_vendor: String,
    /// DHCP option 55, 逗号分隔的请求参数顺序
    #[serde(default)]
    pub dhcp_fp: String,
    #[serde(default)]
    pub oui: String,
    /// 用户手工备注名, 优先级最高
    #[serde(default)]
    pub note: String,
    pub first_seen: u64,
    pub last_seen: u64,
    /// 规则 id -> 命中次数
    #[serde(default)]
    pub dns_hits: BTreeMap<String, Hit>,
    /// 未命中域名样本, 仅在 keep_unmatched=1 时填充
    #[serde(default)]
    pub unmatched: BTreeMap<String, u32>,
    /// 主动探测发现的开放端口
    #[serde(default)]
    pub open_ports: Vec<u16>,
    /// SSH banner 或 HTTP Server 头
    #[serde(default)]
    pub banner: String,
    /// TCP SYN 的协议栈指纹, 见 sniff::tcp_fingerprint
    #[serde(default)]
    pub tcp_fp: String,
    /// 明文 HTTP 的 User-Agent(如今只有 IoT 设备还在发)
    #[serde(default)]
    pub http_ua: String,
    /// 明文 MQTT(1883) CONNECT 里的 ClientID, 固件自己拼的, 常带厂商和型号
    #[serde(default)]
    pub mqtt_id: String,
    /// TLS SNI / HTTP Host 命中的规则。与 dns_hits 分开记, 因为它们的可信度不同:
    /// SNI 是设备真的连上去了, 比一次 DNS 查询更硬。
    #[serde(default)]
    pub sni_hits: BTreeMap<String, Hit>,
    /// 长连接对端命中的规则。这一路专治「只挂一条长连、什么都不查」的 IoT 设备。
    #[serde(default)]
    pub peer_hits: BTreeMap<String, Hit>,
    /// 查询类型计数(A/AAAA/HTTPS/PTR/SRV...)。与域名内容无关的一路信号:
    /// 只有 Apple 系统栈和现代浏览器查 HTTPS(RR 65), Windows 严格成对发 A+AAAA。
    #[serde(default)]
    pub qtypes: BTreeMap<String, u32>,
    /// 最近若干次查询的源端口。实测各家系统都是每次查询换一个临时端口,
    /// 判别力接近于零, 留着只为认出真正把端口写死的嵌入式栈。
    #[serde(default)]
    pub dns_ports: Vec<u16>,
    /// 同一域名的 A 与 AAAA 紧挨着发出的次数。这是 Windows 解析器的标志行为,
    /// 只存计数不存域名 —— 域名比对在内存里做完就丢。
    #[serde(default)]
    pub dns_pair_a4: u32,
    /// 同一域名的 A 与 HTTPS(RR 65) 紧挨着发出的次数, Apple 系统栈 / 现代浏览器
    #[serde(default)]
    pub dns_pair_https: u32,

    #[serde(skip)]
    pub online: bool,
    #[serde(skip)]
    pub iface: String,
    #[serde(skip)]
    pub band: String,
    #[serde(skip)]
    pub signal: Option<i32>,
}

#[derive(Serialize, Clone)]
pub struct Ev {
    pub source: String,
    pub detail: String,
    /// 这条证据最后一次被观察到距今多少秒(0 = 不适用)。
    /// 只给秒数, "3 天前"这种文案由界面自己排。
    pub age: u64,
    /// DNS 证据专用: heartbeat=设备自动发起(可信) / service / web=用户主动访问(噪声)
    pub kind: String,
    /// 可以是负数(反证)
    pub weight: i32,
}

#[derive(Serialize, Default, Clone)]
pub struct Ident {
    pub brand: String,
    pub os: String,
    pub dtype: String,
    pub model: String,
    /// 虚拟化平台(如 "Proxmox 虚拟机"), 与品牌/类型正交
    pub platform: String,
    pub confidence: u32,
    pub evidence: Vec<Ev>,
}

/// 一条信号的贡献
struct Sig {
    source: &'static str,
    detail: String,
    age: u64,
    brand: String,
    os: String,
    dtype: String,
    model: String,
    platform: String,
    kind: String,
    weight: f32,
}

/// 哪些证据可以独立立住结论。
/// web  = 用户主动访问的网页 / 可能被转发的浏览器 UA
/// weak = 大量设备照抄的通用值(比如 DHCP 里的 "MSFT 5.0")
fn establishes(kind: &str) -> bool {
    kind != "web" && kind != "weak"
}

fn top(map: &BTreeMap<String, f32>) -> (String, f32, f32) {
    let mut v: Vec<(&String, &f32)> = map.iter().collect();
    v.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    let first = v
        .first()
        .map(|(k, s)| ((*k).clone(), **s))
        .unwrap_or_default();
    let second = v.get(1).map(|(_, s)| **s).unwrap_or(0.0);
    (first.0, first.1, second)
}

/// 没有信息量的主机名: 设备把接口名或系统默认值当主机名报了上来。
/// 与其显示 "android"/"wlan0", 不如退回 IP —— 至少 IP 能对上人。
/// 注意这只影响显示名, 主机名规则该怎么匹配还怎么匹配。
fn junk_name(n: &str) -> bool {
    matches!(
        n.to_ascii_lowercase().as_str(),
        // "mac" 是 macOS 默认的 DHCP 主机名, 跟 "android" 一样没有信息量;
        // 这类设备的 mDNS 名(yedemacbook-air)反而是用户起的
        "android"
            | "mac"
            | "localhost"
            | "localhost.localdomain"
            | "unknown"
            | "null"
            | "-"
            | "device"
            | "wlan0"
            | "wlan1"
            | "eth0"
            | "eth1"
            | "br-lan"
    )
}

impl Device {
    pub fn best_name(&self) -> String {
        // DHCP option 12 排在 mDNS 前面: mDNS 的 .local 主机名经常是系统默认值
        // (安卓一律报 "android")、被小写、或者带上去重后缀("...-2"), 而 DHCP
        // 主机名是设备自报的那个用户可见名字(Redmi-Note-13-5G)。
        for c in [
            &self.note,
            &self.static_name,
            &self.dhcp_name,
            &self.mdns_name,
        ] {
            if !c.is_empty() && !junk_name(c) {
                return c.clone();
            }
        }
        // 只有 v6 的设备(实测占多数)退回显示 v6 地址, 比裸 MAC 好认
        self.ipv4
            .first()
            .or_else(|| self.ipv6.iter().find(|a| !a.starts_with("fe80")))
            .or_else(|| self.ipv6.first())
            .cloned()
            .unwrap_or_else(|| self.mac.clone())
    }

    pub fn random_mac(&self) -> bool {
        is_random_mac(&self.mac)
    }

    /// 端口环形缓冲区容量。16 个足够看出复用模式, 又不会让档案变大。
    pub const PORT_RING: usize = 16;

    pub fn dns_samples(&self) -> u32 {
        self.qtypes.values().sum()
    }

    pub fn qtype_ratio(&self, t: &str) -> f32 {
        let n = self.dns_samples();
        if n == 0 {
            return 0.0;
        }
        *self.qtypes.get(t).unwrap_or(&0) as f32 / n as f32
    }

    /// 源端口离散度: 不同端口数 / 样本数。
    /// 1.0 = 每次查询新开 socket(Apple mDNSResponder、glibc)
    /// 0.5 = 每次 getaddrinfo 一个 socket, A/AAAA 共用
    /// ≤0.2 = 常驻 socket(Windows DNS Client) 或端口粘死(嵌入式栈)
    pub fn port_spread(&self) -> Option<f32> {
        if self.dns_ports.len() < 8 {
            return None;
        }
        let mut u: Vec<u16> = self.dns_ports.clone();
        u.sort_unstable();
        u.dedup();
        Some(u.len() as f32 / self.dns_ports.len() as f32)
    }

    /// 成对率: 一次配对占掉两条查询, 所以乘 2 再除样本数
    pub fn pair_a4_rate(&self) -> f32 {
        let n = self.dns_samples();
        if n == 0 {
            0.0
        } else {
            (self.dns_pair_a4 * 2) as f32 / n as f32
        }
    }

    pub fn pair_https_rate(&self) -> f32 {
        let n = self.dns_samples();
        if n == 0 {
            0.0
        } else {
            (self.dns_pair_https * 2) as f32 / n as f32
        }
    }

    pub fn record_dns_shape(&mut self, qtype: &str, sport: u16) {
        if !qtype.is_empty() {
            *self.qtypes.entry(qtype.to_string()).or_insert(0) += 1;
        }
        if sport != 0 {
            self.dns_ports.push(sport);
            let n = self.dns_ports.len();
            if n > Self::PORT_RING {
                self.dns_ports.drain(..n - Self::PORT_RING);
            }
        }
    }

    fn signals(&self, r: &Rules, halflife: u64) -> Vec<Sig> {
        let t = now();
        let mut out: Vec<Sig> = Vec::new();

        // --- DHCP option 60: 很多设备直接自报家门, 最强的单条信号 ---
        if !self.dhcp_vendor.is_empty() {
            if let Some(m) = r.match_vendor(&self.dhcp_vendor) {
                // android-dhcp-14 -> 顺手把大版本号抠出来
                let os = if m.id == "vc.android" {
                    let ver: String = self
                        .dhcp_vendor
                        .chars()
                        .skip_while(|c| !c.is_ascii_digit())
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    if ver.is_empty() {
                        m.os.clone()
                    } else {
                        format!("Android {ver}")
                    }
                } else {
                    m.os.clone()
                };
                out.push(Sig {
                    source: "dhcp60",
                    detail: self.dhcp_vendor.clone(),
                    brand: m.brand.clone(),
                    os,
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    age: 0,
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- DHCP option 55 指纹 (顺序敏感); 近似命中降权 ---
        if !self.dhcp_fp.is_empty() {
            if let Some(m) = r.match_dhcp_fp(&self.dhcp_fp) {
                let exact = m.value == self.dhcp_fp;
                out.push(Sig {
                    source: "dhcp55",
                    // "~" 表示近似命中; 具体怎么措辞由界面决定
                    detail: format!("{}{}", self.dhcp_fp, if exact { "" } else { " ~" }),
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    age: 0,
                    // 近似命中只能给已经立住的结论加分, 不能自己下结论 —— option 55 的
                    // 参数顺序在不同厂商间大量重合, 实测一台 TP-LINK 摄像机
                    // 就因近似命中 Windows 指纹而被判成微软。
                    kind: if exact { m.kind.clone() } else { "weak".into() },
                    weight: if exact {
                        m.weight as f32
                    } else {
                        m.weight as f32 * 0.5
                    },
                });
            }
        }

        // --- mDNS 型号串: 唯一能直接给出具体型号的信号 ---
        if !self.mdns_model.is_empty() {
            let m = r.match_model(&self.mdns_model);
            out.push(Sig {
                source: "mdns",
                detail: format!("model={}", self.mdns_model),
                brand: m.map(|x| x.brand.clone()).unwrap_or_default(),
                os: m.map(|x| x.os.clone()).unwrap_or_default(),
                dtype: m.map(|x| x.dtype.clone()).unwrap_or_default(),
                model: self.mdns_model.clone(),
                platform: String::new(),
                age: 0,
                kind: m.map(|x| x.kind.clone()).unwrap_or_default(),
                weight: m.map(|x| x.weight as f32).unwrap_or(3.0),
            });
        }
        for svc in &self.mdns_services {
            if let Some(m) = r.match_service(svc) {
                out.push(Sig {
                    source: "mdns",
                    detail: svc.clone(),
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    age: 0,
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- UPnP/SSDP SERVER 头 ---
        if !self.upnp_server.is_empty() {
            if let Some(m) = r.match_upnp(&self.upnp_server) {
                out.push(Sig {
                    source: "ssdp",
                    detail: self.upnp_server.clone(),
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    age: 0,
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- 主机名 ---
        let hn = if !self.dhcp_name.is_empty() {
            self.dhcp_name.clone()
        } else {
            self.mdns_name.clone()
        };
        if !hn.is_empty() {
            for m in r.match_hostname(&hn) {
                out.push(Sig {
                    source: "hostname",
                    detail: hn.clone(),
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    age: 0,
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- DNS 心跳域名; 次数只给有限加成, 防止一条规则刷爆全局 ---
        // 权重再按最后一次命中的时间衰减: 行为停了, 证据就该淡出。
        for (id, hit) in &self.dns_hits {
            if let Some(rule) = r.dns_by_id(id) {
                let f = hit.decay(t, halflife);
                if f < DECAY_MUTE {
                    continue;
                }
                let bonus = hit.n.min(30) as f32 / 10.0;
                out.push(Sig {
                    source: "dns",
                    detail: format!("{} ×{}", rule.label(), hit.n),
                    age: t.saturating_sub(hit.last),
                    brand: rule.brand.clone(),
                    os: rule.os.clone(),
                    dtype: rule.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    kind: rule.kind.clone(),
                    weight: (rule.weight as f32 + bonus) * f,
                });
            }
        }

        // --- TLS SNI / HTTP Host ---
        // 走 DoH/DoT 的设备在 DNS 那一路完全空白, 但 ClientHello 里的 SNI 仍是明文,
        // 于是同一份域名规则库在这里原样生效。而且 SNI 比 DNS 查询更硬 ——
        // 查了不一定连, 发了 ClientHello 是真的连上去了, 所以权重给满不打折。
        for (id, hit) in &self.sni_hits {
            if let Some(rule) = r.dns_by_id(id) {
                let f = hit.decay(t, halflife);
                if f < DECAY_MUTE {
                    continue;
                }
                let bonus = hit.n.min(30) as f32 / 10.0;
                out.push(Sig {
                    source: "sni",
                    detail: format!("{} ×{}", rule.label(), hit.n),
                    age: t.saturating_sub(hit.last),
                    brand: rule.brand.clone(),
                    os: rule.os.clone(),
                    dtype: rule.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    kind: rule.kind.clone(),
                    weight: (rule.weight as f32 + bonus) * f,
                });
            }
        }

        // --- MQTT ClientID ---
        if !self.mqtt_id.is_empty() {
            for m in r.match_mqtt(&self.mqtt_id) {
                out.push(Sig {
                    source: "mqtt",
                    detail: self.mqtt_id.clone(),
                    age: 0,
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: m.platform.clone(),
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- 长连接对端 ---
        for (id, hit) in &self.peer_hits {
            if let Some(rule) = r.peer_by_id(id) {
                let f = hit.decay(t, halflife);
                if f < DECAY_MUTE {
                    continue;
                }
                out.push(Sig {
                    source: "peer",
                    detail: format!(
                        "{}/{} ×{}",
                        if rule.proto.is_empty() { "tcp/udp" } else { &rule.proto },
                        rule.port,
                        hit.n
                    ),
                    age: t.saturating_sub(hit.last),
                    brand: rule.brand.clone(),
                    os: rule.os.clone(),
                    dtype: rule.dtype.clone(),
                    model: String::new(),
                    platform: String::new(),
                    kind: rule.kind.clone(),
                    weight: rule.weight as f32 * f,
                });
            }
        }

        // --- TCP SYN 协议栈指纹 ---
        // 完全不依赖设备查了什么域名, 也不受随机 MAC 和加密 DNS 影响。
        if !self.tcp_fp.is_empty() {
            if let Some(m) = r.match_tcp(&self.tcp_fp) {
                out.push(Sig {
                    source: "tcp",
                    detail: self.tcp_fp.clone(),
                    age: 0,
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: m.platform.clone(),
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- 明文 HTTP 的 User-Agent ---
        if !self.http_ua.is_empty() {
            for m in r.match_ua(&self.http_ua) {
                out.push(Sig {
                    source: "ua",
                    detail: self.http_ua.clone(),
                    age: 0,
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: m.platform.clone(),
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- 开放端口 / 服务 banner ---
        // 唯一的主动信号。对既不广播、也不用本机 DNS 的安静服务器, 这是仅剩的一路。
        for p in &self.open_ports {
            if let Some(m) = r.match_port(*p) {
                out.push(Sig {
                    source: "port",
                    detail: format!("{p}/tcp"),
                    age: 0,
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: m.platform.clone(),
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }
        if !self.banner.is_empty() {
            for m in r.match_banner(&self.banner) {
                out.push(Sig {
                    source: "banner",
                    detail: self.banner.clone(),
                    age: 0,
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: m.platform.clone(),
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- 多厂商心跳 = 这台设备在替别人转发 DNS ---
        //
        // 心跳域名是设备固件自己发的, 且各家只查各家的。同一台机器上同时出现
        // 小米和华为的心跳, 物理上说不通 —— 唯一的解释是它下面挂着别的设备,
        // 由它代为解析。刷了第三方固件、改了主机名的 AP 就是这么露馅的:
        // 厂商特征全没了, 但"帮别人查 DNS"这个行为藏不住。
        //
        // 注意只能判到"网络设备"为止, 不能判成路由器: 实测这台就是一台纯 AP
        // (dhcp.lan.ignore=1, 不发 DHCP), 只是 odhcpd 的 RA 仍在把自己当
        // 递归 DNS 广播出去。转发者也可能是旁路由、Pi-hole 或带 NAT 的宿主机。
        let hb_brands: std::collections::BTreeSet<String> = out
            .iter()
            .filter(|s| {
                (s.source == "dns" || s.source == "sni")
                    && s.kind == "heartbeat"
                    && !s.brand.is_empty()
            })
            .map(|s| s.brand.clone())
            .collect();
        let fwd = r.forwarder.as_ref();
        if hb_brands.len() >= fwd.map_or(usize::MAX, |f| f.min_brands) {
            // 一旦确定它在转发, 这台设备的 DNS 记录讲的就是"下游有哪些设备",
            // 而不是"它自己是什么"。所以整条 DNS 通路的归属全部作废, 只留证据
            // 给人看; 它自己的身份交回给 OUI / DHCP / mDNS 这些不会串台的信号。
            for sig in out
                .iter_mut()
                .filter(|s| s.source == "dns" || s.source == "sni")
            {
                sig.brand.clear();
                sig.os.clear();
                sig.dtype.clear();
            }
            out.push(Sig {
                source: "forwarder",
                detail: hb_brands.iter().cloned().collect::<Vec<_>>().join("/"),
                brand: String::new(),
                os: String::new(),
                dtype: fwd.map(|f| f.dtype.clone()).unwrap_or_default(),
                model: String::new(),
                platform: String::new(),
                age: 0,
                kind: "stack".to_string(),
                weight: fwd.map_or(0.0, |f| f.weight as f32),
            });
        }

        // --- 协议栈画像: 不看查了什么, 只看怎么查 ---
        for m in r.match_stack(self) {
            out.push(Sig {
                source: "stack",
                detail: if m.desc.is_empty() {
                    m.id.clone()
                } else {
                    m.desc.clone()
                },
                brand: m.brand.clone(),
                os: m.os.clone(),
                dtype: m.dtype.clone(),
                model: String::new(),
                platform: String::new(),
                age: 0,
                kind: "stack".to_string(),
                weight: m.weight as f32,
            });
        }

        // --- OUI ---
        // 随机 MAC 下 OUI 毫无意义, 直接不采信。
        // 更重要的是: 绝不把 OUI 厂商名原样当品牌。网卡/整机的 OUI 常常是代工厂
        // (鸿海、世纪新阳……), 原样塞进品牌桶会把 "DESKTOP-xxx → Windows" 这种
        // 真正靠谱的判定挤掉。只有能归一化到消费品牌时才低权重参与打分,
        // 其余情况仅作为"网卡厂商"展示。
        if !self.oui.is_empty() && !self.random_mac() {
            if let Some(m) = r.match_oui_brand(&self.oui) {
                out.push(Sig {
                    source: "oui",
                    detail: self.oui.clone(),
                    brand: m.brand.clone(),
                    os: m.os.clone(),
                    dtype: m.dtype.clone(),
                    model: String::new(),
                    platform: m.platform.clone(),
                    age: 0,
                    kind: m.kind.clone(),
                    weight: m.weight as f32,
                });
            }
        }

        // --- 反证: 负权重 ---
        // 放在最后, 因为轻重要看别的信号已经给出的品牌。
        let prov_brand = out
            .iter()
            .filter(|s| !s.brand.is_empty() && establishes(&s.kind))
            .max_by(|a, b| a.weight.total_cmp(&b.weight))
            .map(|s| s.brand.clone())
            .unwrap_or_default();
        for pen in &r.penalty {
            let hit = match pen.cond.as_str() {
                // 特权端口: 手机上的应用没 root 绑不了 <1024
                "privileged_port" => self.open_ports.iter().any(|p| *p < 1024),
                _ => false,
            };
            if !hit {
                continue;
            }
            let soft = pen.soften_brands.iter().any(|b| *b == prov_brand);
            let w = if soft { pen.soften_weight } else { pen.weight };
            if w == 0 {
                continue;
            }
            let ports: Vec<String> = self
                .open_ports
                .iter()
                .filter(|p| **p < 1024)
                .map(|p| p.to_string())
                .collect();
            out.push(Sig {
                source: "penalty",
                detail: format!(
                    "开着特权端口 {} —— 不像{}{}",
                    ports.join(","),
                    pen.dtype,
                    if soft { "(该品牌易 root, 已减轻)" } else { "" }
                ),
                age: 0,
                brand: pen.brand.clone(),
                os: pen.os.clone(),
                dtype: pen.dtype.clone(),
                model: String::new(),
                platform: String::new(),
                kind: String::new(),
                weight: w as f32,
            });
        }

        out
    }

    pub fn identify(&self, r: &Rules, halflife: u64) -> Ident {
        let sigs = self.signals(r, halflife);
        let (mut brands, mut oses, mut types) = (
            BTreeMap::<String, f32>::new(),
            BTreeMap::<String, f32>::new(),
            BTreeMap::<String, f32>::new(),
        );
        let mut model = String::new();
        let mut model_w = 0.0f32;
        let mut platform = String::new();
        let mut platform_w = 0.0f32;
        // kind=web 的域名是用户主动访问的网页(比如有人打开了 microsoft.com),
        // 安卓机、Linux 服务器一样会访问。这类信号只能给已经被别的信号立住的
        // 结论加分, 绝不能自己单独定结论 —— 否则一次浏览就能把设备判成别的牌子。
        let solid_brands: std::collections::BTreeSet<&String> = sigs
            .iter()
            .filter(|s| establishes(&s.kind) && !s.brand.is_empty())
            .map(|s| &s.brand)
            .collect();
        let solid_oses: std::collections::BTreeSet<&String> = sigs
            .iter()
            .filter(|s| establishes(&s.kind) && !s.os.is_empty())
            .map(|s| &s.os)
            .collect();

        for s in &sigs {
            if !s.brand.is_empty() && solid_brands.contains(&s.brand) {
                *brands.entry(s.brand.clone()).or_default() += s.weight;
            }
            if !s.os.is_empty() && solid_oses.contains(&s.os) {
                *oses.entry(s.os.clone()).or_default() += s.weight;
            }
            if !s.dtype.is_empty() && establishes(&s.kind) {
                *types.entry(s.dtype.clone()).or_default() += s.weight;
            }
            if !s.model.is_empty() && s.weight > model_w {
                model = s.model.clone();
                model_w = s.weight;
            }
            if !s.platform.is_empty() && s.weight > platform_w {
                platform = s.platform.clone();
                platform_w = s.weight;
            }
        }

        // 被扣成非正数的桶不是结论, 直接丢掉 —— 否则一个只剩负分的
        // "手机" 仍会被 top() 选出来
        brands.retain(|_, v| *v > 0.0);
        oses.retain(|_, v| *v > 0.0);
        types.retain(|_, v| *v > 0.0);

        // 上下位归并: Proxmox VE 就是一种 Debian, 让它们相加而不是分票
        let fold = |m: &mut BTreeMap<String, f32>| {
            for s in &r.subsume {
                if let (true, Some(g)) = (m.contains_key(&s.specific), m.get(&s.generic).copied()) {
                    *m.get_mut(&s.specific).unwrap() += g;
                    m.remove(&s.generic);
                }
            }
        };
        fold(&mut brands);
        fold(&mut oses);

        let (brand, bs, b2) = top(&brands);
        let (os, os_s, os2) = top(&oses);
        let (dtype, _, _) = top(&types);

        // 置信度 = 证据量的饱和度 × 与第二名的领先程度。
        // 领先度要看真正提供了结论的那个桶: 像 "DESKTOP-xxx" 只定 OS 不定品牌,
        // 若一律拿品牌桶算, 一个很确定的 Windows 判定会被误压成低置信。
        let (lead_top, lead_2nd) = if bs >= os_s { (bs, b2) } else { (os_s, os2) };
        let lead = if lead_top + lead_2nd > 0.0 {
            lead_top / (lead_top + lead_2nd)
        } else {
            1.0
        };
        let sat = {
            let s = bs.max(os_s);
            s / (s + 6.0)
        };
        let conf = (100.0 * sat * lead).round().clamp(0.0, 99.0) as u32;

        let mut evidence: Vec<Ev> = sigs
            .iter()
            .map(|s| Ev {
                source: s.source.to_string(),
                detail: s.detail.clone(),
                age: s.age,
                kind: s.kind.clone(),
                weight: s.weight.round() as i32,
            })
            .collect();
        evidence.sort_by(|a, b| b.weight.cmp(&a.weight));
        // 20 条: 12 条时权重低的栈画像会被苹果那种证据多的设备挤掉, 看不见就没法验证
        evidence.truncate(20);

        Ident {
            brand,
            os,
            dtype,
            model,
            platform,
            confidence: if bs == 0.0 && os_s == 0.0 { 0 } else { conf },
            evidence,
        }
    }
}

#[derive(Default)]
pub struct Store {
    pub devs: BTreeMap<String, Device>,
    pub dirty: bool,
    path: String,
}

impl Store {
    pub fn load(path: &str) -> Store {
        let mut devs: BTreeMap<String, Device> = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        // 旧档案没有时间戳, 当成"刚刚命中"处理 —— 否则一升级所有证据立刻过期
        let t = now();
        for d in devs.values_mut() {
            for h in d.dns_hits.values_mut() {
                if h.last == 0 {
                    h.last = t;
                }
            }
        }
        Store {
            devs,
            dirty: false,
            path: path.to_string(),
        }
    }

    pub fn get(&mut self, mac: &str) -> &mut Device {
        let now = now();
        self.dirty = true;
        self.devs.entry(mac.to_string()).or_insert_with(|| Device {
            mac: mac.to_string(),
            first_seen: now,
            last_seen: now,
            ..Default::default()
        })
    }

    /// 按地址找设备, 找不到时再试着从 v6 的 EUI-64 接口标识里反推 MAC。
    ///
    /// 为什么需要: 邻居表是会过期的, 而抓包/DNS 看到的地址可能一时没有对应条目。
    /// SLAAC 的 EUI-64 地址里本来就嵌着网卡 MAC, 不查表也能还原 —— 反推成功
    /// 顺手把这个地址补进设备档案, 下次直接命中。
    pub fn resolve_ip(&mut self, ip: &str) -> Option<String> {
        if let Some(m) = self.by_ip(ip) {
            return Some(m);
        }
        let mac = crate::util::mac_from_eui64(ip)?;
        if !self.devs.contains_key(&mac) {
            return None;
        }
        let d = self.get(&mac);
        if !d.ipv6.iter().any(|x| x == ip) {
            d.ipv6.push(ip.to_string());
        }
        Some(mac)
    }

    pub fn by_ip(&self, ip: &str) -> Option<String> {
        self.devs
            .values()
            .find(|d| d.ipv4.iter().any(|x| x == ip) || d.ipv6.iter().any(|x| x == ip))
            .map(|d| d.mac.clone())
    }

    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        if let Ok(js) = serde_json::to_vec(&self.devs) {
            if atomic_write(&self.path, &js).is_ok() {
                self.dirty = false;
            }
        }
    }

    /// 丢弃过久未见的设备, 以及衰减殆尽的 DNS 命中记录
    pub fn prune(&mut self, max_age: u64, halflife: u64) {
        let t = now();
        let cutoff = t.saturating_sub(max_age);
        let before = self.devs.len();
        for d in self.devs.values_mut() {
            let n = d.dns_hits.len();
            d.dns_hits.retain(|_, h| h.decay(t, halflife) >= DECAY_DROP);
            if d.dns_hits.len() != n {
                self.dirty = true;
            }
        }
        self.devs.retain(|_, d| d.last_seen >= cutoff);
        if self.devs.len() != before {
            self.dirty = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86400;

    #[test]
    fn decay_halves_each_halflife() {
        let t = 1_000_000_000u64;
        let h = Hit { n: 5, last: t };
        assert!((h.decay(t, 7 * DAY) - 1.0).abs() < 1e-6);
        assert!((h.decay(t + 7 * DAY, 7 * DAY) - 0.5).abs() < 1e-6);
        assert!((h.decay(t + 14 * DAY, 7 * DAY) - 0.25).abs() < 1e-6);
        // halflife=0 表示关闭衰减
        assert_eq!(h.decay(t + 999 * DAY, 0), 1.0);
    }

    #[test]
    fn legacy_bare_int_hits_still_load() {
        let d: Device = serde_json::from_str(
            r#"{"mac":"aa:bb:cc:dd:ee:ff","first_seen":1,"last_seen":2,
                "dns_hits":{"ubu.snap":7}}"#,
        )
        .unwrap();
        let h = d.dns_hits.get("ubu.snap").unwrap();
        assert_eq!(h.n, 7);
        // 没有时间戳, 交给 Store::load 迁移; 在此之前不衰减
        assert_eq!(h.last, 0);
        assert_eq!(h.decay(9_999_999, 7 * DAY), 1.0);
    }

    fn rules_with_one_dns_rule() -> Rules {
        serde_json::from_str(
            r#"{"dns":[{"id":"x.test","suffix":"x.test","os":"TestOS",
                        "kind":"heartbeat","weight":10}]}"#,
        )
        .unwrap()
    }

    fn dev_with_hit(age: u64) -> Device {
        let mut d = Device {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ..Default::default()
        };
        d.dns_hits.insert(
            "x.test".into(),
            Hit {
                n: 3,
                last: now().saturating_sub(age),
            },
        );
        d
    }

    #[test]
    fn stale_evidence_fades_out_of_scoring() {
        let r = rules_with_one_dns_rule();
        let fresh = dev_with_hit(0).identify(&r, 7 * DAY);
        assert_eq!(fresh.os, "TestOS");

        // 一个半衰期: 还在, 但置信度更低
        let aged = dev_with_hit(7 * DAY).identify(&r, 7 * DAY);
        assert_eq!(aged.os, "TestOS");
        assert!(
            aged.confidence < fresh.confidence,
            "confidence must drop after decay: {} vs {}",
            aged.confidence,
            fresh.confidence
        );

        // 三个半衰期(12.5%)已低于 DECAY_MUTE, 不再参与判定
        let stale = dev_with_hit(21 * DAY).identify(&r, 7 * DAY);
        assert_eq!(stale.os, "", "decayed evidence must not decide anything");
        assert_eq!(stale.confidence, 0);
    }

    #[test]
    fn prune_drops_fully_decayed_hits() {
        let mut st = Store::default();
        st.devs.insert("a".into(), dev_with_hit(0));
        st.devs.insert("b".into(), dev_with_hit(60 * DAY));
        for d in st.devs.values_mut() {
            d.last_seen = now();
        }
        st.prune(30 * DAY, 7 * DAY);
        assert_eq!(st.devs["a"].dns_hits.len(), 1, "fresh hits must be kept");
        assert_eq!(st.devs["b"].dns_hits.len(), 0, "fully decayed hits must be dropped");
    }

    fn two_vendor_heartbeat_device() -> Device {
        let mut d = Device {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ..Default::default()
        };
        let t = now();
        d.dns_hits.insert("v1.hb".into(), Hit { n: 3, last: t });
        d.dns_hits.insert("v2.hb".into(), Hit { n: 3, last: t });
        d
    }

    const TWO_VENDOR_RULES: &str = r#"{"dns":[
        {"id":"v1.hb","suffix":"a.test","brand":"VendorA","kind":"heartbeat","weight":10},
        {"id":"v2.hb","suffix":"b.test","brand":"VendorB","kind":"heartbeat","weight":10}]"#;

    #[test]
    fn forwarder_verdict_comes_from_rules_data() {
        let d = two_vendor_heartbeat_device();

        // 规则库里配了 forwarder: 判成配置里写的类型, 且 DNS 的品牌归属全部作废
        let with: Rules = serde_json::from_str(&format!(
            "{TWO_VENDOR_RULES},\"forwarder\":{{\"type\":\"GW\",\"weight\":8}}}}"
        ))
        .unwrap();
        let id = d.identify(&with, 0);
        assert_eq!(id.dtype, "GW");
        assert_eq!(id.brand, "", "forwarding devices must not inherit downstream brands");

        // 没配 forwarder: 判据关闭, DNS 品牌照常参与打分
        let without: Rules = serde_json::from_str(&format!("{TWO_VENDOR_RULES}}}")).unwrap();
        let id = d.identify(&without, 0);
        assert_eq!(id.dtype, "");
        assert!(
            id.brand == "VendorA" || id.brand == "VendorB",
            "without the rule DNS brands must still count, got {:?}",
            id.brand
        );
    }

    #[test]
    fn subsume_merges_scores_instead_of_splitting() {
        // 一台 PVE 宿主机: banner 说 Debian, 端口说 Proxmox VE, 权重相同。
        // 没有上下位关系时两者平票, 置信度被压到很低。
        let mut d = Device {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ..Default::default()
        };
        d.banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3".into();
        d.open_ports = vec![8006];

        let base = r#"{"banner":[{"id":"b.deb","mode":"contains","value":"debian","os":"Debian","weight":10}],
                       "port":[{"id":"p.pve","port":8006,"os":"Proxmox VE","weight":10}]"#;

        let split: Rules = serde_json::from_str(&format!("{base}}}")).unwrap();
        let a = d.identify(&split, 0);

        let merged: Rules = serde_json::from_str(&format!(
            r#"{base},"subsume":[{{"specific":"Proxmox VE","generic":"Debian"}}]}}"#
        ))
        .unwrap();
        let b = d.identify(&merged, 0);

        assert_eq!(b.os, "Proxmox VE", "the more specific value must win");
        assert!(
            b.confidence > a.confidence,
            "merging must raise confidence: {} vs {}",
            b.confidence,
            a.confidence
        );
    }

    #[test]
    fn privileged_port_penalty_cancels_a_phone_verdict() {
        // 一台被域名规则判成手机、却监听着 80 端口的设备。
        // 手机上的应用没 root 绑不了 <1024, 所以"手机"这个结论应当被否掉。
        let rules_src = r#"{
            "dns":[{"id":"v.phone","suffix":"a.test","brand":"V","os":"VOS",
                    "type":"手机","kind":"heartbeat","weight":10}],
            "penalty":[{"id":"p1","cond":"privileged_port","type":"手机","weight":-12}]}"#;
        let r: Rules = serde_json::from_str(rules_src).unwrap();

        let mut d = Device {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ..Default::default()
        };
        d.dns_hits.insert(
            "v.phone".into(),
            Hit { n: 2, last: now() },
        );

        assert_eq!(d.identify(&r, 0).dtype, "手机", "没开端口时应当判成手机");

        d.open_ports = vec![80, 443];
        let id = d.identify(&r, 0);
        assert_eq!(id.dtype, "", "开着特权端口就不该再判成手机");
        // 品牌和系统不受影响 —— 反证只针对"类型"这一维
        assert_eq!(id.brand, "V");
        assert_eq!(id.os, "VOS");

        // 只开高位端口则不触发
        d.open_ports = vec![8080, 32400];
        assert_eq!(d.identify(&r, 0).dtype, "手机");
    }

    #[test]
    fn penalty_is_softened_for_easily_rooted_brands() {
        let src = r#"{
            "dns":[
              {"id":"mi","suffix":"a.test","brand":"小米","type":"手机","kind":"heartbeat","weight":10},
              {"id":"hw","suffix":"b.test","brand":"华为","type":"手机","kind":"heartbeat","weight":10}],
            "penalty":[{"id":"p","cond":"privileged_port","type":"手机",
                        "weight":-12,"soften_brands":["小米"],"soften_weight":-3}]}"#;
        let r: Rules = serde_json::from_str(src).unwrap();

        let mk = |rule: &str| {
            let mut d = Device {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                open_ports: vec![80],
                ..Default::default()
            };
            d.dns_hits.insert(rule.into(), Hit { n: 1, last: now() });
            d
        };

        // 小米: 官方可解锁, root 后能绑特权端口 -> 只轻扣, 结论保住
        assert_eq!(mk("mi").identify(&r, 0).dtype, "手机");
        // 华为: bootloader 锁死, 反证依然硬 -> 结论被否掉
        assert_eq!(mk("hw").identify(&r, 0).dtype, "");
    }

    #[test]
    fn dhcp_name_beats_mdns_and_junk_is_skipped() {
        let mut d = Device::default();
        d.dhcp_name = "Redmi-Note-13-5G".into();
        d.mdns_name = "android".into();
        assert_eq!(d.best_name(), "Redmi-Note-13-5G");

        // DHCP 报的是接口名这种垃圾时, 退到 mDNS
        d.dhcp_name = "wlan0".into();
        d.mdns_name = "kitchen-speaker".into();
        assert_eq!(d.best_name(), "kitchen-speaker");

        // macOS 默认报 "Mac", 信息量还不如它的 mDNS 名
        d.dhcp_name = "Mac".into();
        d.mdns_name = "yedemacbook-air".into();
        assert_eq!(d.best_name(), "yedemacbook-air");

        // 两个都没信息量 -> 退回 IP
        d.dhcp_name = "wlan0".into();
        d.mdns_name = "localhost".into();
        d.ipv4 = vec!["172.16.1.72".into()];
        assert_eq!(d.best_name(), "172.16.1.72");

        // 用户备注永远最优先
        d.note = "厨房热水器".into();
        assert_eq!(d.best_name(), "厨房热水器");
    }
}

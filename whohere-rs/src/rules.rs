// 指纹规则库: 域名后缀 / 主机名 / mDNS 服务 / mDNS 型号 / UPnP SERVER 头。
//
// 匹配设计要点:
//  * 域名走"最长后缀优先", 所以 captive.apple.com(强心跳) 会盖过 apple.com(弱网页),
//    同一次查询只计一条规则的分, 不会重复加权。
//  * weight 语义: 9~10 = 设备自动发起、几乎只有该品牌会发的心跳;
//    6~8 = 厂商云服务 / 报文级栈指纹; 1~3 = 用户可能主动访问的网页, 只作噪声参考。
//  * 主机名单独压在 3~6: 它是**用户随手能改的**, 跟固件自动发出来的信号
//    不是一个可信度。有人把台式机命名成 iphone 不该就被判成苹果。
//    没有别的信号时它仍能立住结论, 但一旦和固件级证据冲突, 后者说了算。

use serde::Deserialize;
use std::collections::HashMap;

fn dw() -> u32 {
    5
}

#[derive(Deserialize, Clone)]
pub struct DnsRule {
    pub id: String,
    #[serde(default)]
    pub suffix: String,
    /// 子串匹配。用来表达"协议行为"而不是"品牌域名": wpad. 是 Windows 的
    /// 代理自动发现, _dns-sd._udp 是 Apple 的 DNS-SD 浏览 —— 这类查询跟
    /// 搜索域拼在一起, 后缀匹配抓不住。
    #[serde(default)]
    pub contains: String,
    /// 前缀匹配。wpad. 这类要锚在开头, 否则 mywpad.com 也会被 contains 撞上。
    #[serde(default)]
    pub prefix: String,
    /// 限定查询类型。例: APT 会对镜像源发 SRV, 同一个域名的 A 查询就没这个含义。
    #[serde(default)]
    pub qtype: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, rename = "type")]
    pub dtype: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "dw")]
    pub weight: u32,
}

/// 协议栈画像: 不看查了什么域名, 只看"怎么查"。
///
/// 对只查过几个大众域名的设备(域名规则一条都命不中), 这是唯一还能出结论的一路。
/// 全部是统计特征, 所以必须有样本量门槛, 且权重压得比心跳域名低。
#[derive(Deserialize, Clone)]
pub struct StackRule {
    pub id: String,
    #[serde(default)]
    pub desc: String,
    /// 低于这个查询数不下结论
    #[serde(default)]
    pub min_samples: u32,
    /// 各查询类型的占比区间, 如 {"HTTPS": [0.08, 1.0]}
    #[serde(default)]
    pub ratio: HashMap<String, [f32; 2]>,
    /// 源端口离散度区间
    #[serde(default)]
    pub port_spread: Option<[f32; 2]>,
    /// 同域名 A+AAAA 紧邻发出的比例区间(Windows 解析器行为)
    #[serde(default)]
    pub pair_a4: Option<[f32; 2]>,
    /// 同域名 A+HTTPS 紧邻发出的比例区间(Apple 系统栈 / 现代浏览器)
    #[serde(default)]
    pub pair_https: Option<[f32; 2]>,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, rename = "type")]
    pub dtype: String,
    #[serde(default = "dw")]
    pub weight: u32,
}

impl DnsRule {
    /// 给人看的规则标识。contains/prefix 规则没有 suffix, 直接印 suffix 会是空白。
    pub fn label(&self) -> String {
        if !self.suffix.is_empty() {
            self.suffix.clone()
        } else if !self.prefix.is_empty() {
            format!("{}*", self.prefix)
        } else {
            format!("*{}*", self.contains)
        }
    }
}

/// 长连接对端: 「这台设备常年连着谁的什么端口」。
/// prefix 可选, 用来把同一个端口号按对端网段区分开。
#[derive(Deserialize, Clone)]
pub struct PeerRule {
    #[allow(dead_code)]
    pub id: String,
    /// tcp | udp | 空(都算)
    #[serde(default)]
    pub proto: String,
    pub port: u16,
    /// 对端 IP 前缀, 如 "47." ; 留空表示不限
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, rename = "type")]
    pub dtype: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "dw")]
    pub weight: u32,
}

/// 反证: 某个条件成立时, 从某个结论上**扣分**。
///
/// 之前所有权重都是正的, 只能表达"什么证明是 X", 没法表达"什么证明不是 X"。
/// 典型缺口: 手机不可能监听 1024 以下的特权端口(安卓和 iOS 的应用没有 root
/// 就绑不上), 一台设备只要开着这类端口, 它是手机的可能性就该被压下去。
#[derive(Deserialize, Clone)]
pub struct Penalty {
    #[allow(dead_code)]
    pub id: String,
    /// 条件名, 由代码识别。目前支持: privileged_port(开着 <1024 的端口)
    pub cond: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, rename = "type")]
    pub dtype: String,
    /// 负数
    pub weight: i32,
    /// 这些品牌上改用较轻的扣分。理由: 小米/一加/索尼这类官方支持解锁的安卓机
    /// 被 root 后确实能绑特权端口, 反证在它们身上不成立; 而华为/OPPO/vivo
    /// 这类锁死 bootloader 的机型上反证依然硬。
    #[serde(default)]
    pub soften_brands: Vec<String>,
    /// soften_brands 命中时用的权重(同样是负数)
    #[serde(default)]
    pub soften_weight: i32,
}

/// 上下位关系: specific 是 generic 的更具体说法(Proxmox VE 就是一种 Debian)。
/// 两者同时出现时, 把 generic 的分并进 specific, 而不是让它们互相分票 ——
/// 实测 PVE 宿主机的 SSH banner 说 Debian、8006 端口说 Proxmox VE, 各自权重 10,
/// 结果置信度被这个"平局"压到 31%。
#[derive(Deserialize, Clone)]
pub struct Subsume {
    pub specific: String,
    pub generic: String,
}

/// 多厂商心跳 => 这台设备在替别人转发 DNS。
/// 结论用哪个类型、给多少权重属于规则数据, 不写死在代码里; 规则库里没有这一节
/// 就等于关掉这个判据。
#[derive(Deserialize, Clone)]
pub struct Forwarder {
    #[serde(rename = "type")]
    pub dtype: String,
    #[serde(default = "dw")]
    pub weight: u32,
    /// 至少要几个互斥厂商同时出现才算数
    #[serde(default = "two")]
    pub min_brands: usize,
}

fn two() -> usize {
    2
}

#[derive(Deserialize, Clone)]
pub struct PortRule {
    /// 规则库里的稳定标识, 代码不读它, 但改规则时要靠它对上号
    #[allow(dead_code)]
    pub id: String,
    /// 同 TextRule: weak/web 表示只能给已立住的结论加分
    #[serde(default)]
    pub kind: String,
    pub port: u16,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, rename = "type")]
    pub dtype: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default = "dw")]
    pub weight: u32,
}

#[derive(Deserialize, Clone)]
pub struct TextRule {
    pub id: String,
    /// prefix | contains | exact
    #[serde(default)]
    pub mode: String,
    /// 与 DNS 规则同义: web = 这条证据可能来自别人的流量, 只能给已经
    /// 立住的结论加分, 不能自己下结论
    #[serde(default)]
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, rename = "type")]
    pub dtype: String,
    /// 虚拟化平台。这是独立于"品牌/类型"的一维: PVE 分配的虚拟网卡只说明
    /// 它是台虚拟机, 里面跑的系统得靠别的信号定。
    #[serde(default)]
    pub platform: String,
    #[serde(default = "dw")]
    pub weight: u32,
}

impl TextRule {
    pub fn hit(&self, hay: &str) -> bool {
        let h = hay.to_ascii_lowercase();
        let v = self.value.to_ascii_lowercase();
        match self.mode.as_str() {
            "prefix" => h.starts_with(&v),
            "exact" => h == v,
            _ => h.contains(&v),
        }
    }
}

#[derive(Deserialize, Default)]
pub struct Rules {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub dns: Vec<DnsRule>,
    #[serde(default)]
    pub hostname: Vec<TextRule>,
    #[serde(default)]
    pub mdns_service: Vec<TextRule>,
    #[serde(default)]
    pub mdns_model: Vec<TextRule>,
    #[serde(default)]
    pub upnp: Vec<TextRule>,
    /// DHCP option 60 vendor class
    #[serde(default)]
    pub dhcp_vendor: Vec<TextRule>,
    /// DHCP option 55 请求参数列表(顺序敏感)
    #[serde(default)]
    pub dhcp_fp: Vec<TextRule>,
    /// OUI 厂商名 -> 消费品牌的归一化。只收录能确定对应到终端品牌的,
    /// 代工厂(富士康、世纪新阳之类)刻意不映射 —— 它们不是设备品牌。
    #[serde(default)]
    pub oui_brand: Vec<TextRule>,
    /// 协议栈画像(qtype 比例 / 源端口行为)
    #[serde(default)]
    pub stack: Vec<StackRule>,
    /// 转发器判据; 缺省即关闭
    #[serde(default)]
    pub forwarder: Option<Forwarder>,
    /// TCP SYN 协议栈指纹 "<ttl>:<mss>:<win>:<ws>:<选项顺序>:<df>"
    #[serde(default)]
    pub tcp: Vec<TextRule>,
    /// 明文 HTTP 的 User-Agent
    #[serde(default)]
    pub ua: Vec<TextRule>,
    /// 开放端口 -> 身份
    #[serde(default)]
    pub port: Vec<PortRule>,
    /// SSH banner / HTTP Server 头
    #[serde(default)]
    pub banner: Vec<TextRule>,
    /// 品牌/系统的上下位关系
    #[serde(default)]
    pub subsume: Vec<Subsume>,
    /// 反证规则(负权重)
    #[serde(default)]
    pub penalty: Vec<Penalty>,
    /// 长连接对端
    #[serde(default)]
    pub peer: Vec<PeerRule>,
    /// MQTT CONNECT 的 ClientID
    #[serde(default)]
    pub mqtt: Vec<TextRule>,
    #[serde(skip)]
    dns_idx: HashMap<String, usize>,
    /// 带 contains / qtype 限定的规则下标, 后缀索引装不下, 单独顺序匹配
    #[serde(skip)]
    dns_pat: Vec<usize>,
}

impl Rules {
    /// 用户自定义规则。内置规则库随包升级会被覆盖, 所以自定义的要放这里。
    pub const LOCAL: &'static str = "/etc/whohere/rules.local.json";

    pub fn load(path: &str) -> Rules {
        let mut r: Rules = Self::read(path).unwrap_or_default();
        // 本地规则排在前面 —— 匹配是"先出现者优先", 于是本地条目自然覆盖内置条目
        if let Some(local) = Self::read(Self::LOCAL) {
            r.dns.splice(0..0, local.dns);
            r.hostname.splice(0..0, local.hostname);
            r.mdns_service.splice(0..0, local.mdns_service);
            r.mdns_model.splice(0..0, local.mdns_model);
            r.upnp.splice(0..0, local.upnp);
            r.dhcp_vendor.splice(0..0, local.dhcp_vendor);
            r.dhcp_fp.splice(0..0, local.dhcp_fp);
            r.oui_brand.splice(0..0, local.oui_brand);
            r.stack.splice(0..0, local.stack);
            r.tcp.splice(0..0, local.tcp);
            r.ua.splice(0..0, local.ua);
            r.port.splice(0..0, local.port);
            r.banner.splice(0..0, local.banner);
            r.subsume.splice(0..0, local.subsume);
            r.penalty.splice(0..0, local.penalty);
            r.peer.splice(0..0, local.peer);
            r.mqtt.splice(0..0, local.mqtt);
            if local.forwarder.is_some() {
                r.forwarder = local.forwarder;
            }
            if local.version > r.version {
                r.version = local.version;
            }
        }
        r.reindex();
        r
    }

    fn read(path: &str) -> Option<Rules> {
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
    }

    fn reindex(&mut self) {
        self.dns_idx.clear();
        self.dns_pat.clear();
        for (i, rule) in self.dns.iter().enumerate() {
            // 带 contains 或 qtype 限定的走顺序匹配, 不进后缀索引
            if !rule.contains.is_empty() || !rule.prefix.is_empty() || !rule.qtype.is_empty() {
                self.dns_pat.push(i);
                continue;
            }
            let key = crate::util::norm_domain(&rule.suffix);
            // 先出现者优先: 本地规则被排在前面, 于是能覆盖同后缀的内置规则
            self.dns_idx.entry(key).or_insert(i);
        }
    }

    fn suffix_hit(suffix: &str, domain: &str) -> bool {
        domain == suffix
            || (domain.len() > suffix.len()
                && domain.ends_with(suffix)
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
    }

    /// 行为型规则(contains / 限定 qtype)优先, 然后才是最长后缀优先。
    /// domain 已规整为小写无尾点。
    pub fn match_dns(&self, domain: &str, qtype: &str) -> Option<&DnsRule> {
        for &i in &self.dns_pat {
            let r = &self.dns[i];
            if !r.qtype.is_empty() && !r.qtype.eq_ignore_ascii_case(qtype) {
                continue;
            }
            if !r.contains.is_empty() && !domain.contains(&r.contains) {
                continue;
            }
            if !r.prefix.is_empty() && !domain.starts_with(&r.prefix) {
                continue;
            }
            if !r.suffix.is_empty() && !Self::suffix_hit(&r.suffix, domain) {
                continue;
            }
            // 只有 qtype 限定、没有任何域名条件的规则不成立, 会命中一切
            if r.contains.is_empty() && r.prefix.is_empty() && r.suffix.is_empty() {
                continue;
            }
            return Some(r);
        }
        let d = domain;
        if let Some(&i) = self.dns_idx.get(d) {
            return Some(&self.dns[i]);
        }
        let bytes = d.as_bytes();
        for (pos, _) in bytes.iter().enumerate().filter(|(_, &c)| c == b'.') {
            let tail = &d[pos + 1..];
            if let Some(&i) = self.dns_idx.get(tail) {
                return Some(&self.dns[i]);
            }
        }
        None
    }

    pub fn dns_by_id(&self, id: &str) -> Option<&DnsRule> {
        self.dns.iter().find(|r| r.id == id)
    }

    pub fn match_hostname(&self, name: &str) -> Vec<&TextRule> {
        self.hostname.iter().filter(|r| r.hit(name)).collect()
    }

    pub fn match_service(&self, svc: &str) -> Option<&TextRule> {
        self.mdns_service.iter().find(|r| r.hit(svc))
    }

    pub fn match_model(&self, model: &str) -> Option<&TextRule> {
        self.mdns_model.iter().find(|r| r.hit(model))
    }

    pub fn match_upnp(&self, server: &str) -> Option<&TextRule> {
        self.upnp.iter().find(|r| r.hit(server))
    }

    /// 逐条比对协议栈画像。全部区间都落在范围内才算命中。
    pub fn match_stack<'a>(&'a self, d: &crate::store::Device) -> Vec<&'a StackRule> {
        let n = d.dns_samples();
        let spread = d.port_spread();
        self.stack
            .iter()
            .filter(|r| {
                if n < r.min_samples.max(1) {
                    return false;
                }
                if !r.ratio.iter().all(|(t, [lo, hi])| {
                    let v = d.qtype_ratio(t);
                    v >= *lo && v <= *hi
                }) {
                    return false;
                }
                if let Some([lo, hi]) = r.port_spread {
                    match spread {
                        Some(v) if v >= lo && v <= hi => {}
                        _ => return false,
                    }
                }
                if let Some([lo, hi]) = r.pair_a4 {
                    let v = d.pair_a4_rate();
                    if v < lo || v > hi {
                        return false;
                    }
                }
                if let Some([lo, hi]) = r.pair_https {
                    let v = d.pair_https_rate();
                    if v < lo || v > hi {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    pub fn match_peer(&self, proto: &str, port: u16, remote: &str) -> Option<&PeerRule> {
        self.peer.iter().find(|r| {
            r.port == port
                && (r.proto.is_empty() || r.proto == proto)
                && (r.prefix.is_empty() || remote.starts_with(&r.prefix))
        })
    }

    pub fn peer_by_id(&self, id: &str) -> Option<&PeerRule> {
        self.peer.iter().find(|r| r.id == id)
    }

    pub fn match_port(&self, p: u16) -> Option<&PortRule> {
        self.port.iter().find(|r| r.port == p)
    }

    pub fn match_banner(&self, b: &str) -> Vec<&TextRule> {
        self.banner.iter().filter(|r| r.hit(b)).collect()
    }

    pub fn match_tcp(&self, fp: &str) -> Option<&TextRule> {
        self.tcp.iter().find(|r| r.hit(fp))
    }

    pub fn match_mqtt(&self, id: &str) -> Vec<&TextRule> {
        self.mqtt.iter().filter(|r| r.hit(id)).collect()
    }

    pub fn match_ua(&self, ua: &str) -> Vec<&TextRule> {
        self.ua.iter().filter(|r| r.hit(ua)).collect()
    }

    pub fn match_oui_brand(&self, vendor: &str) -> Option<&TextRule> {
        self.oui_brand.iter().find(|r| r.hit(vendor))
    }

    pub fn match_vendor(&self, vc: &str) -> Option<&TextRule> {
        self.dhcp_vendor.iter().find(|r| r.hit(vc))
    }

    /// option 55 顺序敏感, 先找精确命中; 找不到就退回最长公共前缀近似匹配
    pub fn match_dhcp_fp(&self, fp: &str) -> Option<&TextRule> {
        if let Some(r) = self.dhcp_fp.iter().find(|r| r.value == fp) {
            return Some(r);
        }
        let mut best: Option<(&TextRule, usize)> = None;
        for r in &self.dhcp_fp {
            let n = r
                .value
                .as_bytes()
                .iter()
                .zip(fp.as_bytes())
                .take_while(|(a, b)| a == b)
                .count();
            // 近似匹配至少要吃掉规则的一半, 否则宁可不判
            if n >= r.value.len() / 2 && n >= 8 && best.map_or(true, |(_, m)| n > m) {
                best = Some((r, n));
            }
        }
        best.map(|(r, _)| r)
    }
}

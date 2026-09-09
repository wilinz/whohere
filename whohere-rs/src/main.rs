// whohere - 看清路由器上都挂着谁, 以及那都是些什么设备。
//
// 四路信号融合: DHCP 指纹(opt55/opt60) / mDNS-SSDP 型号串 / DNS 心跳域名 / MAC OUI。
// 单独任何一路都会漏: 随机 MAC 打死 OUI, DoH 打死 DNS, 静默设备不发 mDNS。
//
// 子命令:
//   whohere list            列出全部设备(JSON)
//   whohere detail <mac>    单台详情, 含判定证据
//   whohere daemon          常驻采集(procd 拉起)
//   whohere scan            让常驻进程立刻主动探测一轮
//   whohere forget <mac>    删档
//   whohere note <mac> <名> 设置备注名
//   whohere status          采集源状态
//   whohere rules           规则库概况

mod clients;
mod conns;
mod dhcpev;
mod discover;
mod dnsmsg;
mod dnswatch;
mod event;
mod oui;
mod portprobe;
mod rules;
mod sniff;
mod store;
mod tail;
mod util;

use event::Event;
use rules::Rules;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use store::Store;
use util::*;

/// procd stop 会发 SIGTERM。不接的话最多丢一个 persist_interval 的识别结果,
/// 而这些结果正是重启后不用重新学一遍的东西。
static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    STOPPING.store(true, Ordering::SeqCst);
}

fn install_signals() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

/// 对外 JSON 契约版本。别的包依赖本包的数据时按这个判断兼容性,
/// 字段只增不删, 破坏性改动才 +1。
const SCHEMA: u32 = 1;

const CMD_FILE: &str = "/tmp/whohere.cmd";
const STATUS_FILE: &str = "/tmp/whohere.status.json";

struct Cfg {
    enabled: bool,
    dns_source: String,
    dns_log: String,
    singbox_log: String,
    dnstap_socket: String,
    dns_log_max_kb: u64,
    mdns: bool,
    /// 被动抓包(TCP 栈指纹 / TLS SNI / 明文 HTTP Host)
    sniff: bool,
    /// 从 conntrack 读长连接对端
    conns: bool,
    /// 主动端口探测。全项目唯一会主动连客户端的一路, 默认关闭。
    port_probe: bool,
    ssdp: bool,
    keep_unmatched: bool,
    db: String,
    rules: String,
    oui_db: String,
    persist_interval: u64,
    refresh_interval: u64,
    offline_after: u64,
    max_age: u64,
    /// DNS 证据半衰期(秒)。设 0 关闭衰减。
    evidence_halflife: u64,
}

fn load_cfg() -> Cfg {
    let g = |k: &str| format!("whohere.global.{k}");
    Cfg {
        enabled: uci_bool(&g("enabled"), true),
        dns_source: uci_get_or(&g("dns_source"), "auto"),
        dns_log: uci_get_or(&g("dns_log"), dnswatch::DEFAULT_LOG),
        singbox_log: uci_get_or(&g("singbox_log"), "/var/log/sing-box.log"),
        dnstap_socket: uci_get_or(&g("dnstap_socket"), "/tmp/whohere-dnstap.sock"),
        dns_log_max_kb: uci_num(&g("dns_log_max_kb"), 2048, 64),
        mdns: uci_bool(&g("mdns"), true),
        sniff: uci_bool(&g("sniff"), true),
        conns: uci_bool(&g("conns"), true),
        port_probe: uci_bool(&g("port_probe"), false),
        ssdp: uci_bool(&g("ssdp"), true),
        keep_unmatched: uci_bool(&g("keep_unmatched"), false),
        db: uci_get_or(&g("db"), "/etc/whohere/devices.json"),
        rules: uci_get_or(&g("rules"), "/usr/share/whohere/rules.json"),
        oui_db: uci_get_or(&g("oui_db"), oui::DEFAULT_DB),
        persist_interval: uci_num(&g("persist_interval"), 1800, 60),
        refresh_interval: uci_num(&g("refresh_interval"), 30, 5),
        offline_after: uci_num(&g("offline_after"), 600, 60),
        max_age: uci_num(&g("max_age"), 30 * 86400, 3600),
        // 默认 7 天: 一台设备一周没再发某类心跳, 那条证据的分量减半
        evidence_halflife: uci_num(&g("evidence_halflife"), 7 * 86400, 0),
    }
}

/// dnsmasq 的日志文件存在就用它; 否则看 sing-box 日志; 都没有就退回 dnstap。
fn probe_source(c: &Cfg) -> String {
    if c.dns_source != "auto" {
        return c.dns_source.clone();
    }
    if std::path::Path::new(&c.dns_log).exists() {
        return "dnsmasq_log".into();
    }
    if std::path::Path::new(&c.singbox_log).exists() {
        return "singbox_log".into();
    }
    "off".into()
}

// ---------------- 输出 ----------------

fn merge_live(st: &mut Store, cfg: &Cfg) {
    let seen = clients::collect();
    let statics = clients::static_names();
    let now = now();
    for (mac, s) in &seen {
        let d = st.get(mac);
        for ip in &s.ipv4 {
            if !d.ipv4.contains(ip) {
                d.ipv4.push(ip.clone());
            }
        }
        for ip in &s.ipv6 {
            if !d.ipv6.contains(ip) {
                d.ipv6.push(ip.clone());
            }
        }
        // 只保留最近的几个地址, 免得 IPv6 临时地址把档案撑大
        if d.ipv4.len() > 4 {
            let n = d.ipv4.len();
            d.ipv4.drain(..n - 4);
        }
        if d.ipv6.len() > 4 {
            let n = d.ipv6.len();
            d.ipv6.drain(..n - 4);
        }
        if let Some(h) = &s.dhcp_name {
            d.dhcp_name = h.clone();
        }
        if let Some(n) = statics.get(mac) {
            d.static_name = n.clone();
        }
        d.iface = s.iface.clone().unwrap_or_default();
        d.band = s.band.clone().unwrap_or_default();
        d.signal = s.signal;
        // 在线判据: 邻居表可达, 或租约还没过期
        d.online = s.reachable || s.lease_expire > now;
        if d.online {
            d.last_seen = now;
        }
    }
    // 本轮没出现的设备不立刻判离线: 邻居表条目会正常老化, 设备只是安静一会儿
    // 就闪成离线很难看。给 offline_after 的宽限期。
    for d in st.devs.values_mut() {
        if !seen.contains_key(&d.mac) {
            d.online = now.saturating_sub(d.last_seen) < cfg.offline_after;
        }
    }

    // 历史档案里可能残留着早先版本收进来的 WAN 侧设备, 一并清掉
    let nets = clients::lan_nets();
    if !nets.is_empty() {
        let before = st.devs.len();
        st.devs
            .retain(|_, d| d.ipv4.is_empty() || d.ipv4.iter().any(|ip| clients::in_lan(&nets, ip)));
        if st.devs.len() != before {
            st.dirty = true;
        }
    }

    // 补 OUI(随机 MAC 不查)
    let want: HashSet<String> = st
        .devs
        .values()
        .filter(|d| d.oui.is_empty() && !d.random_mac())
        .map(|d| oui_prefix(&d.mac))
        .collect();
    if !want.is_empty() {
        let found = oui::lookup_many(&cfg.oui_db, &want);
        for d in st.devs.values_mut() {
            if d.oui.is_empty() {
                if let Some(v) = found.get(&oui_prefix(&d.mac)) {
                    d.oui = v.clone();
                }
            }
        }
    }
}

fn dev_json(d: &store::Device, r: &Rules, halflife: u64, full: bool) -> Value {
    let id = d.identify(r, halflife);
    let mut v = json!({
        "mac": d.mac,
        "name": d.best_name(),
        "ipv4": d.ipv4,
        "online": d.online,
        "random_mac": d.random_mac(),
        "brand": id.brand,
        "os": id.os,
        "type": id.dtype,
        "model": id.model,
        "platform": id.platform,
        "confidence": id.confidence,
        "iface": d.iface,
        "band": d.band,
        "signal": d.signal,
        "first_seen": d.first_seen,
        "last_seen": d.last_seen,
        "oui": d.oui,
    });
    if full {
        v["ipv6"] = json!(d.ipv6);
        v["dhcp_name"] = json!(d.dhcp_name);
        v["static_name"] = json!(d.static_name);
        v["mdns_name"] = json!(d.mdns_name);
        v["mdns_model"] = json!(d.mdns_model);
        v["mdns_services"] = json!(d.mdns_services);
        v["upnp_server"] = json!(d.upnp_server);
        v["dhcp_vendor"] = json!(d.dhcp_vendor);
        v["dhcp_fp"] = json!(d.dhcp_fp);
        v["note"] = json!(d.note);
        v["evidence"] = json!(id.evidence);
        v["unmatched"] = json!(d.unmatched);
        // 协议栈画像: 查了多少次、类型分布、源端口行为
        v["open_ports"] = json!(d.open_ports);
        v["banner"] = json!(d.banner);
        v["tcp_fp"] = json!(d.tcp_fp);
        v["http_ua"] = json!(d.http_ua);
        v["mqtt_id"] = json!(d.mqtt_id);
        v["dns_samples"] = json!(d.dns_samples());
        v["qtypes"] = json!(d.qtypes);
        v["port_spread"] = json!(d.port_spread());
        v["pair_a4"] = json!(d.pair_a4_rate());
        v["pair_https"] = json!(d.pair_https_rate());
    }
    v
}

/// 约定一次「最早在何时落盘」。只能提前, 不能推迟——否则持续的
/// DNS/mDNS 流量会把落盘时间一直往后推, 永远存不下来。
fn schedule_save(save_at: &mut Option<u64>, at: u64) {
    if save_at.map_or(true, |cur| at < cur) {
        *save_at = Some(at);
    }
}

fn cmd_list(cfg: &Cfg, r: &Rules) {
    let mut st = Store::load(&cfg.db);
    merge_live(&mut st, cfg);
    let mut devs: Vec<&store::Device> = st.devs.values().collect();
    devs.sort_by(|a, b| b.online.cmp(&a.online).then(b.last_seen.cmp(&a.last_seen)));
    let online = devs.iter().filter(|d| d.online).count();
    let out = json!({
        "schema": SCHEMA,
        "devices": devs
            .iter()
            .map(|d| dev_json(d, r, cfg.evidence_halflife, false))
            .collect::<Vec<_>>(),
        "total": devs.len(),
        "online": online,
        "identified": devs
            .iter()
            .filter(|d| d.identify(r, cfg.evidence_halflife).confidence >= 50)
            .count(),
        "oui_db": oui::count(&cfg.oui_db),
        "status": read_status(),
    });
    println!("{out}");
}

fn cmd_detail(cfg: &Cfg, r: &Rules, mac: &str) {
    let mac = norm_mac(mac).unwrap_or_default();
    let mut st = Store::load(&cfg.db);
    merge_live(&mut st, cfg);
    match st.devs.get(&mac) {
        Some(d) => {
            let mut v = dev_json(d, r, cfg.evidence_halflife, true);
            v["schema"] = json!(SCHEMA);
            println!("{v}");
        }
        None => println!("{}", json!({"error": "not found"})),
    }
}

/// 广播 ubus 事件 whohere.device。下游包用
///     ubus listen whohere.device
/// 就能在设备被识别出来或结论变化时收到通知, 不必轮询。
fn emit_device(d: &store::Device, id: &store::Ident, reason: &str) {
    let payload = json!({
        "schema": SCHEMA,
        "reason": reason,
        "mac": d.mac,
        "name": d.best_name(),
        "ipv4": d.ipv4,
        "brand": id.brand,
        "os": id.os,
        "type": id.dtype,
        "model": id.model,
        "platform": id.platform,
        "confidence": id.confidence,
        "random_mac": d.random_mac(),
    });
    let _ = std::process::Command::new("ubus")
        .args(["send", "whohere.device", &payload.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn read_status() -> Value {
    std::fs::read_to_string(STATUS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({"running": false}))
}

fn push_cmd(line: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CMD_FILE)
    {
        let _ = writeln!(f, "{line}");
    }
}

// ---------------- daemon ----------------

fn daemon(cfg: Cfg, mut r: Rules) {
    install_signals();
    let (tx, rx) = std::sync::mpsc::channel::<Event>();
    let mut st = Store::load(&cfg.db);
    let mut sources: Vec<Value> = Vec::new();
    let source = probe_source(&cfg);

    match source.as_str() {
        "dnsmasq_log" | "singbox_log" => {
            let path = if source == "singbox_log" {
                cfg.singbox_log.clone()
            } else {
                cfg.dns_log.clone()
            };
            // 文件不存在时先建一个空的, 免得 dnsmasq 还没写第一行就被判定为不可用
            if !std::path::Path::new(&path).exists() {
                let _ = std::fs::write(&path, b"");
            }
            dnswatch::spawn_logtail(source.clone(), path, cfg.dns_log_max_kb, tx.clone());
        }
        "dnstap" => dnswatch::spawn_dnstap(cfg.dnstap_socket.clone(), tx.clone()),
        _ => {
            sources.push(json!({"kind": "dns", "state": "disabled", "info": ""}));
        }
    }
    dhcpev::spawn(tx.clone());
    if cfg.mdns {
        discover::spawn_mdns(tx.clone());
    }
    if cfg.ssdp {
        discover::spawn_ssdp(tx.clone());
    }
    if cfg.conns {
        conns::spawn(tx.clone(), 60);
    } else {
        sources.push(json!({"kind": "conns", "state": "disabled", "info": ""}));
    }
    if cfg.sniff {
        let ifs = clients::lan_devices();
        if ifs.is_empty() {
            sources.push(json!({"kind": "sniff", "state": "no_iface", "info": ""}));
        } else {
            sniff::spawn(ifs, tx.clone());
        }
    } else {
        sources.push(json!({"kind": "sniff", "state": "disabled", "info": ""}));
    }

    let started = now();
    let (mut last_refresh, mut last_persist, mut last_rules) = (0u64, now(), now());
    let mut dns_events = 0u64;
    // 诊断用: 归属到设备的 / 找不到主人的
    let (mut dns_matched, mut dns_noowner) = (0u64, 0u64);
    let (mut sniff_events, mut sniff_matched, mut sniff_noowner) = (0u64, 0u64, 0u64);
    // mac -> 上一条查询(域名/类型/时间), 只在内存里用来判"成对", 不落盘
    let mut last_q: std::collections::HashMap<String, (String, String, u64)> =
        std::collections::HashMap::new();
    // 指纹类信息(DHCP/mDNS/SSDP)很少变, 一旦变了就尽快落盘, 不等下一个整周期
    let mut save_at: Option<u64> = None;
    // mac -> 上次广播出去的结论, 用来判断"变了没有", 避免重复刷事件
    let mut announced: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    loop {
        // 事件驱动为主, 1 秒超时用来跑周期性任务
        match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(Event::Dns {
                ip,
                domain,
                qtype,
                sport,
            }) => {
                dns_events += 1;
                // 查询来自我们还没见过的 IP 时无从归属(邻居表未刷新 / 非本网段)
                let mac = st.resolve_ip(&ip);
                if mac.is_none() {
                    dns_noowner += 1;
                }
                if let Some(mac) = mac {
                    // 查询类型和源端口跟域名内容无关, 每条查询都记 —— 域名一条
                    // 规则都命不中的设备, 就靠这个画像出结论
                    st.get(&mac).record_dns_shape(&qtype, sport);
                    // 同一域名的 A/AAAA 或 A/HTTPS 紧挨着发出, 说明是一次
                    // getaddrinfo 展开的。域名只在内存里比一下就丢, 不落盘。
                    let t = now();
                    if let Some((pd, pq, pt)) = last_q.get(&mac) {
                        if *pd == domain && t.saturating_sub(*pt) <= 2 && *pq != qtype {
                            let pair = |a: &str, b: &str| {
                                (pq == a && qtype == b) || (pq == b && qtype == a)
                            };
                            let d = st.get(&mac);
                            if pair("A", "AAAA") {
                                d.dns_pair_a4 += 1;
                            } else if pair("A", "HTTPS") || pair("A", "SVCB") {
                                d.dns_pair_https += 1;
                            }
                        }
                    }
                    // 只是个防泄漏的上限, 清空最多让几条配对漏记
                    if last_q.len() > 512 {
                        last_q.clear();
                    }
                    last_q.insert(mac.clone(), (domain.clone(), qtype.clone(), t));
                    schedule_save(&mut save_at, now() + 120);
                    match r.match_dns(&domain, &qtype) {
                        Some(rule) => {
                            let id = rule.id.clone();
                            let d = st.get(&mac);
                            let h = d.dns_hits.entry(id).or_default();
                            h.n += 1;
                            h.last = now();
                            dns_matched += 1;
                            // DNS 命中直接改变识别结论, 得尽快落盘: CLI 读的是磁盘
                            schedule_save(&mut save_at, now() + 30);
                        }
                        None if cfg.keep_unmatched => {
                            let d = st.get(&mac);
                            if d.unmatched.len() < 50 {
                                *d.unmatched.entry(domain).or_insert(0) += 1;
                                schedule_save(&mut save_at, now() + 30);
                            }
                        }
                        None => {}
                    }
                }
            }
            Ok(Event::Ports { ip, open, banner }) => {
                if let Some(mac) = st.resolve_ip(&ip) {
                    let d = st.get(&mac);
                    d.open_ports = open;
                    // banner 只在拿到新的时才覆盖: 设备临时不响应不该把
                    // 之前读到的 SSH 版本号擦掉
                    if !banner.is_empty() {
                        d.banner = banner;
                    }
                    schedule_save(&mut save_at, now() + 10);
                }
            }
            Ok(Event::Peer {
                ip,
                proto,
                remote,
                port,
            }) => {
                if let Some(mac) = st.resolve_ip(&ip) {
                    match r.match_peer(&proto, port, &remote) {
                        Some(rule) => {
                            let id = rule.id.clone();
                            let d = st.get(&mac);
                            let h = d.peer_hits.entry(id).or_default();
                            h.n += 1;
                            h.last = now();
                            schedule_save(&mut save_at, now() + 30);
                        }
                        None if cfg.keep_unmatched => {
                            let d = st.get(&mac);
                            if d.unmatched.len() < 50 {
                                *d.unmatched.entry(format!("{proto}/{port}")).or_insert(0) += 1;
                                schedule_save(&mut save_at, now() + 60);
                            }
                        }
                        None => {}
                    }
                }
            }
            Ok(Event::TcpFp { ip, fp }) => {
                if let Some(mac) = st.resolve_ip(&ip) {
                    let d = st.get(&mac);
                    if d.tcp_fp != fp {
                        d.tcp_fp = fp;
                        schedule_save(&mut save_at, now() + 20);
                    }
                }
            }
            Ok(Event::Conn { ip, host, ua, via }) => {
                sniff_events += 1;
                let mac = match st.resolve_ip(&ip) {
                    Some(m) => m,
                    None => {
                        // 与 DNS 一路同样的归属失败, 单独计数便于排查
                        sniff_noowner += 1;
                        String::new()
                    }
                };
                if !mac.is_empty() {
                    if !ua.is_empty() {
                        let d = st.get(&mac);
                        // MQTT 的 ClientID 和 HTTP 的 UA 语义不同, 分开存
                        let slot = if via == "mqtt" {
                            &mut d.mqtt_id
                        } else {
                            &mut d.http_ua
                        };
                        if *slot != ua {
                            *slot = ua;
                            schedule_save(&mut save_at, now() + 20);
                        }
                    }
                    if !host.is_empty() {
                        // SNI/Host 直接复用同一套域名规则库
                        match r.match_dns(&host, "") {
                            Some(rule) => {
                                let id = rule.id.clone();
                                let d = st.get(&mac);
                                let h = d.sni_hits.entry(id).or_default();
                                h.n += 1;
                                h.last = now();
                                sniff_matched += 1;
                                schedule_save(&mut save_at, now() + 30);
                            }
                            None if cfg.keep_unmatched => {
                                let d = st.get(&mac);
                                if d.unmatched.len() < 50 {
                                    *d.unmatched.entry(format!("{via}:{host}")).or_insert(0) += 1;
                                    schedule_save(&mut save_at, now() + 30);
                                }
                            }
                            None => {}
                        }
                    }
                }
            }
            Ok(Event::Dhcp {
                mac,
                ip,
                host,
                vendor,
                opts,
            }) => {
                let d = st.get(&mac);
                if !ip.is_empty() && !d.ipv4.contains(&ip) && !ip.contains(':') {
                    d.ipv4.push(ip);
                }
                if !host.is_empty() {
                    d.dhcp_name = host;
                }
                if !vendor.is_empty() {
                    d.dhcp_vendor = vendor;
                }
                if !opts.is_empty() {
                    d.dhcp_fp = opts;
                }
                d.last_seen = now();
                schedule_save(&mut save_at, now() + 20);
            }
            Ok(Event::Mdns {
                ip,
                name,
                model,
                services,
            }) => {
                if let Some(mac) = st.resolve_ip(&ip) {
                    let d = st.get(&mac);
                    if !name.is_empty() {
                        d.mdns_name = name;
                    }
                    if !model.is_empty() {
                        d.mdns_model = model;
                    }
                    for s in services {
                        if !d.mdns_services.contains(&s) && d.mdns_services.len() < 24 {
                            d.mdns_services.push(s);
                            schedule_save(&mut save_at, now() + 20);
                        }
                    }
                }
            }
            Ok(Event::Ssdp { ip, server }) => {
                if let Some(mac) = st.resolve_ip(&ip) {
                    let d = st.get(&mac);
                    if d.upnp_server != server {
                        d.upnp_server = server;
                        schedule_save(&mut save_at, now() + 20);
                    }
                }
            }
            Ok(Event::SourceInfo { kind, state, info }) => {
                sources.retain(|s| s["kind"] != kind);
                sources.push(json!({"kind": kind, "state": state, "info": info}));
            }
            Err(_) => {}
        }

        let t = now();

        if STOPPING.load(Ordering::SeqCst) {
            merge_live(&mut st, &cfg);
            st.save();
            let _ = std::fs::remove_file(STATUS_FILE);
            return;
        }

        if save_at.is_some_and(|at| t >= at) {
            save_at = None;
            st.save();
        }

        if t.saturating_sub(last_refresh) >= cfg.refresh_interval {
            last_refresh = t;
            merge_live(&mut st, &cfg);

            // 结论有变化就广播一次
            for d in st.devs.values() {
                let id = d.identify(&r, cfg.evidence_halflife);
                if id.confidence == 0 {
                    continue;
                }
                let sig = format!("{}|{}|{}|{}", id.brand, id.os, id.dtype, id.model);
                match announced.get(&d.mac) {
                    Some(prev) if *prev == sig => {}
                    prev => {
                        emit_device(d, &id, if prev.is_none() { "new" } else { "changed" });
                        announced.insert(d.mac.clone(), sig);
                    }
                }
            }
            let _ = atomic_write(
                STATUS_FILE,
                serde_json::to_string(&json!({
                    "running": true,
                    "started": started,
                    "dns_source": source,
                    "dns_events": dns_events,
                    "dns_matched": dns_matched,
                    "dns_noowner": dns_noowner,
                    "sniff_events": sniff_events,
                    "sniff_matched": sniff_matched,
                    "sniff_noowner": sniff_noowner,
                    "devices": st.devs.len(),
                    "online": st.devs.values().filter(|d| d.online).count(),
                    "sources": sources,
                    "rules_version": r.version,
                }))
                .unwrap_or_default()
                .as_bytes(),
            );
        }

        // 规则库被 update-rules 换掉后自动热加载
        if t.saturating_sub(last_rules) >= 60 {
            last_rules = t;
            let fresh = Rules::load(&cfg.rules);
            if fresh.dns.len() != r.dns.len() || fresh.version != r.version {
                r = fresh;
            }
        }

        if t.saturating_sub(last_persist) >= cfg.persist_interval {
            last_persist = t;
            st.prune(cfg.max_age, cfg.evidence_halflife);
            st.save();
        }

        // 外部命令
        if std::path::Path::new(CMD_FILE).exists() {
            let txt = std::fs::read_to_string(CMD_FILE).unwrap_or_default();
            let _ = std::fs::remove_file(CMD_FILE);
            for line in txt.lines() {
                let mut it = line.splitn(3, ' ');
                match (it.next(), it.next(), it.next()) {
                    (Some("forget"), Some(m), _) => {
                        if let Some(m) = norm_mac(m) {
                            st.devs.remove(&m);
                            st.dirty = true;
                        }
                    }
                    (Some("note"), Some(m), Some(n)) => {
                        if let Some(m) = norm_mac(m) {
                            st.get(&m).note = n.to_string();
                        }
                    }
                    (Some("scan"), _, _) => {
                        // 主动探测由各监听线程自己周期性做; 这里立刻补一发
                        if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
                            discover::probe_mdns(&s);
                            discover::probe_ssdp(&s);
                        }
                        merge_live(&mut st, &cfg);
                    }
                    (Some("probe"), _, _) => {
                        // 端口探测有自己的按钮和自己的开关 —— 它是全项目唯一会
                        // 主动连客户端的动作, 不该被"立即探测"这种无害的组播
                        // 刷新顺带捎上。
                        if cfg.port_probe {
                            merge_live(&mut st, &cfg);
                            let ips: Vec<String> = st
                                .devs
                                .values()
                                .filter(|d| d.online)
                                .filter_map(|d| d.ipv4.first().cloned())
                                .collect();
                            portprobe::run(ips, tx.clone());
                        } else {
                            sources.retain(|s| s["kind"] != "ports");
                            sources.push(json!({"kind":"ports","state":"disabled","info":""}));
                        }
                    }
                    (Some("save"), _, _) => st.save(),
                    _ => {}
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("list");
    let cfg = load_cfg();
    let r = Rules::load(&cfg.rules);

    match cmd {
        "daemon" => {
            if !cfg.enabled {
                eprintln!("whohere: disabled (uci set whohere.global.enabled=1)");
                std::process::exit(0);
            }
            daemon(cfg, r);
        }
        "detail" => cmd_detail(&cfg, &r, args.get(2).map(|s| s.as_str()).unwrap_or("")),
        "status" => println!("{}", read_status()),
        "scan" => {
            push_cmd("scan");
            println!("{}", json!({"ok": true}));
        }
        "probe" => {
            let on = cfg.port_probe;
            if on {
                push_cmd("probe");
            }
            println!("{}", json!({"ok": on, "enabled": on}));
        }
        "forget" => {
            let m = args.get(2).cloned().unwrap_or_default();
            push_cmd(&format!("forget {m}"));
            // 常驻进程没跑时也要能删
            let mut st = Store::load(&cfg.db);
            if let Some(m) = norm_mac(&m) {
                if st.devs.remove(&m).is_some() {
                    st.dirty = true;
                    st.save();
                }
            }
            println!("{}", json!({"ok": true}));
        }
        "note" => {
            let m = args.get(2).cloned().unwrap_or_default();
            let n = args.get(3).cloned().unwrap_or_default();
            push_cmd(&format!("note {m} {n}"));
            let mut st = Store::load(&cfg.db);
            if let Some(m) = norm_mac(&m) {
                st.get(&m).note = n;
                st.save();
            }
            println!("{}", json!({"ok": true}));
        }
        "rules" => println!(
            "{}",
            json!({
                "version": r.version,
                "dns": r.dns.len(),
                "hostname": r.hostname.len(),
                "mdns_service": r.mdns_service.len(),
                "mdns_model": r.mdns_model.len(),
                "upnp": r.upnp.len(),
                "dhcp_vendor": r.dhcp_vendor.len(),
                "dhcp_fp": r.dhcp_fp.len(),
                "stack": r.stack.len(),
                "tcp": r.tcp.len(),
                "ua": r.ua.len(),
                "port": r.port.len(),
                "peer": r.peer.len(),
                "mqtt": r.mqtt.len(),
                "banner": r.banner.len(),
                "oui_entries": oui::count(&cfg.oui_db),
            })
        ),
        _ => cmd_list(&cfg, &r),
    }
}

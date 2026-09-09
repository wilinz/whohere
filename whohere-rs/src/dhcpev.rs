// DHCP 指纹入口。
//
// dnsmasq 在 OpenWrt 上跑在 ujail 里, dhcp-script 是被 `.` source 进去执行的,
// 只能写 jail 内被 RW 挂载的路径 —— 所以钩子不能直接落文件, 只能通过 jail 里
// 可用的 ubus socket 把数据送出来。这里就是接收端: 起一个 `ubus listen`
// 子进程读它的 stdout。

use crate::event::Event;
use crate::util::norm_mac;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;

pub const UBUS_EVENT: &str = "whohere.dhcp";

fn handle(v: &Value, tx: &Sender<Event>) {
    let o = match v.get(UBUS_EVENT) {
        Some(o) => o,
        None => return,
    };
    let s = |k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mac = match norm_mac(&s("mac")) {
        Some(m) => m,
        None => return,
    };
    let _ = tx.send(Event::Dhcp {
        mac,
        ip: s("ip"),
        host: s("host"),
        vendor: s("vendor"),
        opts: s("opts"),
    });
}

pub fn spawn(tx: Sender<Event>) {
    std::thread::spawn(move || loop {
        let child = Command::new("ubus")
            .args(["listen", UBUS_EVENT])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Event::SourceInfo {
                    kind: "dhcp",
                    state: "listen_failed",
                    info: format!("ubus listen: {e}"),
                });
                std::thread::sleep(std::time::Duration::from_secs(30));
                continue;
            }
        };
        let _ = tx.send(Event::SourceInfo {
            kind: "dhcp",
            state: "subscribed",
            info: UBUS_EVENT.to_string(),
        });
        if let Some(out) = child.stdout.take() {
            // ubus 可能吐单行也可能吐美化过的多行 JSON, 用括号配平来切分
            let mut depth = 0i32;
            let mut acc = String::new();
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                for c in line.chars() {
                    match c {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                acc.push_str(&line);
                acc.push('\n');
                if depth <= 0 && !acc.trim().is_empty() {
                    if let Ok(v) = serde_json::from_str::<Value>(acc.trim()) {
                        handle(&v, &tx);
                    }
                    acc.clear();
                    depth = 0;
                }
                if acc.len() > 64 * 1024 {
                    acc.clear();
                    depth = 0;
                }
            }
        }
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_secs(5));
    });
}

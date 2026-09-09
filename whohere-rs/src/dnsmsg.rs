// 极简 DNS 报文解析。够用即可: 问题段域名(给 dnstap 用) + 应答段
// PTR/SRV/TXT/A 记录(给 mDNS 用)。带域名压缩指针处理与防环计数。

pub const T_A: u16 = 1;
pub const T_PTR: u16 = 12;
pub const T_TXT: u16 = 16;
pub const T_SRV: u16 = 33;

pub struct Record {
    pub name: String,
    pub rtype: u16,
    /// PTR/SRV 的目标名; TXT 为空
    pub target: String,
    /// TXT 的各条键值串
    pub txt: Vec<String>,
    /// A 记录的点分地址
    pub addr: String,
}

/// 从 off 处读一个(可能压缩的)域名, 返回 (名字, 该字段之后的偏移)
fn read_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut after = off;
    // 指针跳转次数上限, 防止构造出的环形指针把我们卡死
    let mut hops = 0;
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            off += 1;
            if !jumped {
                after = off;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let b2 = *buf.get(off + 1)? as usize;
            let ptr = ((len & 0x3f) << 8) | b2;
            if !jumped {
                after = off + 2;
                jumped = true;
            }
            hops += 1;
            if hops > 16 || ptr >= buf.len() {
                return None;
            }
            off = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let s = buf.get(off + 1..off + 1 + len)?;
        parts.push(String::from_utf8_lossy(s).into_owned());
        off += 1 + len;
        if !jumped {
            after = off;
        }
    }
    Some((parts.join("."), after))
}

/// 只取第一个问题的域名, dnstap 场景够用
pub fn first_question(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    let (name, _) = read_name(buf, 12)?;
    if name.is_empty() {
        None
    } else {
        Some(crate::util::norm_domain(&name))
    }
}

/// 解析全部应答/权威/附加段记录 (mDNS 响应用)
pub fn parse_records(buf: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    if buf.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let counts = (u16::from_be_bytes([buf[6], buf[7]]) as usize)
        + (u16::from_be_bytes([buf[8], buf[9]]) as usize)
        + (u16::from_be_bytes([buf[10], buf[11]]) as usize);
    let mut off = 12;
    // 跳过问题段
    for _ in 0..qd {
        match read_name(buf, off) {
            Some((_, n)) => off = n + 4,
            None => return out,
        }
    }
    for _ in 0..counts {
        let (name, n) = match read_name(buf, off) {
            Some(v) => v,
            None => break,
        };
        off = n;
        if off + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        let rdata = match buf.get(off..off + rdlen) {
            Some(v) => v,
            None => break,
        };
        let mut rec = Record {
            name: crate::util::norm_domain(&name),
            rtype,
            target: String::new(),
            txt: Vec::new(),
            addr: String::new(),
        };
        match rtype {
            T_PTR => {
                if let Some((t, _)) = read_name(buf, off) {
                    rec.target = crate::util::norm_domain(&t);
                }
            }
            T_SRV => {
                // priority(2) weight(2) port(2) target
                if rdlen > 6 {
                    if let Some((t, _)) = read_name(buf, off + 6) {
                        rec.target = crate::util::norm_domain(&t);
                    }
                }
            }
            T_TXT => {
                let mut i = 0;
                while i < rdata.len() {
                    let l = rdata[i] as usize;
                    if l == 0 || i + 1 + l > rdata.len() {
                        break;
                    }
                    rec.txt
                        .push(String::from_utf8_lossy(&rdata[i + 1..i + 1 + l]).into_owned());
                    i += 1 + l;
                }
            }
            T_A => {
                if rdlen == 4 {
                    rec.addr = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                }
            }
            _ => {}
        }
        out.push(rec);
        off += rdlen;
    }
    out
}

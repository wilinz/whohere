// 增量读日志文件, 处理轮转(inode 变)与截断(size 变小)。
// 只吐完整行; 半行留在缓冲区等下次。

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

pub struct Tail {
    path: String,
    pos: u64,
    ino: u64,
    buf: String,
    /// 单行上限, 防御畸形/超长行把内存吃光
    max_line: usize,
}

impl Tail {
    pub fn new(path: &str) -> Tail {
        // 从文件末尾开始, 不回放历史(历史日志对"现在谁在线"没意义, 还可能很大)
        let (pos, ino) = std::fs::metadata(path)
            .map(|m| (m.len(), m.ino()))
            .unwrap_or((0, 0));
        Tail {
            path: path.to_string(),
            pos,
            ino,
            buf: String::new(),
            max_line: 8192,
        }
    }

    pub fn read_lines(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let md = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return out,
        };
        if md.ino() != self.ino {
            self.ino = md.ino();
            self.pos = 0;
            self.buf.clear();
        } else if md.len() < self.pos {
            // 被 truncate(我们自己限流时就会这么干)
            self.pos = 0;
            self.buf.clear();
        }
        if md.len() == self.pos {
            return out;
        }
        let mut f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return out,
        };
        if f.seek(SeekFrom::Start(self.pos)).is_err() {
            return out;
        }
        let mut chunk = vec![0u8; 256 * 1024];
        loop {
            let n = match f.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            self.pos += n as u64;
            self.buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
            while let Some(i) = self.buf.find('\n') {
                let line: String = self.buf.drain(..=i).collect();
                out.push(line.trim_end().to_string());
            }
            if self.buf.len() > self.max_line {
                self.buf.clear();
            }
            if n < chunk.len() {
                break;
            }
        }
        out
    }

    pub fn size(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    /// 原始日志读完即弃: 截断文件, 只保留我们已经提炼出的指纹结果。
    /// 这既是隐私要求, 也是防止 tmpfs 被日志撑爆。
    pub fn truncate(&mut self) {
        if std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .and_then(|f| f.set_len(0))
            .is_ok()
        {
            self.pos = 0;
            self.buf.clear();
        }
    }
}

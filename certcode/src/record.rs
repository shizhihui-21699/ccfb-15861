//! 证书记录及其定长规范二进制编码。
//!
//! 规范编码(canonical encoding)是整个方案签名稳定性的基础:
//! 同一条证书记录在任何机器、任何时间编码出的字节完全一致,
//! 签名覆盖的就是这段字节,不存在 JSON 字段顺序/空白差异问题。

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// 记录 schema 版本,写入记录首字节;将来格式演进时据此区分。
pub const RECORD_VERSION: u8 = 0x01;

/// 各字段长度上限(字节)
pub const SERIAL_LEN: usize = 16;
pub const SUBJECT_LEN: usize = 16;
pub const NAME_MAX_BYTES: usize = 128;

/// ASCII 合法字符:大写字母、数字、连字符(编号/科目用)
fn is_ascii_token_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'
}

/// 一张证书上需要防伪保护的全部信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateRecord {
    /// 证书编号,全局唯一,ASCII,最长 12 字节,如 `CERT20260001`
    pub serial: String,
    /// 持证人姓名(支持中文);编码前做 Unicode NFC 规范化
    pub name: String,
    /// 职业资格科目/工种,ASCII,最长 16 字节,如 `WELDER-1G`
    pub subject: String,
    /// 成绩,0..=1000(支持一位小数时由发证方乘 10)
    pub score: u16,
    /// 签发日期:自 1970-01-01 起的天数
    pub issued_on: u32,
}

impl CertificateRecord {
    /// 构造时做 NFC 规范化与字段校验。
    pub fn new(serial: &str, name: &str, subject: &str, score: u16, issued_on: u32) -> Result<Self> {
        let rec = CertificateRecord {
            serial: serial.to_string(),
            name: name.nfc().collect::<String>(),
            subject: subject.to_string(),
            score,
            issued_on,
        };
        rec.validate()?;
        Ok(rec)
    }

    pub fn validate(&self) -> Result<()> {
        // 编号
        let serial = self.serial.as_bytes();
        if serial.is_empty() || serial.len() > SERIAL_LEN {
            return Err(Error::Encode(format!(
                "证书编号长度须在 1..={SERIAL_LEN} 字节之间,实际 {} 字节",
                serial.len()
            )));
        }
        if !serial.iter().all(|&b| is_ascii_token_char(b)) {
            return Err(Error::Encode(
                "证书编号只能含大写字母、数字和连字符(-)".into(),
            ));
        }

        // 姓名:NFC 后校验
        let nfc_name: String = self.name.nfc().collect();
        if nfc_name != self.name {
            return Err(Error::Encode("姓名未经 NFC 规范化,请使用 CertificateRecord::new 构造".into()));
        }
        let nb = nfc_name.as_bytes();
        if nb.is_empty() || nb.len() > NAME_MAX_BYTES {
            return Err(Error::Encode(format!(
                "姓名长度须在 1..={NAME_MAX_BYTES} 字节(NFC UTF-8)之间"
            )));
        }
        if nfc_name.chars().any(|c| c.is_control()) {
            return Err(Error::Encode("姓名不得包含控制字符".into()));
        }

        // 科目
        let subject = self.subject.as_bytes();
        if subject.is_empty() || subject.len() > SUBJECT_LEN {
            return Err(Error::Encode(format!(
                "科目长度须在 1..={SUBJECT_LEN} 字节之间,实际 {} 字节",
                subject.len()
            )));
        }
        if !subject.iter().all(|&b| is_ascii_token_char(b)) {
            return Err(Error::Encode(
                "科目只能含大写字母、数字和连字符(-),如 WELDER-1G".into(),
            ));
        }

        if self.score > 1000 {
            return Err(Error::Encode("成绩范围为 0..=1000".into()));
        }
        Ok(())
    }

    /// 规范二进制编码(定长头部 + 变长姓名)。
    ///
    /// 布局:
    /// ```text
    /// [0]      version        u8
    /// [1..17]  serial         16 字节,右补 0x00
    /// [17]     name_len       u8
    /// [18..]   name           NFC UTF-8 字节
    /// [..+16]  subject        16 字节,右补 0x00
    /// [+2]     score          u16 大端
    /// [+4]     issued_on      u32 大端
    /// ```
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let name_bytes = self.name.as_bytes(); // 构造时已 NFC
        let mut out = Vec::with_capacity(1 + SERIAL_LEN + 1 + name_bytes.len() + SUBJECT_LEN + 6);
        out.push(RECORD_VERSION);

        let mut serial_buf = [0u8; SERIAL_LEN];
        serial_buf[..self.serial.len()].copy_from_slice(self.serial.as_bytes());
        out.extend_from_slice(&serial_buf);

        out.push(name_bytes.len() as u8);
        out.extend_from_slice(name_bytes);

        let mut subject_buf = [0u8; SUBJECT_LEN];
        subject_buf[..self.subject.len()].copy_from_slice(self.subject.as_bytes());
        out.extend_from_slice(&subject_buf);

        out.extend_from_slice(&self.score.to_be_bytes());
        out.extend_from_slice(&self.issued_on.to_be_bytes());
        Ok(out)
    }

    /// 严格解码:拒绝任何尾部多余字节、补位区污染、非法字段。
    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self> {
        let need_at_least = 1 + SERIAL_LEN + 1 + SUBJECT_LEN + 6;
        if buf.len() < need_at_least {
            return Err(Error::Decode(format!(
                "记录过短:{} 字节,至少需要 {need_at_least} 字节",
                buf.len()
            )));
        }
        let mut pos = 0;
        let version = buf[pos];
        pos += 1;
        if version != RECORD_VERSION {
            return Err(Error::Decode(format!("不支持的记录版本: {version:#x}")));
        }

        let serial_raw = &buf[pos..pos + SERIAL_LEN];
        pos += SERIAL_LEN;
        let serial_end = serial_raw.iter().position(|&b| b == 0).unwrap_or(serial_raw.len());
        // 补位区必须全是 0,防止利用补位位携带隐藏数据造成歧义
        if serial_raw[serial_end..].iter().any(|&b| b != 0) {
            return Err(Error::Decode("编号补位区含非零字节".into()));
        }
        let serial = std::str::from_utf8(&serial_raw[..serial_end])
            .map_err(|_| Error::Decode("编号不是合法 UTF-8".into()))?
            .to_string();

        let name_len = buf[pos] as usize;
        pos += 1;
        if pos + name_len + SUBJECT_LEN + 6 > buf.len() {
            return Err(Error::Decode("姓名长度超出缓冲区".into()));
        }
        let name_raw = &buf[pos..pos + name_len];
        pos += name_len;
        // NFC 校验在 validate 中完成;先按 UTF-8 解码
        let name = std::str::from_utf8(name_raw)
            .map_err(|_| Error::Decode("姓名不是合法 UTF-8".into()))?
            .to_string();

        let subject_raw = &buf[pos..pos + SUBJECT_LEN];
        pos += SUBJECT_LEN;
        let subject_end = subject_raw.iter().position(|&b| b == 0).unwrap_or(subject_raw.len());
        if subject_raw[subject_end..].iter().any(|&b| b != 0) {
            return Err(Error::Decode("科目补位区含非零字节".into()));
        }
        let subject = std::str::from_utf8(&subject_raw[..subject_end])
            .map_err(|_| Error::Decode("科目不是合法 UTF-8".into()))?
            .to_string();

        let score = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;
        let issued_on = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        if pos != buf.len() {
            return Err(Error::Decode(format!("记录尾部有 {} 字节多余数据", buf.len() - pos)));
        }

        let rec = CertificateRecord { serial, name, subject, score, issued_on };
        rec.validate()?;
        Ok(rec)
    }

    /// 规范记录的 SHA-256 摘要;签发清单中保存其截断版本。
    pub fn digest(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let bytes = self.to_canonical_bytes()?;
        Ok(Sha256::digest(bytes).into())
    }
}

/// 按编号排序,保证清单文件稳定可复现。
impl Ord for CertificateRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.serial.cmp(&other.serial)
    }
}
impl PartialOrd for CertificateRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_chinese_name() {
        let rec = CertificateRecord::new("CERT20260001", "张三", "WELDER-1G", 955, 20750).unwrap();
        let bytes = rec.to_canonical_bytes().unwrap();
        let back = CertificateRecord::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let rec = CertificateRecord::new("A-1", "李四·F", "NURSE", 880, 20000).unwrap();
        assert_eq!(rec.to_canonical_bytes().unwrap(), rec.to_canonical_bytes().unwrap());
    }

    #[test]
    fn rejects_tampered_padding() {
        let rec = CertificateRecord::new("A1", "王五", "NURSE", 600, 20000).unwrap();
        let mut bytes = rec.to_canonical_bytes().unwrap();
        bytes[5] = 0x7F; // 污染编号补位区
        assert!(CertificateRecord::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let rec = CertificateRecord::new("A1", "王五", "NURSE", 600, 20000).unwrap();
        let mut bytes = rec.to_canonical_bytes().unwrap();
        bytes.push(0);
        assert!(CertificateRecord::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn nfc_normalization_is_applied() {
        // U+00E9(é)与 e + U+0301(组合尖音符)NFC 后等价
        let a = CertificateRecord::new("A1", "café", "NURSE", 600, 20000).unwrap();
        let b = CertificateRecord::new("A1", "cafe\u{0301}", "NURSE", 600, 20000).unwrap();
        assert_eq!(a.to_canonical_bytes().unwrap(), b.to_canonical_bytes().unwrap());
    }

    #[test]
    fn digest_stable() {
        let rec = CertificateRecord::new("A1", "王五", "NURSE", 600, 20000).unwrap();
        assert_eq!(rec.digest().unwrap(), rec.digest().unwrap());
    }
}

//! 密码学层:Ed25519 签名信封与密钥管理。
//!
//! 信任层级:
//! - 根密钥(root):离线保管,用于签名"签发公钥目录"和"签发清单";
//! - 签发密钥(issuing):日常给证书签名,密钥泄露时可被根密钥废止。
//!
//! 不自行实现任何签名/哈希原语,全部使用 ed25519-dalek 与 sha2。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::record::CertificateRecord;

/// 二维码载荷起始魔数,便于扫描端快速识别本系统的码并拒绝其他 QR 内容。
pub const ENVELOPE_MAGIC: u8 = 0xC0;
/// 信封格式版本。
pub const ENVELOPE_VERSION: u8 = 0x01;
/// 签名长度(Ed25519)。
pub const SIGNATURE_LEN: usize = 64;
/// 域分离前缀:即使同一把密钥在别的系统签名,签名也无法跨场景复用。
pub const DOMAIN_SEP: &[u8] = b"certcode.io/signed-cert-record/v1";

/// 待签名的字节 = 魔数 + 信封版本 + 密钥编号 + 规范记录。
fn signing_input(key_id: u8, record: &CertificateRecord) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(3 + 64);
    input.push(ENVELOPE_MAGIC);
    input.push(ENVELOPE_VERSION);
    input.push(key_id);
    input.extend_from_slice(&record.to_canonical_bytes()?);
    Ok(input)
}

/// 加域分离后实际喂给 Ed25519 的消息。
fn dom_separated(prefix: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN_SEP.len() + 1 + prefix.len());
    m.push(DOMAIN_SEP.len() as u8);
    m.extend_from_slice(DOMAIN_SEP);
    m.extend_from_slice(prefix);
    m
}

/// 印在证书上的完整防伪码载荷:记录 + 签发密钥编号 + 签名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub key_id: u8,
    pub record: CertificateRecord,
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedEnvelope {
    /// 序列化为二维码字节流:
    /// `魔数 | 版本 | key_id | 规范记录 | 64 字节签名`
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = signing_input(self.key_id, &self.record)?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// 解析二维码字节流(此时尚未验签,调用方必须再走完整信任校验)。
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 3 + SIGNATURE_LEN {
            return Err(Error::Decode("信封过短".into()));
        }
        if buf[0] != ENVELOPE_MAGIC {
            return Err(Error::Decode(format!("魔数不匹配: {:#x}", buf[0])));
        }
        if buf[1] != ENVELOPE_VERSION {
            return Err(Error::Decode(format!("不支持的信封版本: {:#x}", buf[1])));
        }
        let key_id = buf[2];
        let record_end = buf.len() - SIGNATURE_LEN;
        let record = CertificateRecord::from_canonical_bytes(&buf[3..record_end])?;
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&buf[record_end..]);
        Ok(SignedEnvelope { key_id, record, signature })
    }

    /// 仅做密码学验签(信任策略在 trust 模块中另行检查)。
    pub fn verify_signature(&self, vk: &VerifyingKey) -> Result<()> {
        let input = signing_input(self.key_id, &self.record)?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&dom_separated(&input), &sig)
            .map_err(|_| Error::Signature("证书记录签名验证失败".into()))
    }
}

/// 签发身份:持有私钥时可签名;只分发公钥的核验端无法签名。
pub struct IssuingIdentity {
    pub key_id: u8,
    pub verifying: VerifyingKey,
    signing: Option<SigningKey>,
}

impl IssuingIdentity {
    pub fn generate(key_id: u8) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        IssuingIdentity { key_id, verifying, signing: Some(signing) }
    }

    pub fn public_only(key_id: u8, verifying: VerifyingKey) -> Self {
        IssuingIdentity { key_id, verifying, signing: None }
    }

    /// 给一条证书记录签名,生成可印刷的防伪信封。
    pub fn sign_record(&self, record: &CertificateRecord) -> Result<SignedEnvelope> {
        let sk = self
            .signing
            .as_ref()
            .ok_or_else(|| Error::Signature("这是仅含公钥的身份,无法签名".into()))?;
        let input = signing_input(self.key_id, record)?;
        let sig: Signature = sk.sign(&dom_separated(&input));
        Ok(SignedEnvelope { key_id: self.key_id, record: record.clone(), signature: sig.to_bytes() })
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }
}

/// 根身份:离线保管,签名信任目录与签发清单。
pub struct RootIdentity {
    pub verifying: VerifyingKey,
    /// crate 内可见:发证侧 CLI/Authority 需要重新装配带私钥的身份;
    /// 外部库使用者只能通过构造器访问,核验端加载时校验该字段为 None。
    pub(crate) signing: Option<SigningKey>,
}

impl RootIdentity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        RootIdentity { verifying: signing.verifying_key(), signing: Some(signing) }
    }

    pub fn public_only(verifying: VerifyingKey) -> Self {
        RootIdentity { verifying, signing: None }
    }

    /// 以完整根身份(含私钥)构造;仅发证侧调用,核验端禁止使用。
    pub fn with_signing(signing: SigningKey) -> Self {
        RootIdentity { verifying: signing.verifying_key(), signing: Some(signing) }
    }

    /// 根签名(对任意字节消息),内部加独立域分离。
    pub fn sign_message(&self, domain: &str, message: &[u8]) -> Result<[u8; 64]> {
        let sk = self
            .signing
            .as_ref()
            .ok_or_else(|| Error::Signature("根身份仅含公钥,无法签名".into()))?;
        let mut m = Vec::with_capacity(domain.len() + message.len() + 2);
        m.push(b'R');
        m.push(domain.len() as u8);
        m.extend_from_slice(domain.as_bytes());
        m.extend_from_slice(message);
        Ok(sk.sign(&m).to_bytes())
    }

    /// 根验签。
    pub fn verify_message(&self, domain: &str, message: &[u8], sig: &[u8; 64]) -> Result<()> {
        let mut m = Vec::with_capacity(domain.len() + message.len() + 2);
        m.push(b'R');
        m.push(domain.len() as u8);
        m.extend_from_slice(domain.as_bytes());
        m.extend_from_slice(message);
        let sig = Signature::from_bytes(sig);
        self.verifying
            .verify(&m, &sig)
            .map_err(|_| Error::Signature("根签名验证失败".into()))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// 是否持有签名能力(核验端加载的根身份应为 false)。
    pub fn is_signing_capable(&self) -> bool {
        self.signing.is_some()
    }
}

/// 密钥落盘格式(私钥文件必须离线介质保存,权限 0600)。
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredKey {
    /// `root` 或 `issuing`
    pub kind: String,
    #[serde(default)]
    pub key_id: Option<u8>,
    pub public_base64: String,
    /// 仅私钥文件存在;公钥分发文件中省略该字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_base64: Option<String>,
}

impl StoredKey {
    pub fn from_root(root: &RootIdentity, include_secret: bool) -> Self {
        StoredKey {
            kind: "root".into(),
            key_id: None,
            public_base64: B64.encode(root.public_bytes()),
            secret_base64: root.signing.as_ref().map(|sk| B64.encode(sk.to_bytes())).filter(|_| include_secret),
        }
    }

    pub fn from_issuing(id: &IssuingIdentity, include_secret: bool) -> Self {
        StoredKey {
            kind: "issuing".into(),
            key_id: Some(id.key_id),
            public_base64: B64.encode(id.public_bytes()),
            secret_base64: id
                .signing
                .as_ref()
                .map(|sk| B64.encode(sk.to_bytes()))
                .filter(|_| include_secret),
        }
    }

    pub fn to_root_identity(&self) -> Result<RootIdentity> {
        if self.kind != "root" {
            return Err(Error::Bundle("密钥文件类型不是 root".into()));
        }
        let vk = decode_verifying(&self.public_base64)?;
        if let Some(sec) = &self.secret_base64 {
            let sk = decode_signing(sec)?;
            if sk.verifying_key().to_bytes() != vk.to_bytes() {
                return Err(Error::Bundle("根密钥公钥与私钥不匹配".into()));
            }
            Ok(RootIdentity { verifying: sk.verifying_key(), signing: Some(sk) })
        } else {
            Ok(RootIdentity::public_only(vk))
        }
    }

    pub fn to_issuing_identity(&self) -> Result<IssuingIdentity> {
        if self.kind != "issuing" {
            return Err(Error::Bundle("密钥文件类型不是 issuing".into()));
        }
        let key_id = self.key_id.ok_or_else(|| Error::Bundle("签发密钥缺少 key_id".into()))?;
        let vk = decode_verifying(&self.public_base64)?;
        if let Some(sec) = &self.secret_base64 {
            let sk = decode_signing(sec)?;
            if sk.verifying_key().to_bytes() != vk.to_bytes() {
                return Err(Error::Bundle("签发密钥公钥与私钥不匹配".into()));
            }
            Ok(IssuingIdentity { key_id, verifying: sk.verifying_key(), signing: Some(sk) })
        } else {
            Ok(IssuingIdentity::public_only(key_id, vk))
        }
    }
}

fn decode_verifying(s: &str) -> Result<VerifyingKey> {
    let bytes = B64
        .decode(s.trim())
        .map_err(|e| Error::Bundle(format!("公钥 base64 解码失败: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Bundle("公钥长度不是 32 字节".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::Bundle(format!("公钥非法: {e}")))
}

fn decode_signing(s: &str) -> Result<SigningKey> {
    let bytes = B64
        .decode(s.trim())
        .map_err(|e| Error::Bundle(format!("私钥 base64 解码失败: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Bundle("私钥长度不是 32 字节".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// 记录摘要的截断长度(签发清单中每张证书保存 10 字节)。
///
/// 2^80 ≈ 1.2×10^24 的碰撞空间,针对单张证书的定向伪造在物理上不可行,
/// 同时把百万级证书清单控制在约 10 MB。
pub const TRUNCATED_DIGEST_LEN: usize = 10;

/// 计算清单中使用的截断摘要(记录规范编码 SHA-256 的前 10 字节)。
pub fn truncated_digest(record: &CertificateRecord) -> Result<[u8; TRUNCATED_DIGEST_LEN]> {
    let full = record.digest()?;
    let mut out = [0u8; TRUNCATED_DIGEST_LEN];
    out.copy_from_slice(&full[..TRUNCATED_DIGEST_LEN]);
    Ok(out)
}

/// 供清单/目录使用的辅助哈希。
pub fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CertificateRecord {
        CertificateRecord::new("CERT20260001", "张三", "WELDER-1G", 955, 20750).unwrap()
    }

    #[test]
    fn sign_and_verify_envelope() {
        let issuer = IssuingIdentity::generate(1);
        let env = issuer.sign_record(&sample()).unwrap();
        let bytes = env.to_bytes().unwrap();
        let parsed = SignedEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, env);
        parsed.verify_signature(&issuer.verifying).unwrap();
    }

    #[test]
    fn tampered_record_fails_verification() {
        let issuer = IssuingIdentity::generate(1);
        let env = issuer.sign_record(&sample()).unwrap();
        let mut bytes = env.to_bytes().unwrap();
        // 翻转成绩区域的一个比特
        let score_pos = bytes.len() - SIGNATURE_LEN - 4;
        bytes[score_pos] ^= 0x01;
        let parsed = SignedEnvelope::from_bytes(&bytes).unwrap();
        assert!(parsed.verify_signature(&issuer.verifying).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let issuer = IssuingIdentity::generate(1);
        let other = IssuingIdentity::generate(2);
        let env = issuer.sign_record(&sample()).unwrap();
        assert!(env.verify_signature(&other.verifying).is_err());
    }

    #[test]
    fn root_signature_roundtrip() {
        let root = RootIdentity::generate();
        let msg = b"hello trust bundle";
        let sig = root.sign_message("test-domain", msg).unwrap();
        root.verify_message("test-domain", msg, &sig).unwrap();
        assert!(root.verify_message("other-domain", msg, &sig).is_err());
    }

    #[test]
    fn stored_key_roundtrip() {
        let issuer = IssuingIdentity::generate(7);
        let stored = StoredKey::from_issuing(&issuer, true);
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredKey = serde_json::from_str(&json).unwrap();
        let restored = back.to_issuing_identity().unwrap();
        let env = restored.sign_record(&sample()).unwrap();
        env.verify_signature(&issuer.verifying).unwrap();
    }

    #[test]
    fn public_only_key_cannot_sign() {
        let issuer = IssuingIdentity::generate(1);
        let pub_only = IssuingIdentity::public_only(1, issuer.verifying);
        assert!(pub_only.sign_record(&sample()).is_err());
    }
}

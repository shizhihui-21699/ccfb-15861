//! # certcode — 印刷证书的离线密码学防伪码
//!
//! ## 信任模型
//!
//! ```text
//! 离线根密钥(root,Ed25519)
//!   ├── 签名签发公钥目录(含 active/compromised 状态)
//!   └── 签名签发清单(每张真证书的截断摘要)
//!
//! 签发密钥(issuing,Ed25519)
//!   └── 对每张证书的规范记录签名 → 印成 QR(H 级纠错)
//!
//! 手机核验端(离线)
//!   ├── 扫 QR → 解析信封 → 用目录公钥验签
//!   ├── 查签发清单确认该编号+内容确认真实签发
//!   └── 密钥已泄露时:清单内旧证 VERIFIED,清单外伪造 REJECTED
//! ```
//!
//! ## 模块
//! - [`record`] — 证书记录与定长规范二进制编码
//! - [`crypto`] — Ed25519 签名信封、密钥管理
//! - [`trust`] — 根签名目录/签发清单、泄露处置、核验策略
//! - [`qr`] — H 级纠错 QR 码渲染与识别
//! - [`degrade`] — 复印/传真/拍照退化模拟器(测试用)

pub mod crypto;
pub mod degrade;
pub mod error;
pub mod qr;
pub mod record;
pub mod trust;

use std::path::Path;

use crypto::{IssuingIdentity, SignedEnvelope};
use error::Result;
use qr::QrOptions;
use record::CertificateRecord;
use trust::{TrustBundle, VerificationReport};

pub use error::Error;

/// 发证端一步完成:记录 → 签名 → 渲染 PNG 防伪码。
pub fn issue_code(
    identity: &IssuingIdentity,
    record: &CertificateRecord,
    out_png: &Path,
    opts: &QrOptions,
) -> Result<(SignedEnvelope, qr::GeneratedQr)> {
    let envelope = identity.sign_record(record)?;
    let payload = envelope.to_bytes()?;
    let info = qr::render_png(&payload, out_png, opts)?;
    Ok((envelope, info))
}

/// 核验端一步完成:图像 → 解码 → 完整信任校验。
pub fn verify_image(
    bundle: &TrustBundle,
    image_path: &Path,
    today: u32,
) -> Result<(VerificationReport, CertificateRecord)> {
    let payload = qr::decode_image(image_path)?;
    let envelope = SignedEnvelope::from_bytes(&payload)?;
    let report = bundle.verify(&envelope, today)?;
    Ok((report, envelope.record))
}

/// 核验端:直接对已解码字节做校验(供自定义扫码器接入)。
pub fn verify_payload(
    bundle: &TrustBundle,
    payload: &[u8],
    today: u32,
) -> Result<(VerificationReport, CertificateRecord)> {
    let envelope = SignedEnvelope::from_bytes(payload)?;
    let report = bundle.verify(&envelope, today)?;
    Ok((report, envelope.record))
}

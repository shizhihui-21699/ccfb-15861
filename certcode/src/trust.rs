//! 离线信任体系:根密钥签名的密钥目录 + 签发清单。
//!
//! 应对私钥泄露的关键设计:
//! 1. 每张证书的截断摘要(10 字节)进入根签名的签发清单;
//! 2. 签发密钥泄露后,根密钥在目录中将其标记为 `compromised`;
//! 3. 旧真证书:密码学签名有效且摘要在清单中 → 继续 VERIFIED;
//! 4. 攻击者用泄露私钥伪造的新证书:摘要不在清单中 → REJECTED。
//!
//! 核验端不需要联网,只需定期更新这份根签名的信任包。

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    sha256_hex, truncated_digest, IssuingIdentity, RootIdentity, SignedEnvelope, TRUNCATED_DIGEST_LEN,
};
use crate::error::{Error, Result};

/// 签发密钥状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// 正常使用
    Active,
    /// 私钥疑似/确认泄露:仅清单内旧证书可信
    Compromised,
}

/// 目录中的一把签发公钥。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub key_id: u8,
    pub public_base64: String,
    pub status: KeyStatus,
    /// 自纪元天数;记录在该日期(含)之后签发才视为时间有效
    pub valid_from: u32,
    /// 失效日(不含);null 表示长期有效
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<u32>,
    pub added_on: u32,
}

/// 根签名的签发公钥目录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDirectory {
    pub schema: u8,
    pub generated_on: u32,
    pub keys: Vec<KeyEntry>,
}

impl KeyDirectory {
    pub const DOMAIN: &'static str = "key-directory/v1";

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // BTreeMap 保证键序稳定;to_vec 保证不同机器字节一致
        let value = serde_json::to_value(self)
            .map_err(|e| Error::Bundle(format!("目录序列化失败: {e}")))?;
        canonical_json(&value)
    }

    pub fn get(&self, key_id: u8) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

/// 某把签发密钥的签发清单(根签名),覆盖一个连续编号区间内的全部证书。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceManifest {
    pub schema: u8,
    pub key_id: u8,
    /// 区间内第一张证书编号
    pub serial_first: String,
    /// 区间内最后一张证书编号
    pub serial_last: String,
    pub issued_on: u32,
    /// 按字典序升序的证书编号,与 digests_base64 一一对应。
    /// 显式保存编号(每条约 12 字节)换来看不见的字符集/跳号假设,核验用二分查找。
    pub serials: Vec<String>,
    /// 按 serials 同序排列的截断摘要,每条 10 字节 base64
    pub digests_base64: Vec<String>,
}

impl IssuanceManifest {
    pub const DOMAIN: &'static str = "issuance-manifest/v1";

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|e| Error::Bundle(format!("清单序列化失败: {e}")))?;
        canonical_json(&value)
    }

    /// 解析全部截断摘要为定长字节数组。
    pub fn digest_bytes(&self) -> Result<Vec<[u8; TRUNCATED_DIGEST_LEN]>> {
        self.digests_base64
            .iter()
            .map(|s| {
                let raw = B64
                    .decode(s)
                    .map_err(|e| Error::Bundle(format!("清单摘要 base64 失败: {e}")))?;
                if raw.len() != TRUNCATED_DIGEST_LEN {
                    return Err(Error::Bundle(format!(
                        "清单摘要长度应为 {TRUNCATED_DIGEST_LEN} 字节,实际 {}",
                        raw.len()
                    )));
                }
                let mut arr = [0u8; TRUNCATED_DIGEST_LEN];
                arr.copy_from_slice(&raw);
                Ok(arr)
            })
            .collect()
    }

    /// 信任包加载时的结构自校验(根签名已保证来源可信,这里防格式损坏)。
    pub fn validate_structure(&self) -> Result<()> {
        if self.serials.len() != self.digests_base64.len() || self.serials.is_empty() {
            return Err(Error::Bundle(format!(
                "key{} 清单:serials({}) 与 digests({}) 数量不一致或为空",
                self.key_id,
                self.serials.len(),
                self.digests_base64.len()
            )));
        }
        let mut sorted_unique: Vec<&String> = self.serials.iter().collect();
        sorted_unique.sort();
        sorted_unique.dedup();
        if sorted_unique.len() != self.serials.len() {
            return Err(Error::Bundle(format!("key{} 清单存在重复编号", self.key_id)));
        }
        let in_order: Vec<&String> = self.serials.iter().collect();
        if in_order != sorted_unique {
            return Err(Error::Bundle(format!("key{} 清单编号未按升序排列", self.key_id)));
        }
        if self.serial_first != self.serials[0] || self.serial_last != *self.serials.last().unwrap() {
            return Err(Error::Bundle(format!(
                "key{} 清单区间端点与编号数组不一致", self.key_id
            )));
        }
        // 提前验证每条摘要可解码
        self.digest_bytes()?;
        Ok(())
    }
}

/// 根签名外壳:payload 是规范 JSON 的 base64。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWrapper {
    pub payload_base64: String,
    pub signature_base64: String,
    pub signed_sha256: String,
}

impl SignedWrapper {
    pub fn sign<T: ?Sized + serde::Serialize>(
        root: &RootIdentity,
        domain: &str,
        payload: &T,
    ) -> Result<Self> {
        let value = serde_json::to_value(payload)
            .map_err(|e| Error::Bundle(format!("序列化失败: {e}")))?;
        let raw = canonical_json(&value)?;
        let sig = root.sign_message(domain, &raw)?;
        Ok(SignedWrapper {
            payload_base64: B64.encode(&raw),
            signature_base64: B64.encode(sig),
            signed_sha256: sha256_hex(&raw),
        })
    }

    /// 验根签并还原 payload。返回的是解析后的 JSON 结构。
    pub fn open<T: serde::de::DeserializeOwned>(&self, root: &RootIdentity, domain: &str) -> Result<T> {
        let raw = B64
            .decode(&self.payload_base64)
            .map_err(|e| Error::Bundle(format!("payload base64 失败: {e}")))?;
        let sig_bytes = B64
            .decode(&self.signature_base64)
            .map_err(|e| Error::Bundle(format!("签名 base64 失败: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(Error::Bundle("根签名长度不是 64 字节".into()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        root.verify_message(domain, &raw, &sig)?;

        // 防止文件被改 payload 后只重算 sha256:真正的门槛是上面的根验签
        if sha256_hex(&raw) != self.signed_sha256 {
            return Err(Error::Bundle("signed_sha256 与 payload 不一致".into()));
        }
        serde_json::from_slice(&raw).map_err(|e| Error::Bundle(format!("payload 解析失败: {e}")))
    }
}

/// 核验端持有的完整离线信任包。
pub struct TrustBundle {
    pub root: RootIdentity,
    pub directory: KeyDirectory,
    /// key_id → 该密钥的清单(可有多份,覆盖不同编号区间)
    manifests: BTreeMap<u8, Vec<IssuanceManifest>>,
}

/// 核验结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 签名有效、密钥可信、记录在签发清单中
    Verified,
    /// 密码学有效但不在清单覆盖范围(新证尚未发布清单,或可疑)
    Untrusted,
    /// 明确拒绝(签名坏、密钥泄露且无清单记录等)
    Rejected,
}

/// 带解释的核验结果。
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub verdict: Verdict,
    pub key_id: u8,
    pub serial: String,
    pub detail: String,
}

impl TrustBundle {
    /// 从目录加载信任包:`root.json`、`directory.signed.json`、`manifests/*.signed.json`
    pub fn load(dir: &Path) -> Result<Self> {
        let root_path = dir.join("root.json");
        let stored: crate::crypto::StoredKey =
            serde_json::from_slice(&fs::read(&root_path)?).map_err(|e| {
                Error::Bundle(format!("root.json 解析失败: {e}"))
            })?;
        let root = stored.to_root_identity()?;
        if root.is_signing_capable() {
            return Err(Error::Bundle(
                "核验端的 root.json 不得包含根私钥,请只分发公钥文件".into(),
            ));
        }

        let wrapper: SignedWrapper = serde_json::from_slice(
            &fs::read(dir.join("directory.signed.json"))?,
        )
        .map_err(|e| Error::Bundle(format!("directory.signed.json 解析失败: {e}")))?;
        let directory: KeyDirectory = wrapper.open(&root, KeyDirectory::DOMAIN)?;

        let mut manifests: BTreeMap<u8, Vec<IssuanceManifest>> = BTreeMap::new();
        let mdir = dir.join("manifests");
        if mdir.is_dir() {
            for entry in fs::read_dir(&mdir)? {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let mw: SignedWrapper = serde_json::from_slice(&fs::read(&path)?)
                    .map_err(|e| Error::Bundle(format!("{} 解析失败: {e}", path.display())))?;
                let manifest: IssuanceManifest = mw.open(&root, IssuanceManifest::DOMAIN)?;
                manifest.validate_structure()?;
                manifests.entry(manifest.key_id).or_default().push(manifest);
            }
        }
        for list in manifests.values_mut() {
            list.sort_by(|a, b| a.serial_first.cmp(&b.serial_first));
        }
        Ok(TrustBundle { root, directory, manifests })
    }

    pub fn root_public_bytes(&self) -> [u8; 32] {
        self.root.public_bytes()
    }

    /// 用已通过根验签的目录与清单构造信任包(测试或自定义分发通道使用)。
    /// 调用方须保证 directory/manifests 均已用对应根公钥验签。
    pub fn from_parts(
        root: RootIdentity,
        directory: KeyDirectory,
        manifests: BTreeMap<u8, Vec<IssuanceManifest>>,
    ) -> Self {
        TrustBundle { root, directory, manifests }
    }

    /// 完整离线核验。
    pub fn verify(&self, envelope: &SignedEnvelope, today: u32) -> Result<VerificationReport> {
        let key_id = envelope.key_id;
        let serial = envelope.record.serial.clone();
        let reject = |detail: String| {
            Ok(VerificationReport { verdict: Verdict::Rejected, key_id, serial: serial.clone(), detail })
        };

        let entry = match self.directory.get(key_id) {
            Some(e) => e,
            None => return reject(format!("密钥编号 {key_id} 不在根签名目录中")),
        };

        // 1. 密码学验签
        let vk_bytes: [u8; 32] = B64
            .decode(&entry.public_base64)
            .map_err(|e| Error::Bundle(format!("目录公钥 base64 失败: {e}")))?
            .try_into()
            .map_err(|_| Error::Bundle("目录公钥长度错误".into()))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| Error::Bundle(format!("目录公钥非法: {e}")))?;
        if let Err(e) = envelope.verify_signature(&vk) {
            return reject(e.to_string());
        }

        // 2. 签发清单检查(抵御泄露密钥伪造)
        let target = truncated_digest(&envelope.record)?;
        let in_manifest = self.find_in_manifests(key_id, &serial, &target)?;

        // 3. 结合密钥状态给出结论
        match entry.status {
            KeyStatus::Compromised => {
                if in_manifest {
                    Ok(VerificationReport {
                        verdict: Verdict::Verified,
                        key_id,
                        serial,
                        detail: "签发密钥已废止,但该证书在根签名签发清单中,旧证继续有效".into(),
                    })
                } else {
                    reject(
                        "签发密钥已标记泄露/废止,且该证书不在签发清单中:疑似伪造".into(),
                    )
                }
            }
            KeyStatus::Active => {
                if in_manifest {
                    return Ok(VerificationReport {
                        verdict: Verdict::Verified,
                        key_id,
                        serial,
                        detail: "签名有效且记录与签发清单一致".into(),
                    });
                }
                // 不在清单:再看时间窗口
                if today < entry.valid_from {
                    return reject(format!(
                        "证书早于密钥生效日(今天 {today} < valid_from {})",
                        entry.valid_from
                    ));
                }
                if let Some(to) = entry.valid_to {
                    if today >= to {
                        return reject(format!("密钥已于 {to} 失效(今天 {today})"));
                    }
                }
                Ok(VerificationReport {
                    verdict: Verdict::Untrusted,
                    key_id,
                    serial,
                    detail: "密码学签名有效,但证书尚未进入任何根签名签发清单,无法排除伪造".into(),
                })
            }
        }
    }

    /// 在某把密钥的全部清单中查找该编号 + 截断摘要。
    fn find_in_manifests(
        &self,
        key_id: u8,
        serial: &str,
        target: &[u8; TRUNCATED_DIGEST_LEN],
    ) -> Result<bool> {
        let Some(lists) = self.manifests.get(&key_id) else {
            return Ok(false);
        };
        for m in lists {
            // 编号落在本清单的闭区间内才可能命中
            if serial < m.serial_first.as_str() || serial > m.serial_last.as_str() {
                continue;
            }
            // 显式编号数组上做二分查找,不依赖编号字符集或连续性假设
            let Ok(idx) = m.serials.binary_search(&serial.to_string()) else {
                continue;
            };
            let digests = m.digest_bytes()?;
            if idx >= digests.len() || m.serials.len() != digests.len() {
                return Err(Error::Bundle(format!(
                    "key{key_id} 清单结构损坏:serials 与 digests 数量不一致"
                )));
            }
            return Ok(&digests[idx] == target);
        }
        Ok(false)
    }
}

/// 发证端使用:构建并维护目录/清单(持有根私钥的离线机器上运行)。
pub struct Authority {
    pub root: RootIdentity,
    pub directory: KeyDirectory,
    /// key_id → 待发布的清单累积
    pending: BTreeMap<u8, Vec<(String, [u8; TRUNCATED_DIGEST_LEN])>>,
}

impl Authority {
    pub fn new(root: RootIdentity, generated_on: u32) -> Self {
        Authority {
            root,
            directory: KeyDirectory { schema: 1, generated_on, keys: Vec::new() },
            pending: BTreeMap::new(),
        }
    }

    /// 打开发证侧工作副本:载入已有目录(需持有根私钥才能执行后续发布操作)。
    pub fn open(root: RootIdentity, directory: KeyDirectory) -> Self {
        Authority { root, directory, pending: BTreeMap::new() }
    }

    /// 登记一把新的签发公钥。
    pub fn register_issuing_key(
        &mut self,
        identity: &IssuingIdentity,
        valid_from: u32,
        valid_to: Option<u32>,
        today: u32,
    ) -> Result<()> {
        if self.directory.keys.iter().any(|k| k.key_id == identity.key_id) {
            return Err(Error::Trust(format!("key_id {} 已存在,目录条目不可修改", identity.key_id)));
        }
        self.directory.keys.push(KeyEntry {
            key_id: identity.key_id,
            public_base64: B64.encode(identity.public_bytes()),
            status: KeyStatus::Active,
            valid_from,
            valid_to,
            added_on: today,
        });
        self.directory.keys.sort_by_key(|k| k.key_id);
        Ok(())
    }

    /// 密钥泄露:只能 active → compromised,单向不可逆。
    pub fn mark_compromised(&mut self, key_id: u8) -> Result<KeyEntry> {
        let entry = self
            .directory
            .keys
            .iter_mut()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| Error::Trust(format!("key_id {key_id} 不存在")))?;
        entry.status = KeyStatus::Compromised;
        Ok(entry.clone())
    }

    /// 把一张已签发证书加入待发布清单。
    pub fn record_issuance(&mut self, envelope: &SignedEnvelope) -> Result<()> {
        let digest = truncated_digest(&envelope.record)?;
        let list = self.pending.entry(envelope.key_id).or_default();
        if list.iter().any(|(s, _)| s == &envelope.record.serial) {
            return Err(Error::Trust(format!("编号 {} 已在待发布清单中", envelope.record.serial)));
        }
        list.push((envelope.record.serial.clone(), digest));
        Ok(())
    }

    /// 生成某把密钥当前累积记录的签发清单(根签名外壳)。
    pub fn publish_manifest(&mut self, key_id: u8, today: u32) -> Result<(IssuanceManifest, SignedWrapper)> {
        let mut entries = self.pending.remove(&key_id).unwrap_or_default();
        if entries.is_empty() {
            return Err(Error::Trust(format!("key_id {key_id} 没有待发布的签发记录")));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let serial_first = entries.first().unwrap().0.clone();
        let serial_last = entries.last().unwrap().0.clone();
        let serials = entries.iter().map(|(s, _)| s.clone()).collect();
        let digests_base64 = entries.iter().map(|(_, d)| B64.encode(d)).collect();
        let manifest = IssuanceManifest {
            schema: 1,
            key_id,
            serial_first,
            serial_last,
            serials,
            issued_on: today,
            digests_base64,
        };
        let wrapper = SignedWrapper::sign(&self.root, IssuanceManifest::DOMAIN, &manifest)?;
        Ok((manifest, wrapper))
    }

    /// 生成根签名的目录外壳。
    pub fn signed_directory(&self) -> Result<SignedWrapper> {
        SignedWrapper::sign(&self.root, KeyDirectory::DOMAIN, &self.directory)
    }
}

/// 规范 JSON:对象键按字典序、无多余空白、UTF-8。
/// 保证根签名在不同机器/serde 版本间可复现。
fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    fn sort_in_place(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for child in map.values_mut() {
                    sort_in_place(child);
                }
                // 默认(未开 preserve_order)Map 即 BMap 后端,键天然有序;
                // 这里显式收集再重建,保证任何编译特性下顺序都确定。
                let entries: Vec<(String, serde_json::Value)> =
                    std::mem::take(map).into_iter().collect();
                let mut sorted = serde_json::Map::new();
                for (k, val) in entries {
                    sorted.insert(k, val);
                }
                *map = sorted;
            }
            serde_json::Value::Array(arr) => {
                for child in arr {
                    sort_in_place(child);
                }
            }
            _ => {}
        }
    }
    let mut v = value.clone();
    sort_in_place(&mut v);
    // serde_json 对 BTreeMap 按键序输出;无空白分隔符
    let s = serde_json::to_string(&v).map_err(|e| Error::Bundle(format!("canonical JSON 失败: {e}")))?;
    Ok(s.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IssuingIdentity;
    use crate::record::CertificateRecord;

    fn record(serial: &str, score: u16) -> CertificateRecord {
        CertificateRecord::new(serial, "张三", "WELDER-1G", score, 20750).unwrap()
    }

    /// 构造带根签名能力的 Authority(测试环境,生产环境根私钥只在离线机器)。
    fn setup_authority() -> (RootIdentity, IssuingIdentity, Authority) {
        let root = RootIdentity::generate();
        let root_pub = RootIdentity::public_only(root.verifying);
        let issuer = IssuingIdentity::generate(1);
        let mut auth = Authority::new(root, 20750);
        auth.register_issuing_key(&issuer, 20000, None, 20750).unwrap();
        (root_pub, issuer, auth)
    }

    #[test]
    fn full_lifecycle_including_leak() {
        let (root_pub, issuer, mut auth) = setup_authority();

        // 1. 签发两张真证书
        let env1 = issuer.sign_record(&record("CERT2026000001", 900)).unwrap();
        let env2 = issuer.sign_record(&record("CERT2026000002", 850)).unwrap();
        auth.record_issuance(&env1).unwrap();
        auth.record_issuance(&env2).unwrap();

        // 2. 密钥泄露!根密钥废止它
        auth.mark_compromised(1).unwrap();

        // 3. 攻击者用泄露私钥伪造一张新证书(密码学上完全合法)
        let forged = issuer.sign_record(&record("CERT2026000003", 1000)).unwrap();

        // 4. 发布清单与目录(均带根签名)
        let (_, manifest_wrapper) = auth.publish_manifest(1, 20750).unwrap();
        let dir_wrapper = auth.signed_directory().unwrap();
        let manifest: IssuanceManifest =
            manifest_wrapper.open(&auth.root, IssuanceManifest::DOMAIN).unwrap();
        let directory: KeyDirectory =
            dir_wrapper.open(&auth.root, KeyDirectory::DOMAIN).unwrap();

        let bundle = TrustBundle {
            root: root_pub,
            directory,
            manifests: BTreeMap::from([(1, vec![manifest])]),
        };

        // 旧真证书:密钥已废止但仍在清单中 → 继续可信
        let r1 = bundle.verify(&env1, 20760).unwrap();
        assert_eq!(r1.verdict, Verdict::Verified, "{}", r1.detail);
        let r2 = bundle.verify(&env2, 20760).unwrap();
        assert_eq!(r2.verdict, Verdict::Verified);

        // 伪造证书:不在清单 → 拒绝
        let rf = bundle.verify(&forged, 20760).unwrap();
        assert_eq!(rf.verdict, Verdict::Rejected, "{}", rf.detail);

        // 篡改真证书成绩:密码学验签先失败 → 拒绝
        let mut tampered_bytes = env1.to_bytes().unwrap();
        let p = tampered_bytes.len() - 64 - 4;
        tampered_bytes[p] ^= 0x01;
        let tampered = SignedEnvelope::from_bytes(&tampered_bytes).unwrap();
        let rt = bundle.verify(&tampered, 20760).unwrap();
        assert_eq!(rt.verdict, Verdict::Rejected);
    }

    #[test]
    fn active_key_without_manifest_is_untrusted() {
        let root = RootIdentity::generate();
        let issuer = IssuingIdentity::generate(1);
        let directory = KeyDirectory {
            schema: 1,
            generated_on: 20750,
            keys: vec![KeyEntry {
                key_id: 1,
                public_base64: B64.encode(issuer.public_bytes()),
                status: KeyStatus::Active,
                valid_from: 20000,
                valid_to: None,
                added_on: 20750,
            }],
        };
        let bundle = TrustBundle {
            root: RootIdentity::public_only(root.verifying),
            directory,
            manifests: BTreeMap::new(),
        };
        let env = issuer.sign_record(&record("CERT2026000001", 900)).unwrap();
        let report = bundle.verify(&env, 20760).unwrap();
        assert_eq!(report.verdict, Verdict::Untrusted);
    }

    #[test]
    fn tampered_trust_bundle_fails_root_signature() {
        let root = RootIdentity::generate();
        let dir = KeyDirectory { schema: 1, generated_on: 1, keys: vec![] };
        let mut wrapper = SignedWrapper::sign(&root, KeyDirectory::DOMAIN, &dir).unwrap();
        wrapper.signed_sha256 = "00".repeat(32);
        let res: Result<KeyDirectory> =
            wrapper.open(&RootIdentity::public_only(root.verifying), KeyDirectory::DOMAIN);
        assert!(res.is_err());
    }

    #[test]
    fn canonical_json_is_stable() {
        let dir = KeyDirectory {
            schema: 1,
            generated_on: 20750,
            keys: vec![KeyEntry {
                key_id: 1,
                public_base64: "AA".into(),
                status: KeyStatus::Active,
                valid_from: 1,
                valid_to: None,
                added_on: 1,
            }],
        };
        assert_eq!(dir.canonical_bytes().unwrap(), dir.canonical_bytes().unwrap());
    }
}

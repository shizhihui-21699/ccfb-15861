//! 端到端测试:发证 → 印刷退化 → 扫码核验 → 密钥泄露处置 全链路。

use std::collections::BTreeMap;
use std::fs;

use certcode::crypto::{IssuingIdentity, RootIdentity, SignedEnvelope};
use certcode::degrade::Degradation;
use certcode::qr;
use certcode::record::CertificateRecord;
use certcode::trust::{
    Authority, IssuanceManifest, KeyDirectory, KeyEntry, KeyStatus, TrustBundle, Verdict,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

fn rec(serial: &str, score: u16) -> CertificateRecord {
    CertificateRecord::new(serial, "张三", "WELDER-1G", score, 20750).unwrap()
}

fn build_bundle(
    root: &RootIdentity,
    issuer: &IssuingIdentity,
    manifests: Vec<IssuanceManifest>,
    status: KeyStatus,
) -> TrustBundle {
    let directory = KeyDirectory {
        schema: 1,
        generated_on: 20750,
        keys: vec![KeyEntry {
            key_id: issuer.key_id,
            public_base64: B64.encode(issuer.public_bytes()),
            status,
            valid_from: 20000,
            valid_to: None,
            added_on: 20750,
        }],
    };
    TrustBundle::from_parts(
        RootIdentity::public_only(root.verifying),
        directory,
        BTreeMap::from([(issuer.key_id, manifests)]),
    )
}

#[test]
fn full_lifecycle_with_manifest() {
    let root = RootIdentity::generate();
    let root_pub = RootIdentity::public_only(root.verifying);
    let issuer = IssuingIdentity::generate(3);
    let mut auth = Authority::new(root, 20750);
    auth.register_issuing_key(&issuer, 20000, None, 20750).unwrap();

    // 连续同宽编号签发 5 张
    let mut envs = vec![];
    for i in 1..=5u32 {
        let serial = format!("CERT2026{i:06}");
        let env = issuer.sign_record(&rec(&serial, 800 + i as u16 * 10)).unwrap();
        auth.record_issuance(&env).unwrap();
        envs.push(env);
    }
    let (manifest, _) = auth.publish_manifest(3, 20750).unwrap();
    let bundle = build_bundle(&root_pub, &issuer, vec![manifest], KeyStatus::Active);

    for env in &envs {
        let report = bundle.verify(env, 20760).unwrap();
        assert_eq!(report.verdict, Verdict::Verified, "{}", report.detail);
    }

    // 区间内但摘要被换(改成绩):拒绝
    let mut fake = envs[2].clone();
    fake.record.score = 1000;
    let report = bundle.verify(&fake, 20760).unwrap();
    assert_eq!(report.verdict, Verdict::Rejected);
}

#[test]
fn leak_scenario_old_certs_survive_forgeries_rejected() {
    let root = RootIdentity::generate();
    let root_pub = RootIdentity::public_only(root.verifying);
    let issuer = IssuingIdentity::generate(1);
    let mut auth = Authority::new(root, 20750);
    auth.register_issuing_key(&issuer, 20000, None, 20750).unwrap();

    let genuine: Vec<_> = (1..=3)
        .map(|i| {
            let env = issuer
                .sign_record(&rec(&format!("CERT2026{i:06}"), 700 + i * 10))
                .unwrap();
            auth.record_issuance(&env).unwrap();
            env
        })
        .collect();

    // 泄露后:先发布全部旧证清单,再废止
    let (manifest, _) = auth.publish_manifest(1, 20750).unwrap();
    auth.mark_compromised(1).unwrap();
    let bundle = build_bundle(&root_pub, &issuer, vec![manifest], KeyStatus::Compromised);

    // 旧证依旧 VERIFIED
    for env in &genuine {
        let r = bundle.verify(env, 20800).unwrap();
        assert_eq!(r.verdict, Verdict::Verified, "{}", r.detail);
    }

    // 攻击者拿泄露私钥签的新证:密码学合法但清单无记录 → REJECTED
    let forged = issuer.sign_record(&rec("CERT2026000004", 1000)).unwrap();
    let r = bundle.verify(&forged, 20800).unwrap();
    assert_eq!(r.verdict, Verdict::Rejected);

    // 攻击者还尝试重号伪造(同编号改成绩):摘要不匹配 → REJECTED
    let mut collision = genuine[0].clone();
    collision.record.name = "李四".to_string();
    let r = bundle.verify(&collision, 20800).unwrap();
    assert_eq!(r.verdict, Verdict::Rejected);

    // 最强攻击:攻击者用泄露的私钥对同号改分记录重新签名,
    // 密码学上完全合法,但摘要与清单中该编号的真证不一致 → REJECTED
    let mut forged_record = genuine[0].record.clone();
    forged_record.score = 1000;
    let resigned = issuer.sign_record(&forged_record).unwrap();
    assert!(resigned.verify_signature(&issuer.verifying).is_ok(), "前置:重签件本身验签应通过");
    let r = bundle.verify(&resigned, 20800).unwrap();
    assert_eq!(r.verdict, Verdict::Rejected, "泄露密钥重签的同号伪造必须被清单拦截: {}", r.detail);
}

#[test]
fn qr_survives_mild_and_moderate_degradation() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuingIdentity::generate(1);
    let record = rec("CERT2026000001", 925);
    let env = issuer.sign_record(&record).unwrap();
    let payload = env.to_bytes().unwrap();

    let png = dir.path().join("code.png");
    qr::render_png(&payload, &png, &qr::QrOptions { module_px: 12, ..Default::default() }).unwrap();

    for level in [Degradation::mild(), Degradation::moderate()] {
        let img = image::open(&png).unwrap().to_luma8();
        let degraded = level.apply(&img).unwrap();
        let out = dir.path().join(format!("deg_{}.png", level.seed));
        degraded.save(&out).unwrap();
        let decoded = match qr::decode_image(&out) {
            Ok(bytes) => bytes,
            Err(e) => panic!("退化级别 seed={} 后应仍可解码: {e}", level.seed),
        };
        assert_eq!(decoded, payload);
        let parsed = SignedEnvelope::from_bytes(&decoded).unwrap();
        parsed.verify_signature(&issuer.verifying).unwrap();
    }
}

#[test]
fn payload_size_fits_compact_envelope() {
    let issuer = IssuingIdentity::generate(1);
    // 4 个汉字的姓名(12 字节 UTF-8),贴近常见长度
    let record = CertificateRecord::new("CERT20260001", "欧阳修文远", "WELDER-1G", 955, 20750).unwrap();
    let env = issuer.sign_record(&record).unwrap();
    let payload = env.to_bytes().unwrap();
    // 头部 3 + 记录(36+name_len) + 签名 64
    assert!(payload.len() <= 130, "实际载荷 {} 字节,应控制在 130 内", payload.len());
}

#[test]
fn unknown_key_id_is_rejected() {
    let root = RootIdentity::generate();
    let issuer = IssuingIdentity::generate(1);
    let bundle = build_bundle(&root, &issuer, vec![], KeyStatus::Active);
    let other = IssuingIdentity::generate(9);
    let env = other.sign_record(&rec("CERT2026000001", 900)).unwrap();
    assert_eq!(bundle.verify(&env, 20760).unwrap().verdict, Verdict::Rejected);
}

#[test]
fn trust_bundle_directory_tampering_rejected() {
    let root = RootIdentity::generate();
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("manifests")).unwrap();
    fs::write(dir.path().join("root.json"), serde_json::to_vec_pretty(
        &certcode::crypto::StoredKey::from_root(&RootIdentity::public_only(root.verifying), false)
    ).unwrap()).unwrap();

    let directory = KeyDirectory { schema: 1, generated_on: 1, keys: vec![] };
    let mut wrapper =
        certcode::trust::SignedWrapper::sign(&root, KeyDirectory::DOMAIN, &directory).unwrap();
    // 篡改 payload 但保留旧签名
    let mut raw = B64.decode(&wrapper.payload_base64).unwrap();
    let last = raw.len() - 2;
    raw[last] ^= 0x01;
    wrapper.payload_base64 = B64.encode(raw);
    fs::write(
        dir.path().join("directory.signed.json"),
        serde_json::to_vec_pretty(&wrapper).unwrap(),
    )
    .unwrap();
    assert!(TrustBundle::load(dir.path()).is_err());
}

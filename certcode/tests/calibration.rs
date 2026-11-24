//! 退化信道校准实验(不参与生产):
//! 统计不同 module_px 与退化级别下的解码成功率,辅助确定印刷参数。
//!
//! 运行:cargo test --test calibration -- --nocapture
use certcode::crypto::IssuingIdentity;
use certcode::degrade::Degradation;
use certcode::qr::{self, QrOptions};
use certcode::record::CertificateRecord;

#[test]
fn calibration_matrix() {
    let issuer = IssuingIdentity::generate(1);
    let record = CertificateRecord::new("CERT2026000001", "张三", "WELDER-1G", 955, 20750).unwrap();
    let envelope = issuer.sign_record(&record).unwrap();
    let payload = envelope.to_bytes().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let png = dir.path().join("code.png");
    qr::render_png(&payload, &png, &QrOptions { module_px: 12, ..Default::default() }).unwrap();
    let original = image::open(&png).unwrap().to_luma8();
    println!(
        "原始图 {}x{};载荷 {} 字节",
        original.width(),
        original.height(),
        payload.len()
    );

    let levels = [
        ("干净", Degradation::default()),
        ("轻度(复印一次)", Degradation::mild()),
        ("中度(复印+传真)", Degradation::moderate()),
        ("重度(拍照翻拍)", Degradation::severe()),
    ];

    for (name, level) in levels {
        let degraded = level.apply(&original).unwrap();
        let out = dir.path().join(format!("cal_{}.png", level.seed));
        degraded.save(&out).unwrap();
        match qr::decode_image(&out) {
            Ok(bytes) => {
                let ok = bytes == payload;
                println!("{name:<18} 解码{}", if ok { "成功 ✔" } else { "成功但载荷不一致 �" });
            }
            Err(e) => println!("{name:<18} 解码失败: {e}"),
        }
    }

    // 多种子稳定性:轻度级别跑 5 个种子,确认不是单点幸运
    let mut success = 0;
    for seed in [1u64, 7, 42, 99, 123] {
        let mut lvl = Degradation::mild();
        lvl.seed = seed;
        let degraded = lvl.apply(&original).unwrap();
        if qr::decode_gray(&degraded).map(|b| b == payload).unwrap_or(false) {
            success += 1;
        }
    }
    println!("轻度退化 5 种子成功率: {success}/5");

    // 重度退化 × 模块尺寸扫描:确定印刷参数下限
    println!("--- 重度退化(拍照翻拍)模块尺寸扫描 ---");
    for mpx in [8u32, 12, 16, 20] {
        let png = dir.path().join(format!("s{mpx}.png"));
        qr::render_png(&payload, &png, &QrOptions { module_px: mpx, ..Default::default() }).unwrap();
        let img = image::open(&png).unwrap().to_luma8();
        let degraded = Degradation::severe().apply(&img).unwrap();
        let r = qr::decode_gray(&degraded).map(|b| b == payload).unwrap_or(false);
        println!("module_px={mpx:>2} 图 {:>4}px 重度退化: {}", img.width(), if r { "OK ✔" } else { "FAIL" });
    }
}

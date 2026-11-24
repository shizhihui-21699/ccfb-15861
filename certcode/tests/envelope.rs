//! 退化参数包络扫描:找到解码开始失败的参数边界,给出可操作的印刷工作区间。
use certcode::crypto::IssuingIdentity;
use certcode::degrade::Degradation;
use certcode::qr::{self, QrOptions};
use certcode::record::CertificateRecord;

#[test]
fn failure_envelope_sweep() {
    let issuer = IssuingIdentity::generate(1);
    let record = CertificateRecord::new("CERT2026000001", "张三", "WELDER-1G", 955, 20750).unwrap();
    let payload = issuer.sign_record(&record).unwrap().to_bytes().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let png = dir.path().join("code.png");
    qr::render_png(&payload, &png, &QrOptions { module_px: 10, ..Default::default() }).unwrap();
    let base = image::open(&png).unwrap().to_luma8();

    let ok = |lvl: &Degradation| -> bool {
        lvl.apply(&base)
            .and_then(|d| qr::decode_gray(&d))
            .map(|b| b == payload)
            .unwrap_or(false)
    };

    // 固定其他参数,单独扫描模糊半径(最常见的失焦退化)
    println!("--- 模糊半径扫描(噪声=12,二值化抖动=15) ---");
    for sigma in [0.0f32, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0] {
        let lvl = Degradation { blur_sigma: sigma, noise_sigma: 12.0, threshold_jitter: 15, ..Degradation::mild() };
        println!("blur σ={sigma:<4} {}", if ok(&lvl) { "OK" } else { "FAIL" });
    }

    // 扫描二值化阈值抖动(传真机阈值电路)
    println!("--- 阈值抖动扫描(模糊=1.0,噪声=12) ---");
    for j in [0u8, 10, 20, 30, 40, 50, 60] {
        let lvl = Degradation { threshold_jitter: j, blur_sigma: 1.0, noise_sigma: 12.0, ..Degradation::mild() };
        println!("jitter ±{j:<3} {}", if ok(&lvl) { "OK" } else { "FAIL" });
    }

    // 扫描噪声
    println!("--- 噪声扫描(模糊=1.0,抖动=15) ---");
    for n in [0.0f32, 10.0, 20.0, 30.0, 40.0, 50.0] {
        let lvl = Degradation { noise_sigma: n, blur_sigma: 1.0, threshold_jitter: 15, ..Degradation::mild() };
        println!("noise σ={n:<5} {}", if ok(&lvl) { "OK" } else { "FAIL" });
    }
}

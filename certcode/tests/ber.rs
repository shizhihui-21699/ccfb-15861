//! 模块误码率(BER)测量:把退化图按模块网格中心采样,与原始模块比对,
//! 量化各退化级别相对 QR-H 30% 纠错容量的位置。
use certcode::crypto::IssuingIdentity;
use certcode::degrade::Degradation;
use certcode::qr::{self, QrOptions};
use certcode::record::CertificateRecord;

#[test]
fn measure_bit_error_rate() {
    let issuer = IssuingIdentity::generate(1);
    let record = CertificateRecord::new("CERT2026000001", "张三", "WELDER-1G", 955, 20750).unwrap();
    let payload = issuer.sign_record(&record).unwrap().to_bytes().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let png = dir.path().join("code.png");
    let info = qr::render_png(&payload, &png, &QrOptions { module_px: 10, ..Default::default() }).unwrap();
    let original = image::open(&png).unwrap().to_luma8();
    let mpx = 10u32;
    let modules = info.modules_per_side; // 含静区

    let ber = |img: &image::GrayImage| -> f32 {
        let mut errors = 0u32;
        let mut total = 0u32;
        for my in 0..modules {
            for mx in 0..modules {
                // 模块中心像素
                let cx = mx * mpx + mpx / 2;
                let cy = my * mpx + mpx / 2;
                let orig_dark = original.get_pixel(cx, cy)[0] < 128;
                let deg_dark = img.get_pixel(cx, cy)[0] < 128;
                total += 1;
                if orig_dark != deg_dark { errors += 1; }
            }
        }
        errors as f32 / total as f32
    };

    for (name, level) in [
        ("干净", Degradation::default()),
        ("轻度(复印)", Degradation::mild()),
        ("中度(复印+传真)", Degradation::moderate()),
        ("重度(合成极限)", Degradation::severe()),
    ] {
        let deg = level.apply(&original).unwrap();
        let rate = ber(&deg);
        let decodable = qr::decode_gray(&deg).map(|b| b == payload).unwrap_or(false);
        println!(
            "{name:<16} 模块误码率 {:.1}%  (QR-H 纠错容量≈30%)  解码:{}",
            rate * 100.0,
            if decodable { "OK" } else { "FAIL" }
        );
    }
}

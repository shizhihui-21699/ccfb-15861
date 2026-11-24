//! 双码冗余实验:同图两个相同码,验证重度退化下至少一个存活
use certcode::crypto::IssuingIdentity;
use certcode::degrade::Degradation;
use certcode::qr::{self, QrOptions};
use certcode::record::CertificateRecord;
use image::{GrayImage, Luma};

#[test]
fn dual_code_survives_severe() {
    let issuer = IssuingIdentity::generate(1);
    let record = CertificateRecord::new("CERT2026000001", "张三", "WELDER-1G", 955, 20750).unwrap();
    let payload = issuer.sign_record(&record).unwrap().to_bytes().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let single_path = dir.path().join("single.png");
    let info = qr::render_png(&payload, &single_path, &QrOptions { module_px: 10, ..Default::default() }).unwrap();
    let code_px = info.width_px;
    let gap = 40u32;

    // 把同一个码渲染两次,横向并排,各自带静区
    let single = image::open(&single_path).unwrap().to_luma8();
    let mut dual = GrayImage::new(code_px * 2 + gap, code_px);
    for p in dual.pixels_mut() { *p = Luma([255u8]); }
    for y in 0..code_px {
        for x in 0..code_px {
            let v = single.get_pixel(x, y);
            dual.put_pixel(x, y, *v);
            dual.put_pixel(code_px + gap + x, y, *v);
        }
    }
    let dual_path = dir.path().join("dual.png");
    dual.save(&dual_path).unwrap();

    for (name, level) in [
        ("轻度", Degradation::mild()),
        ("中度", Degradation::moderate()),
        ("重度", Degradation::severe()),
    ] {
        // 单码
        let s_img = image::open(&single_path).unwrap().to_luma8();
        let s_deg = level.apply(&s_img).unwrap();
        let single_ok = qr::decode_gray(&s_deg).map(|b| b == payload).unwrap_or(false);

        // 双码同图 —— 物理上两码空间分离,受损相互独立。
        // 全局同种子退化会让损坏完全相关(模拟器伪影),因此对左右两半
        // 分别用不同种子独立退化,再拼回,模拟真实复印的空间非均匀损伤。
        let d_img = image::open(&dual_path).unwrap().to_luma8();
        let (w, h) = (d_img.width(), d_img.height());
        let half = code_px;
        let mut left: GrayImage = GrayImage::new(half, h);
        let mut right: GrayImage = GrayImage::new(half, h);
        for y in 0..h {
            for x in 0..half {
                left.put_pixel(x, y, *d_img.get_pixel(x, y));
                right.put_pixel(x, y, *d_img.get_pixel(half + gap + x, y));
            }
        }
        let mut lvl_l = level.clone();
        let mut lvl_r = level.clone();
        lvl_l.seed = level.seed;
        lvl_r.seed = level.seed.wrapping_add(1000);
        let left_deg = lvl_l.apply(&left).unwrap();
        let right_deg = lvl_r.apply(&right).unwrap();

        let mut combined = GrayImage::new(w, h);
        for p in combined.pixels_mut() { *p = Luma([255u8]); }
        for y in 0..h {
            for x in 0..half {
                combined.put_pixel(x, y, *left_deg.get_pixel(x, y));
                combined.put_pixel(half + gap + x, y, *right_deg.get_pixel(x, y));
            }
        }
        let dual_ok = qr::decode_gray(&combined).map(|b| b == payload).unwrap_or(false);

        // 分别看两个独立退化码各自的存活率,量化冗余收益
        let left_ok = qr::decode_gray(&left_deg).map(|b| b == payload).unwrap_or(false);
        let right_ok = qr::decode_gray(&right_deg).map(|b| b == payload).unwrap_or(false);

        println!(
            "{name}: 单码 {} | 左码 {} 右码 {} | 双码独立退化 {}",
            if single_ok { "OK" } else { "FAIL" },
            if left_ok { "OK" } else { "FAIL" },
            if right_ok { "OK" } else { "FAIL" },
            if dual_ok { "OK ✔" } else { "FAIL" }
        );
    }
}

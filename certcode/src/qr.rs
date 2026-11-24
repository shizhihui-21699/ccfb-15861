//! QR 码生成与识别。
//!
//! 抗复印/传真/拍照的工程要点:
//! - 强制 EcLevel::H(Reed-Solomon 30% 纠错容量),QR 规范的最高级;
//! - 模块像素(module_px)足够大,印刷后每个模块仍覆盖多个打印机网点;
//! - 保留规范要求的 4 模块静区(quiet zone);
//! - 建议在证书上重复印刷两个相同码,任一存活即可核验。

use std::path::Path;

use image::{GrayImage, Luma};
use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};
use rqrr;

use crate::error::{Error, Result};

/// 生成参数。
#[derive(Debug, Clone)]
pub struct QrOptions {
    /// 每个模块的像素边长;300dpi 印刷建议 ≥ 8
    pub module_px: u32,
    /// 静区模块数,QR 规范要求至少 4
    pub quiet_zone: u32,
    /// 限制最大版本(版本越高模块越密、越怕退化);None 表示自动
    pub max_version: Option<i16>,
}

impl Default for QrOptions {
    fn default() -> Self {
        // 版本越高模块越密、越怕退化,也越接近解码器能力上限
        QrOptions { module_px: 10, quiet_zone: 4, max_version: Some(DECODER_SAFE_MAX_VERSION) }
    }
}

/// 生成结果附带尺寸信息,供印刷排版参考。
#[derive(Debug, Clone)]
pub struct GeneratedQr {
    pub width_px: u32,
    pub height_px: u32,
    /// QR 版本(1..=40),版本号决定模块密度
    pub version: i16,
    /// 每边模块数(含静区)
    pub modules_per_side: u32,
}

/// 本核验器(rqrr)稳定支持的最高 QR 版本。
/// V10-H 字节模式容量 122 字节,足以容纳本系统信封;
/// 更低版本也意味着模块更稀疏、印刷退化存活率更高。
/// 生产手机 App 换用 ZXing/ML Kit/Apple Vision 后可放宽此限制。
pub const DECODER_SAFE_MAX_VERSION: i16 = 10;

/// 把任意字节载荷渲染为灰度 PNG 文件。
pub fn render_png(payload: &[u8], out_path: &Path, opts: &QrOptions) -> Result<GeneratedQr> {
    let (img, info) = build_image(payload, opts)?;
    img.save(out_path)
        .map_err(|e| Error::Image(format!("写 PNG 失败 {}: {e}", out_path.display())))?;
    Ok(info)
}

/// 纯内存构建单码灰度图(供单码落盘与双码合成共用,避免临时文件往返)。
fn build_image(payload: &[u8], opts: &QrOptions) -> Result<(GrayImage, GeneratedQr)> {
    let code = encode_qr(payload, opts.max_version)?;
    let module_count = code.width() as u32; // 不含静区的模块数
    let version = ((code.width() as i16) - 17) / 4; // V1=21 模块,每升一版 +4
    let total_modules = module_count + opts.quiet_zone * 2;
    let px = total_modules * opts.module_px;

    let mut img = GrayImage::new(px, px);
    let dark = Luma([0u8]);
    let light = Luma([255u8]);

    // 先填白(静区)
    for p in img.pixels_mut() {
        *p = light;
    }
    // 再画深色模块
    for y in 0..module_count {
        for x in 0..module_count {
            if code[(x as usize, y as usize)] == qrcode::Color::Dark {
                let x0 = (x + opts.quiet_zone) * opts.module_px;
                let y0 = (y + opts.quiet_zone) * opts.module_px;
                for dy in 0..opts.module_px {
                    for dx in 0..opts.module_px {
                        img.put_pixel(x0 + dx, y0 + dy, dark);
                    }
                }
            }
        }
    }
    let info = GeneratedQr { width_px: px, height_px: px, version, modules_per_side: total_modules };
    Ok((img, info))
}

/// 渲染两个相同的防伪码横向并排(各自带完整静区),用于证书冗余印刷。
///
/// 两个码空间分离,复印/拍照时损伤相互独立:单码存活概率为 p 时,
/// 整图至少一个可核验的概率为 1-(1-p)²。解码端 `decode_gray` 会返回
/// 检测到的多个码中第一个成功解码者,无需上层感知冗余。
/// 两码间距取单码宽的 8%,且不小于 40px。
pub fn render_dual_png(payload: &[u8], out_path: &Path, opts: &QrOptions) -> Result<GeneratedQr> {
    let (single_img, single) = build_image(payload, opts)?;
    let code_px = single.width_px;
    let gap_px = (code_px * 8 / 100).max(40);

    let w = code_px * 2 + gap_px;
    let h = single.height_px;
    let mut canvas = GrayImage::new(w, h);
    for p in canvas.pixels_mut() {
        *p = Luma([255u8]);
    }
    for y in 0..h {
        for x in 0..code_px {
            let v = single_img.get_pixel(x, y);
            canvas.put_pixel(x, y, *v);
            canvas.put_pixel(code_px + gap_px + x, y, *v);
        }
    }
    canvas
        .save(out_path)
        .map_err(|e| Error::Image(format!("写双码 PNG 失败 {}: {e}", out_path.display())))?;
    Ok(GeneratedQr { width_px: w, height_px: h, version: single.version, modules_per_side: single.modules_per_side })
}

/// 终端预览(ASCII/Unicode),不依赖图像库输出。
pub fn render_unicode(payload: &[u8]) -> Result<String> {
    let code = encode_qr(payload, Some(DECODER_SAFE_MAX_VERSION))?;
    let s = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    Ok(s)
}

fn encode_qr(payload: &[u8], max_version: Option<i16>) -> Result<QrCode> {
    // 让库自动选能容纳载荷的"最小版本"(with_version 是精确版本而非上限,
    // 直接传 V20 会把所有码强制渲染成高密度 V20,既浪费面积又增加解码失败率)。
    let code = QrCode::with_error_correction_level(payload, EcLevel::H)
        .map_err(|e| Error::Qr(format!("QR 编码失败(载荷可能过大): {e}")))?;
    let version = ((code.width() as i16) - 17) / 4;
    if let Some(cap) = max_version {
        if version > cap {
            return Err(Error::Qr(format!(
                "载荷需要 QR V{version},超过解码器安全上限 V{cap}(H 级);\
                 请缩短姓名或减少载荷,或升级支持高版本的解码后端"
            )));
        }
    }
    Ok(code)
}

/// 从图像文件识别 QR 并还原字节。
/// 支持一张图里多个码,返回第一个成功解码的载荷。
pub fn decode_image(path: &Path) -> Result<Vec<u8>> {
    let img = image::open(path)
        .map_err(|e| Error::Image(format!("读图失败 {}: {e}", path.display())))?
        .to_luma8();
    decode_gray(&img)
}

/// 从灰度内存图像解码。
pub fn decode_gray(img: &GrayImage) -> Result<Vec<u8>> {
    // rqrr 的 detect_grids 返回的网格借用 PreparedImage,
    // 因此检测与解码必须在同一次调用内完成(检测失败再放大重试)。
    match try_decode(img) {
        Ok(Some(payload)) => Ok(payload),
        Ok(None) => {
            let scaled = scale_2x(img);
            try_decode(&scaled)?.ok_or_else(|| Error::Qr("图像中未检测到 QR 码".into()))
        }
        Err(first_err) => {
            // 检测到码但本尺寸解码失败,放大后再尝试一次
            let scaled = scale_2x(img);
            match try_decode(&scaled) {
                Ok(Some(payload)) => Ok(payload),
                Ok(None) => Err(first_err),
                Err(_) => Err(first_err),
            }
        }
    }
}

/// 返回:Ok(None)=未检测到码;Err=检测到但全部解码失败。
///
/// 关键:必须用 rqrr 的 `decode_to` 写原始字节,不能用 `decode`。
/// 后者内部 `String::from_utf8`,而本系统载荷含 Ed25519 签名(随机字节,
/// 非合法 UTF-8),会被误报为 EncodingError——这是 rqrr 对二进制载荷的已知坑。
fn try_decode(img: &GrayImage) -> Result<Option<Vec<u8>>> {
    let mut decoder = rqrr::PreparedImage::prepare(img.clone());
    let grids = decoder.detect_grids();
    if grids.is_empty() {
        return Ok(None);
    }
    let mut last_err = None;
    for grid in grids {
        let mut raw = Vec::new();
        match grid.decode_to(&mut raw) {
            Ok(_meta) => return Ok(Some(raw)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(Error::Qr(format!("QR 解码失败: {:?}", last_err)))
}

fn scale_2x(img: &GrayImage) -> GrayImage {
    let (w, h) = img.dimensions();
    let mut out = GrayImage::new(w * 2, h * 2);
    for y in 0..h {
        for x in 0..w {
            let p = img.get_pixel(x, y);
            for dy in 0..2 {
                for dx in 0..2 {
                    out.put_pixel(x * 2 + dx, y * 2 + dy, *p);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello certcode anti-counterfeit payload 0123456789";
        let code = encode_qr(payload, Some(DECODER_SAFE_MAX_VERSION)).unwrap();
        // 渲染成图再解码
        let w = code.width() as u32 + 8;
        let mut img = GrayImage::new(w * 4, w * 4);
        for p in img.pixels_mut() {
            *p = Luma([255]);
        }
        for y in 0..code.width() {
            for x in 0..code.width() {
                if code[(x, y)] == qrcode::Color::Dark {
                    for dy in 0..4 {
                        for dx in 0..4 {
                            img.put_pixel((x as u32 + 4) * 4 + dx, (y as u32 + 4) * 4 + dy, Luma([0]));
                        }
                    }
                }
            }
        }
        let decoded = decode_gray(&img).unwrap();
        assert_eq!(decoded, payload);
    }
}

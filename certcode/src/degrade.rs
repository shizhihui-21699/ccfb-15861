//! 打印-复印-传真-拍照信道的退化模拟器。
//!
//! 全部为确定性操作(可指定种子),用于在测试中量化防伪码的鲁棒性,
//! 不参与生产发证/核验流程。

use image::{GrayImage, Luma};

use crate::error::Result;

/// 退化参数集合,按真实复印/拍照链路的典型量级标定。
#[derive(Debug, Clone)]
pub struct Degradation {
    /// 高斯模糊半径(像素),模拟失焦/印刷网点扩散
    pub blur_sigma: f32,
    /// 加性高斯噪声标准差(0..=255)
    pub noise_sigma: f32,
    /// 随机数种子(保证测试可复现)
    pub seed: u64,
    /// JPEG 风格块效应/量化强度 1..=30(数字越大退化越重);0 表示不做
    pub blocky: u8,
    /// 二值化阈值抖动幅度(0..=128),模拟传真机阈值抖动
    pub threshold_jitter: u8,
    /// 整体亮度偏移(-128..=128),模拟曝光偏差
    pub brightness: i16,
    /// 对比度系数(1.0 为不变)
    pub contrast: f32,
}

impl Default for Degradation {
    fn default() -> Self {
        Degradation {
            blur_sigma: 0.0,
            noise_sigma: 0.0,
            seed: 1,
            blocky: 0,
            threshold_jitter: 0,
            brightness: 0,
            contrast: 1.0,
        }
    }
}

impl Degradation {
    /// 轻度:办公复印一次
    pub fn mild() -> Self {
        Degradation {
            blur_sigma: 1.0,
            noise_sigma: 8.0,
            seed: 11,
            blocky: 4,
            threshold_jitter: 10,
            brightness: 6,
            contrast: 1.05,
        }
    }

    /// 中度:复印后传真再扫描
    pub fn moderate() -> Self {
        Degradation {
            blur_sigma: 1.8,
            noise_sigma: 16.0,
            seed: 22,
            blocky: 8,
            threshold_jitter: 22,
            brightness: -8,
            contrast: 1.12,
        }
    }

    /// 重度:拍照后屏幕翻拍再打印,角度/光照不佳
    pub fn severe() -> Self {
        Degradation {
            blur_sigma: 3.0,
            noise_sigma: 28.0,
            seed: 33,
            blocky: 14,
            threshold_jitter: 40,
            brightness: -16,
            contrast: 1.25,
        }
    }

    pub fn apply(&self, img: &GrayImage) -> Result<GrayImage> {
        let mut out = img.clone();
        // 顺序模拟真实扫描链路:光学失焦 → 传感器噪声 → 曝光/对比度
        // → 量化位数下降 → 传真式阈值二值化
        if self.blur_sigma > 0.0 {
            out = gaussian_blur(&out, self.blur_sigma);
        }
        if self.noise_sigma > 0.0 {
            add_gaussian_noise(&mut out, self.noise_sigma, self.seed);
        }
        if self.brightness != 0 || (self.contrast - 1.0).abs() > f32::EPSILON {
            adjust(&mut out, self.brightness, self.contrast);
        }
        if self.blocky > 0 {
            posterize(&mut out, self.blocky);
        }
        if self.threshold_jitter > 0 {
            jittered_binarize(&mut out, self.threshold_jitter, self.seed);
        }
        Ok(out)
    }
}

/// 可分离高斯模糊。
pub fn gaussian_blur(img: &GrayImage, sigma: f32) -> GrayImage {
    let radius = (sigma * 3.0).ceil() as i32;
    let kernel: Vec<f32> = (-radius..=radius)
        .map(|i| {
            let x = i as f32 / sigma;
            (-0.5 * x * x).exp()
        })
        .collect();
    let sum: f32 = kernel.iter().sum();
    let kernel: Vec<f32> = kernel.iter().map(|v| v / sum).collect();

    let (w, h) = img.dimensions();
    let mut tmp = GrayImage::new(w, h);
    let mut out = GrayImage::new(w, h);

    for y in 0..h {
        for x in 0..w {
            let mut acc = 0f32;
            for (i, k) in kernel.iter().enumerate() {
                let sx = (x as i32 + i as i32 - radius).clamp(0, w as i32 - 1) as u32;
                acc += img.get_pixel(sx, y)[0] as f32 * k;
            }
            tmp.put_pixel(x, y, Luma([acc.round().clamp(0.0, 255.0) as u8]));
        }
    }
    for y in 0..h {
        for x in 0..w {
            let mut acc = 0f32;
            for (i, k) in kernel.iter().enumerate() {
                let sy = (y as i32 + i as i32 - radius).clamp(0, h as i32 - 1) as u32;
                acc += tmp.get_pixel(x, sy)[0] as f32 * k;
            }
            out.put_pixel(x, y, Luma([acc.round().clamp(0.0, 255.0) as u8]));
        }
    }
    out
}

/// 确定性 LCG 高斯噪声(Box-Muller)。
pub fn add_gaussian_noise(img: &mut GrayImage, sigma: f32, seed: u64) {
    let mut state = seed.max(1);
    let next_u = |state: &mut u64| -> f32 {
        // LCG 常数
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((*state >> 33) as f32) / (1u64 << 31) as f32
    };
    for p in img.pixels_mut() {
        let u1 = next_u(&mut state).max(1e-6);
        let u2 = next_u(&mut state);
        let g = (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos();
        let v = p[0] as f32 + g * sigma;
        p[0] = v.round().clamp(0.0, 255.0) as u8;
    }
}

pub fn adjust(img: &mut GrayImage, brightness: i16, contrast: f32) {
    for p in img.pixels_mut() {
        let v = (p[0] as f32 - 128.0) * contrast + 128.0 + brightness as f32;
        p[0] = v.round().clamp(0.0, 255.0) as u8;
    }
}

/// 色调分离(位深下降):逐像素把灰度量化到较粗的阶梯,
/// 近似 JPEG/扫描仪的量化,但不做跨模块空间平均,避免人为抹掉 QR 模块边界。
pub fn posterize(img: &mut GrayImage, strength: u8) {
    // strength 1..=30 → 量化步长 8..=62
    let step = (strength as u16 * 2 + 6).max(8);
    for p in img.pixels_mut() {
        let v = p[0] as u16;
        let q = (v / step) * step + step / 2;
        p[0] = q.min(255) as u8;
    }
}

/// 带空间抖动的二值化,模拟传真/复印阈值电路。
/// 阈值在 128 两侧对称抖动,不引入系统性偏黑/偏白。
pub fn jittered_binarize(img: &mut GrayImage, jitter: u8, seed: u64) {
    let mut state = seed.max(1);
    let (w, h) = img.dimensions();
    for y in 0..h {
        for x in 0..w {
            state = state.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
            let r = (state >> 33) as i32 % (jitter as i32 * 2 + 1);
            let threshold = 128 - jitter as i32 + r; // 区间 [128-jitter, 128+jitter]
            let v = if img.get_pixel(x, y)[0] as i32 > threshold { 255 } else { 0 };
            img.put_pixel(x, y, Luma([v]));
        }
    }
}

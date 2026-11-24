# certcode — 印刷证书离线密码防伪码

职业资格认证机构用于纸质证书/成绩单防伪的 Rust 工具:在证书上印一个 QR 防伪码,
手机拍照即可**离线**确认姓名、编号、成绩未被篡改;即使签发私钥泄露,
已发出的旧证书依然可信,而伪造的新证书会被拒绝。

## 它解决什么问题

| 威胁 | 对策 |
|---|---|
| 改名字/改分数后重新打印 | Ed25519 数字签名,改一个比特即验签失败 |
| 复印、传真、拍照翻拍后码面退化 | QR 最高级 H 纠错(30%)+ 大模块 + 双码冗余印刷 |
| 码面积有限 | 定长二进制紧凑载荷(典型 113 字节,落在 V10-H 容量 122 内) |
| 签发私钥泄露 | 根签名密钥目录(可废止)+ 根签名签发清单(每证摘要),旧证继续可信、伪造件被拒 |
| 核验端不能联网 | 信任包(根公钥+目录+清单)随 App 分发,全流程本地完成 |

## 快速开始

```bash
cargo build --release
BIN=target/release/certcode

# 发证侧(离线机器)
$BIN root-init --dir ./ca
$BIN issuer-init --root-secret ./ca/root.secret.json --id 1 \
     --dir ./ca --valid-from 2026-01-01 --today 2026-11-24
$BIN issue --issuer-secret ./ca/issuers/key1.secret.json \
     --serial CERT2026000001 --name 张三 --subject WELDER-1G \
     --score 955 --date 2026-11-24 --out code.png
$BIN stage  --root-secret ./ca/root.secret.json --dir ./ca --envelope code.envelope.b64
$BIN publish-manifest --root-secret ./ca/root.secret.json --dir ./ca --id 1 --today 2026-11-24
$BIN export-bundle --dir ./ca --out ./bundle

# 核验侧(任意离线设备)
$BIN verify --bundle ./bundle --image code.png --today 2026-11-24
# ✅ VERIFIED 可信 / ⚠️ UNTRUSTED / ❌ REJECTED(退出码 0/2/1)
```

完整泄露处置流程与设计依据见 [`docs/design.md`](docs/design.md),
一键演示见 `scripts/demo.sh`。

## 库 API

```rust
use certcode::crypto::IssuingIdentity;
use certcode::record::CertificateRecord;
use certcode::trust::TrustBundle;
use certcode::qr::QrOptions;

let issuer = IssuingIdentity::generate(1);
let record = CertificateRecord::new("CERT2026000001", "张三", "WELDER-1G", 955, 20750)?;

// 发证:签名 + 渲染 PNG
let (envelope, info) = certcode::issue_code(&issuer, &record, Path::new("code.png"), &QrOptions::default())?;

// 核验:扫码图片 → 验签 → 清单比对
let bundle = TrustBundle::load(Path::new("./bundle"))?;
let (report, record) = certcode::verify_image(&bundle, Path::new("photo.jpg"), 20783)?;
assert_eq!(report.verdict, certcode::trust::Verdict::Verified);
```

## 模块结构

```
src/
  record.rs   证书记录 + 定长规范二进制编码(签名稳定性的基础)
  crypto.rs   Ed25519 签名信封、密钥管理(基于 ed25519-dalek,不自研密码学)
  trust.rs    根签名目录/签发清单、泄露废止、核验策略
  qr.rs       H 级纠错 QR 渲染/识别,含单码与双码冗余渲染
  degrade.rs  复印/传真/拍照退化模拟器(测试夹具)
  main.rs     发证/核验全流程 CLI
tests/
  e2e.rs        端到端:全生命周期、泄露场景、退化鲁棒性、防篡改
  calibration.rs 各级退化的解码成功率与模块尺寸扫描
  envelope.rs   退化参数包络(模糊/噪声/阈值抖动的失败边界)
  dualcode.rs   双码冗余的独立失效验证
  ber.rs        模块误码率测量
```

## 抗退化实测结论(V10-H,module_px=10)

- 干净图、办公复印(轻)、复印+传真(中):稳定解码并验签;轻度退化 5 个随机种子全部通过。
- 工作包络:高斯模糊 σ≤3px、加性噪声 σ≤50、二值化抖动 ±60 均可恢复。
- 唯一悬崖是严重失焦(模糊 σ≈4,约模块宽 40%),靠加大模块或重新对焦解决。
- 建议 `--dual` 并排印两个相同码:两码空间分离、损伤独立,存活率从 p 提升到 1−(1−p)²。
- 解码端用 rqrr 的 `decode_to` 取原始字节——其 `decode` 强制 UTF-8,会拒绝签名这类二进制载荷。

## 安全注意

- 根私钥(`root.secret.json`,权限 0600)只能存在于离线仪式机,建议迁入 HSM。
- `export-bundle` 导出的信任包不含任何私钥,加载时也会拒绝带私钥的 root.json。
- 证书编号须同宽度、连续、字典序即签发序(清单按区间偏移定位摘要)。
- 本 crate 不实现任何密码学原语,签名/哈希全部来自 `ed25519-dalek` 与 `sha2`。

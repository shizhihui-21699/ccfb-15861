//! certcode 命令行:发证端(离线机器)与核验端(手机/办公机)工作流。

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};

use certcode::crypto::{IssuingIdentity, RootIdentity, StoredKey};
use certcode::error::Error;
use certcode::qr::QrOptions;
use certcode::record::CertificateRecord;
use certcode::trust::{
    Authority, KeyDirectory, KeyStatus, SignedWrapper, TrustBundle, Verdict,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(name = "certcode", version, about = "印刷证书离线密码防伪码工具")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 生成根密钥(离线仪式机);同时写出私钥文件与对外公钥文件
    RootInit {
        #[arg(long)]
        dir: PathBuf,
    },
    /// 生成一把签发密钥并登记到根签名目录
    IssuerInit {
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        id: u8,
        #[arg(long)]
        dir: PathBuf,
        /// 生效日,YYYY-MM-DD
        #[arg(long)]
        valid_from: String,
        /// 失效日,YYYY-MM-DD(可选)
        #[arg(long)]
        valid_to: Option<String>,
        /// 登记日期,YYYY-MM-DD
        #[arg(long)]
        today: String,
    },
    /// 给一张证书生成防伪码 PNG
    Issue {
        #[arg(long)]
        issuer_secret: PathBuf,
        /// 证书编号
        #[arg(long)]
        serial: String,
        /// 持证人姓名
        #[arg(long)]
        name: String,
        /// 科目
        #[arg(long)]
        subject: String,
        /// 成绩 0..=1000(如 95.5 分填 955)
        #[arg(long)]
        score: u16,
        /// 签发日 YYYY-MM-DD
        #[arg(long)]
        date: String,
        #[arg(long)]
        out: PathBuf,
        /// 模块像素边长
        #[arg(long, default_value_t = 10)]
        module_px: u32,
        /// 并排印刷两个相同码(冗余抗复印/拍照损伤)
        #[arg(long, default_value_t = false)]
        dual: bool,
    },
    /// 把已签发信封登记进待发布清单(信封由 issue --envelope 产出)
    Stage {
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        envelope: PathBuf,
    },
    /// 发布某把签发密钥的签发清单(根签名)
    PublishManifest {
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        id: u8,
        #[arg(long)]
        today: String,
    },
    /// 重新发布根签名目录(登记新密钥或废止后必须执行)
    PublishDirectory {
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        today: String,
    },
    /// 密钥泄露处置:废止签发密钥(单向),随后须 publish-directory
    Revoke {
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        id: u8,
    },
    /// 导出核验端信任包(只含根公钥 + 签名文件,绝不包含私钥)
    ExportBundle {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// 核验一张防伪码图片(离线)
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        today: String,
    },
    /// 查看信封明文内容(用于人工比对姓名/编号/成绩)
    Inspect {
        #[arg(long)]
        envelope: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::RootInit { dir } => root_init(&dir),
        Cmd::IssuerInit { root_secret, id, dir, valid_from, valid_to, today } => {
            issuer_init(&root_secret, id, &dir, &valid_from, valid_to.as_deref(), &today)
        }
        Cmd::Issue { issuer_secret, serial, name, subject, score, date, out, module_px, dual } => {
            issue(&IssueArgs {
                issuer_secret: &issuer_secret,
                serial: &serial,
                name: &name,
                subject: &subject,
                score,
                date: &date,
                out: &out,
                module_px,
                dual,
            })
        }
        Cmd::Stage { root_secret, dir, envelope } => stage(&root_secret, &dir, &envelope),
        Cmd::PublishManifest { root_secret, dir, id, today } => {
            publish_manifest(&root_secret, &dir, id, &today)
        }
        Cmd::PublishDirectory { root_secret, dir, today } => {
            publish_directory(&root_secret, &dir, &today)
        }
        Cmd::Revoke { root_secret, dir, id } => revoke(&root_secret, &dir, id),
        Cmd::ExportBundle { dir, out } => export_bundle(&dir, &out),
        Cmd::Verify { bundle, image, today } => verify(&bundle, &image, &today),
        Cmd::Inspect { envelope } => inspect(&envelope),
    }
}

// ---------- 日期工具:公历 YYYY-MM-DD → 纪元天数(Howard Hinnant 算法) ----------

fn days_from_ymd(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe - 719468
}

fn parse_date(s: &str) -> Result<u32> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(Box::new(Error::Encode("日期格式应为 YYYY-MM-DD".into())));
    }
    let y: i32 = parts[0].parse()?;
    let m: u32 = parts[1].parse()?;
    let d: u32 = parts[2].parse()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(Box::new(Error::Encode("非法日期".into())));
    }
    let days = days_from_ymd(y, m, d);
    if days < 0 {
        return Err(Box::new(Error::Encode("日期早于 1970-01-01".into())));
    }
    Ok(days as u32)
}

// ---------- 密钥与目录的磁盘布局 ----------
//
// <dir>/
//   root.secret.json            根私钥(0600,永不离开离线机)
//   root.json                   根公钥
//   directory.json              目录明文(权威工作副本)
//   directory.signed.json       根签名目录
//   issuers/key<id>.secret.json 签发私钥
//   issuers/key<id>.json        签发公钥
//   manifests/key<id>-<n>.signed.json
//   pending/key<id>.json        待发布信封记录

fn ensure_dirs(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir.join("issuers"))?;
    fs::create_dir_all(dir.join("manifests"))?;
    fs::create_dir_all(dir.join("pending"))?;
    Ok(())
}

fn write_secret_file(path: &Path, json: &str) -> Result<()> {
    fs::write(path, json)?;
    set_user_only_perms(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_user_only_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_perms(_path: &Path) -> Result<()> {
    Ok(())
}

fn load_root_secret(path: &Path) -> Result<RootIdentity> {
    let stored: StoredKey = serde_json::from_slice(&fs::read(path)?)?;
    Ok(stored.to_root_identity()?)
}

fn load_directory(dir: &Path) -> Result<KeyDirectory> {
    let p = dir.join("directory.json");
    let d: KeyDirectory = serde_json::from_slice(&fs::read(&p)?)
        .map_err(|e| Error::Bundle(format!("directory.json 读取失败({e});请先执行 issuer-init")))?;
    Ok(d)
}

fn save_directory(dir: &Path, directory: &KeyDirectory) -> Result<()> {
    fs::write(dir.join("directory.json"), serde_json::to_vec_pretty(directory)?)?;
    Ok(())
}

fn root_init(dir: &Path) -> Result<()> {
    ensure_dirs(dir)?;
    let secret_path = dir.join("root.secret.json");
    if secret_path.exists() {
        return Err(Box::new(Error::Bundle("root.secret.json 已存在,拒绝覆盖".into())));
    }
    let root = RootIdentity::generate();
    write_secret_file(&secret_path, &serde_json::to_string_pretty(&StoredKey::from_root(&root, true))?)?;
    fs::write(dir.join("root.json"), serde_json::to_string_pretty(&StoredKey::from_root(&root, false))?)?;
    println!("✔ 根密钥已生成: {}", secret_path.display());
    println!("  公钥文件:       {}", dir.join("root.json").display());
    println!("⚠ root.secret.json 必须留在离线机器,权限已设为 0600,切勿分发或联网");
    Ok(())
}

fn issuer_init(
    root_secret: &Path,
    id: u8,
    dir: &Path,
    valid_from: &str,
    valid_to: Option<&str>,
    today: &str,
) -> Result<()> {
    ensure_dirs(dir)?;
    let root = load_root_secret(root_secret)?;
    let directory = if dir.join("directory.json").exists() {
        load_directory(dir)?
    } else {
        KeyDirectory { schema: 1, generated_on: parse_date(today)?, keys: vec![] }
    };
    let mut authority = Authority::open(root, directory);

    let issuer = IssuingIdentity::generate(id);
    authority.register_issuing_key(
        &issuer,
        parse_date(valid_from)?,
        valid_to.map(parse_date).transpose()?,
        parse_date(today)?,
    )?;

    let sk_path = dir.join("issuers").join(format!("key{id}.secret.json"));
    let pk_path = dir.join("issuers").join(format!("key{id}.json"));
    write_secret_file(&sk_path, &serde_json::to_string_pretty(&StoredKey::from_issuing(&issuer, true))?)?;
    fs::write(&pk_path, serde_json::to_string_pretty(&StoredKey::from_issuing(&issuer, false))?)?;
    save_directory(dir, &authority.directory)?;

    let wrapper = authority.signed_directory()?;
    fs::write(dir.join("directory.signed.json"), serde_json::to_vec_pretty(&wrapper)?)?;

    println!("✔ 签发密钥 id={id} 已登记并写入根签名目录");
    println!("  私钥: {}", sk_path.display());
    println!("  公钥: {}", pk_path.display());
    Ok(())
}

/// issue 命令的全部输入参数(收拢成结构体,避免长参数列表)。
struct IssueArgs<'a> {
    issuer_secret: &'a Path,
    serial: &'a str,
    name: &'a str,
    subject: &'a str,
    score: u16,
    date: &'a str,
    out: &'a Path,
    module_px: u32,
    dual: bool,
}

fn issue(args: &IssueArgs) -> Result<()> {
    let IssueArgs { issuer_secret, serial, name, subject, score, date, out, module_px, dual } = args;
    let stored: StoredKey = serde_json::from_slice(&fs::read(issuer_secret)?)?;
    let identity = stored.to_issuing_identity()?;
    let record = CertificateRecord::new(serial, name, subject, *score, parse_date(date)?)?;
    let envelope = identity.sign_record(&record)?;
    let payload = envelope.to_bytes()?;
    let opts = QrOptions { module_px: *module_px, ..Default::default() };

    let info = if *dual {
        certcode::qr::render_dual_png(&payload, out, &opts)?
    } else {
        certcode::qr::render_png(&payload, out, &opts)?
    };

    // 同时落一个信封文件,供 stage 登记清单
    let env_path = out.with_extension("envelope.b64");
    fs::write(&env_path, B64.encode(&payload))?;

    println!("✔ 防伪码已生成: {}", out.display());
    println!("  信封副本:       {}", env_path.display());
    println!("  印刷模式:       {}", if *dual { "双码冗余(并排)" } else { "单码" });
    println!("  QR 版本:        V{} (每边 {} 模块, {}×{} px)", info.version, info.modules_per_side, info.width_px, info.height_px);
    println!("  载荷:           {} 字节", payload.len());
    Ok(())
}

fn stage(root_secret: &Path, dir: &Path, envelope: &Path) -> Result<()> {
    let _root = load_root_secret(root_secret)?; // 确认持有根私钥才允许操作发证目录
    let raw = B64.decode(fs::read_to_string(envelope)?.trim())?;
    let env = certcode::crypto::SignedEnvelope::from_bytes(&raw)?;
    let key_id = env.key_id;
    let pending_path = dir.join("pending").join(format!("key{key_id}.jsonl"));
    if pending_path.exists() {
        let existing = fs::read_to_string(&pending_path)?;
        for line in existing.lines() {
            if line.is_empty() {
                continue;
            }
            let old = certcode::crypto::SignedEnvelope::from_bytes(&B64.decode(line)?)?;
            if old.record.serial == env.record.serial {
                return Err(Box::new(Error::Trust(format!("编号 {} 已登记", env.record.serial))));
            }
        }
    }
    let mut file = fs::OpenOptions::new().create(true).append(true).open(&pending_path)?;
    use std::io::Write;
    writeln!(file, "{}", B64.encode(env.to_bytes()?))?;
    println!("✔ 编号 {} 已加入 key{key_id} 待发布清单", env.record.serial);
    Ok(())
}

fn publish_manifest(root_secret: &Path, dir: &Path, id: u8, today: &str) -> Result<()> {
    let root = load_root_secret(root_secret)?;
    let directory = load_directory(dir)?;
    let mut authority = Authority::open(root, directory);

    let pending_path = dir.join("pending").join(format!("key{id}.jsonl"));
    if !pending_path.exists() {
        return Err(Box::new(Error::Trust(format!("key{id} 没有待发布记录"))));
    }
    let lines = fs::read_to_string(&pending_path)?;
    for line in lines.lines() {
        if line.is_empty() {
            continue;
        }
        let env = certcode::crypto::SignedEnvelope::from_bytes(&B64.decode(line)?)?;
        authority.record_issuance(&env)?;
    }

    let (manifest, wrapper) = authority.publish_manifest(id, parse_date(today)?)?;
    let count = manifest.digests_base64.len();
    let fname = dir.join("manifests").join(format!("key{id}-{}.signed.json", manifest.serial_first));
    fs::write(&fname, serde_json::to_vec_pretty(&wrapper)?)?;
    fs::remove_file(&pending_path)?;

    println!("✔ 已发布 key{id} 签发清单: {}", fname.display());
    println!("  区间: {} .. {},共 {count} 条记录", manifest.serial_first, manifest.serial_last);
    Ok(())
}

fn publish_directory(root_secret: &Path, dir: &Path, today: &str) -> Result<()> {
    let root = load_root_secret(root_secret)?;
    let mut directory = load_directory(dir)?;
    directory.generated_on = parse_date(today)?;
    let wrapper = SignedWrapper::sign(&root, KeyDirectory::DOMAIN, &directory)?;
    fs::write(dir.join("directory.signed.json"), serde_json::to_vec_pretty(&wrapper)?)?;
    let active = directory.keys.iter().filter(|k| k.status == KeyStatus::Active).count();
    let compromised = directory.keys.len() - active;
    println!("✔ 根签名目录已发布: {}", dir.join("directory.signed.json").display());
    println!("  密钥条目: {} 把(active={active}, compromised={compromised})", directory.keys.len());
    Ok(())
}

fn revoke(root_secret: &Path, dir: &Path, id: u8) -> Result<()> {
    let root = load_root_secret(root_secret)?;
    let directory = load_directory(dir)?;
    let mut authority = Authority::open(root, directory);
    let entry = authority.mark_compromised(id)?;
    save_directory(dir, &authority.directory)?;
    println!("✔ key{id} 已标记为 {:?}(单向不可逆)", entry.status);
    println!("  接下来请: 1) publish-manifest 发布该密钥全部旧证清单  2) publish-directory 重新发布目录");
    Ok(())
}

fn export_bundle(dir: &Path, out: &Path) -> Result<()> {
    // 安全检查:导出路径不得包含任何 secret 文件
    fs::create_dir_all(out.join("manifests"))?;
    fs::copy(dir.join("root.json"), out.join("root.json"))?;
    fs::copy(dir.join("directory.signed.json"), out.join("directory.signed.json"))?;
    let msrc = dir.join("manifests");
    let mut n = 0;
    for entry in fs::read_dir(&msrc)? {
        let p = entry?.path();
        if p.extension().and_then(|s| s.to_str()) == Some("json") {
            fs::copy(&p, out.join("manifests").join(p.file_name().unwrap()))?;
            n += 1;
        }
    }
    // 校验导出包自身可用,且不含私钥
    let bundle = TrustBundle::load(out)?;
    println!("✔ 核验信任包已导出: {}", out.display());
    println!("  根公钥指纹: {}", &hex::encode(bundle.root_public_bytes())[..16]);
    println!("  签发清单:   {n} 份");
    println!("⚠ 已确认包内无任何私钥;可随核验 App 分发或定期推送更新");
    Ok(())
}

fn verify(bundle_dir: &Path, image: &Path, today: &str) -> Result<()> {
    let bundle = TrustBundle::load(bundle_dir)?;
    let (report, record) = certcode::verify_image(&bundle, image, parse_date(today)?)?;

    let (tag, code) = match report.verdict {
        Verdict::Verified => ("✅ VERIFIED 可信", 0),
        Verdict::Untrusted => ("⚠️  UNTRUSTED 无法确认", 2),
        Verdict::Rejected => ("❌ REJECTED 拒绝", 1),
    };
    println!("{tag}");
    println!("  编号: {}", record.serial);
    println!("  姓名: {}", record.name);
    println!("  科目: {}", record.subject);
    println!("  成绩: {:.1}", record.score as f64 / 10.0);
    println!("  密钥: key{}", report.key_id);
    println!("  依据: {}", report.detail);
    println!("  请人工核对证书纸质内容与以上姓名/编号/成绩是否完全一致");
    std::process::exit(code);
}

fn inspect(envelope: &Path) -> Result<()> {
    let raw = B64.decode(fs::read_to_string(envelope)?.trim())?;
    let env = certcode::crypto::SignedEnvelope::from_bytes(&raw)?;
    println!("key_id:    {}", env.key_id);
    println!("serial:    {}", env.record.serial);
    println!("name:      {}", env.record.name);
    println!("subject:   {}", env.record.subject);
    println!("score:     {:.1}", env.record.score as f64 / 10.0);
    println!("issued_on: {} (纪元天数)", env.record.issued_on);
    println!("signature: {}", hex::encode(env.signature));
    Ok(())
}

use std::fmt;

/// 统一错误类型
#[derive(Debug)]
pub enum Error {
    /// 编码阶段:字段超长、非法字符等
    Encode(String),
    /// 解码阶段:字节流损坏或长度不对
    Decode(String),
    /// 签名/验签失败
    Signature(String),
    /// 信任策略拒绝:密钥已废止、编号不在签发清单、摘要不匹配等
    Trust(String),
    /// QR 码生成或识别
    Qr(String),
    /// 图像处理
    Image(String),
    /// IO
    Io(String),
    /// 信任包/清单文件格式
    Bundle(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encode(m) => write!(f, "编码错误: {m}"),
            Error::Decode(m) => write!(f, "解码错误: {m}"),
            Error::Signature(m) => write!(f, "签名错误: {m}"),
            Error::Trust(m) => write!(f, "信任校验失败: {m}"),
            Error::Qr(m) => write!(f, "二维码错误: {m}"),
            Error::Image(m) => write!(f, "图像处理错误: {m}"),
            Error::Io(m) => write!(f, "IO 错误: {m}"),
            Error::Bundle(m) => write!(f, "信任包错误: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

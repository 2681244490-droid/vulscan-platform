use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Connection timeout: {0}")]
    ConnectionTimeout(String),

    #[error("Response timeout: {0}")]
    ResponseTimeout(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Missing required configuration: {0}")]
    MissingConfig(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid target format: {0}")]
    InvalidTargetFormat(String),

    #[error("Target unreachable: {0}")]
    TargetUnreachable(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Target not authorized for scanning")]
    TargetNotAuthorized,

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Detector error: {0}")]
    Detector(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File watch error: {0}")]
    FileWatch(#[from] notify::Error),

    #[error("CVSS calculation error: {0}")]
    CvssCalculation(String),

    #[error("Result export error: {0}")]
    Export(String),

    #[error("Scan task cancelled")]
    TaskCancelled,

    #[error("Scan task paused")]
    TaskPaused,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl ScannerError {
    pub fn code(&self) -> u16 {
        match self {
            ScannerError::Network(_) => 1001,
            ScannerError::ConnectionTimeout(_) => 1002,
            ScannerError::ResponseTimeout(_) => 1003,
            ScannerError::Parse(_) => 2001,
            ScannerError::Regex(_) => 2002,
            ScannerError::UrlParse(_) => 2003,
            ScannerError::JsonParse(_) => 2004,
            ScannerError::YamlParse(_) => 2005,
            ScannerError::Config(_) => 3001,
            ScannerError::MissingConfig(_) => 3002,
            ScannerError::Validation(_) => 4001,
            ScannerError::InvalidTargetFormat(_) => 4002,
            ScannerError::TargetUnreachable(_) => 4003,
            ScannerError::RateLimit(_) => 5001,
            ScannerError::Authorization(_) => 6001,
            ScannerError::TargetNotAuthorized => 6002,
            ScannerError::Plugin(_) => 7001,
            ScannerError::Detector(_) => 7002,
            ScannerError::Io(_) => 8001,
            ScannerError::FileWatch(_) => 8002,
            ScannerError::CvssCalculation(_) => 9001,
            ScannerError::Export(_) => 9002,
            ScannerError::TaskCancelled => 10001,
            ScannerError::TaskPaused => 10002,
            ScannerError::Unknown(_) => 9999,
        }
    }

    pub fn category(&self) -> &str {
        match self {
            ScannerError::Network(_) | ScannerError::ConnectionTimeout(_) | ScannerError::ResponseTimeout(_) => "network",
            ScannerError::Parse(_) | ScannerError::Regex(_) | ScannerError::UrlParse(_) | ScannerError::JsonParse(_) | ScannerError::YamlParse(_) => "parse",
            ScannerError::Config(_) | ScannerError::MissingConfig(_) => "config",
            ScannerError::Validation(_) | ScannerError::InvalidTargetFormat(_) | ScannerError::TargetUnreachable(_) => "validation",
            ScannerError::RateLimit(_) => "rate_limit",
            ScannerError::Authorization(_) | ScannerError::TargetNotAuthorized => "authorization",
            ScannerError::Plugin(_) | ScannerError::Detector(_) => "plugin",
            ScannerError::Io(_) | ScannerError::FileWatch(_) => "io",
            ScannerError::CvssCalculation(_) | ScannerError::Export(_) => "result",
            ScannerError::TaskCancelled | ScannerError::TaskPaused => "task",
            ScannerError::Unknown(_) => "unknown",
        }
    }
}

pub type Result<T> = std::result::Result<T, ScannerError>;

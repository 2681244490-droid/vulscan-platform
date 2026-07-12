use chrono::{DateTime, Utc};
use uuid::Uuid;

pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn current_time() -> DateTime<Utc> {
    Utc::now()
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, hash)
}

pub fn generate_random_string(length: usize) -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn parse_url(url: &str) -> Result<url::Url, url::ParseError> {
    url::Url::parse(url)
}

pub fn validate_url(url: &str) -> bool {
    parse_url(url).is_ok()
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s.chars().take(max_len).collect::<String>() + "..."
    }
}

pub fn format_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

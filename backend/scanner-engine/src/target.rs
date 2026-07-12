use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use reqwest::Client;
use url::Url;

use crate::error::{Result, ScannerError};
use crate::traits::TargetValidator;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetType {
    Domain(String),
    IpAddress(IpAddr),
    Url(Url),
}

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetType::Domain(d) => write!(f, "{}", d),
            TargetType::IpAddress(ip) => write!(f, "{}", ip),
            TargetType::Url(u) => write!(f, "{}", u),
        }
    }
}

impl TargetType {
    
    pub fn normalize(&self) -> String {
        match self {
            TargetType::Domain(d) => d.to_lowercase(),
            TargetType::IpAddress(ip) => ip.to_string(),
            TargetType::Url(u) => {
                let mut u = u.clone();
                u.set_fragment(None);
                u.query_pairs_mut().clear();
                u.to_string().to_lowercase()
            }
        }
    }
    
    pub fn hostname(&self) -> Option<String> {
        match self {
            TargetType::Domain(d) => Some(d.clone()),
            TargetType::IpAddress(ip) => Some(ip.to_string()),
            TargetType::Url(u) => u.host_str().map(|h| h.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub target_type: TargetType,
    pub priority: u32,
    pub group: Option<String>,
    pub is_authorized: bool,
    pub is_reachable: Option<bool>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Target {
    pub fn new(target_type: TargetType) -> Self {
        Target {
            id: uuid::Uuid::new_v4().to_string(),
            target_type,
            priority: 100,
            group: None,
            is_authorized: false,
            is_reachable: None,
            created_at: chrono::Utc::now(),
        }
    }
    
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
    
    pub fn with_group(mut self, group: &str) -> Self {
        self.group = Some(group.to_string());
        self
    }
    
    pub fn mark_authorized(mut self) -> Self {
        self.is_authorized = true;
        self
    }
    
    pub fn mark_reachable(mut self, reachable: bool) -> Self {
        self.is_reachable = Some(reachable);
        self
    }
    
    pub fn normalized_key(&self) -> String {
        self.target_type.normalize()
    }
}

pub struct TargetManager {
    targets: Arc<tokio::sync::RwLock<HashMap<String, Target>>>,
    groups: Arc<tokio::sync::RwLock<HashMap<String, Vec<String>>>>,
    validator: Arc<dyn TargetValidator + 'static>,
}

impl TargetManager {
    pub fn new(validator: Arc<dyn TargetValidator + 'static>, _client: Arc<Client>) -> Self {
        TargetManager {
            targets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            groups: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            validator,
        }
    }
    
    pub async fn add_target(&self, input: &str) -> Result<Target> {
        let target = self.validator.validate(input).await?;
        let normalized_key = target.normalized_key();
        
        let mut targets = self.targets.write().await;
        if targets.contains_key(&normalized_key) {
            return Err(ScannerError::Validation(format!("Target already exists: {}", input)));
        }
        
        targets.insert(normalized_key.clone(), target.clone());
        
        if let Some(group) = &target.group {
            let mut groups = self.groups.write().await;
            groups.entry(group.clone()).or_default().push(normalized_key);
        }
        
        Ok(target)
    }
    
    pub async fn add_targets(&self, inputs: &[&str]) -> Result<Vec<Target>> {
        let mut results = Vec::new();
        for input in inputs {
            match self.add_target(input).await {
                Ok(target) => results.push(target),
                Err(e) => {
                    tracing::warn!("Failed to add target {}: {}", input, e);
                }
            }
        }
        Ok(results)
    }
    
    pub async fn add_cidr(&self, cidr: &str) -> Result<Vec<Target>> {
        let net: IpNet = cidr.parse()
            .map_err(|e| ScannerError::InvalidTargetFormat(format!("Invalid CIDR: {}, error: {}", cidr, e)))?;
        
        let mut targets = Vec::new();
        for ip in net.hosts() {
            let input = ip.to_string();
            match self.add_target(&input).await {
                Ok(target) => targets.push(target),
                Err(e) => {
                    tracing::debug!("Failed to add IP {} from CIDR: {}", ip, e);
                }
            }
        }
        
        Ok(targets)
    }
    
    pub async fn remove_target(&self, key: &str) -> Result<bool> {
        let normalized_key = self.normalize_key(key);
        let mut targets = self.targets.write().await;
        
        if let Some(target) = targets.remove(&normalized_key) {
            if let Some(group) = &target.group {
                let mut groups = self.groups.write().await;
                if let Some(keys) = groups.get_mut(group) {
                    keys.retain(|k| k != &normalized_key);
                    if keys.is_empty() {
                        groups.remove(group);
                    }
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    pub async fn get_target(&self, key: &str) -> Option<Target> {
        let normalized_key = self.normalize_key(key);
        let targets = self.targets.read().await;
        targets.get(&normalized_key).cloned()
    }
    
    pub async fn list_targets(&self) -> Vec<Target> {
        let targets = self.targets.read().await;
        targets.values().cloned().collect()
    }
    
    pub async fn list_targets_by_group(&self, group: &str) -> Vec<Target> {
        let groups = self.groups.read().await;
        let targets = self.targets.read().await;
        
        groups.get(group)
            .map(|keys| keys.iter()
                .filter_map(|k| targets.get(k))
                .cloned()
                .collect())
            .unwrap_or_default()
    }
    
    pub async fn get_groups(&self) -> Vec<String> {
        let groups = self.groups.read().await;
        groups.keys().cloned().collect()
    }
    
    pub async fn validate_all(&self) -> Result<Vec<Target>> {
        let targets = self.list_targets().await;
        let mut validated = Vec::new();
        
        for mut target in targets {
            if !target.is_authorized {
                match self.validator.is_authorized(&target).await {
                    Ok(true) => {
                        target.is_authorized = true;
                        validated.push(target.clone());
                    }
                    Ok(false) => {
                        tracing::warn!("Target not authorized: {}", target.target_type.to_string());
                    }
                    Err(e) => {
                        tracing::warn!("Authorization check failed for {}: {}", target.target_type.to_string(), e);
                    }
                }
            } else {
                validated.push(target);
            }
        }
        
        Ok(validated)
    }
    
    pub async fn check_reachability(&self, key: &str) -> Result<bool> {
        let target = self.get_target(key).await
            .ok_or_else(|| ScannerError::Validation(format!("Target not found: {}", key)))?;
        
        let reachable = self.validator.is_reachable(&target).await?;
        
        let mut targets = self.targets.write().await;
        if let Some(t) = targets.get_mut(&target.normalized_key()) {
            t.is_reachable = Some(reachable);
        }
        
        Ok(reachable)
    }
    
    pub async fn check_all_reachability(&self) -> Result<Vec<(String, bool)>> {
        let targets = self.list_targets().await;
        let mut results = Vec::new();
        
        for target in targets {
            let reachable = match self.validator.is_reachable(&target).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Reachability check failed for {}: {}", target.target_type.to_string(), e);
                    false
                }
            };
            
            let mut targets_lock = self.targets.write().await;
            if let Some(t) = targets_lock.get_mut(&target.normalized_key()) {
                t.is_reachable = Some(reachable);
            }
            
            results.push((target.id, reachable));
        }
        
        Ok(results)
    }
    
    pub async fn sort_by_priority(&self) -> Vec<Target> {
        let mut targets = self.list_targets().await;
        targets.sort_by_key(|a| a.priority);
        targets
    }
    
    pub async fn get_authorized_targets(&self) -> Vec<Target> {
        let targets = self.list_targets().await;
        targets.into_iter()
            .filter(|t| t.is_authorized)
            .collect()
    }
    
    pub async fn get_reachable_targets(&self) -> Vec<Target> {
        let targets = self.list_targets().await;
        targets.into_iter()
            .filter(|t| t.is_reachable.unwrap_or(false))
            .collect()
    }
    
    pub async fn count(&self) -> usize {
        let targets = self.targets.read().await;
        targets.len()
    }
    
    pub async fn clear(&self) {
        let mut targets = self.targets.write().await;
        targets.clear();
        
        let mut groups = self.groups.write().await;
        groups.clear();
    }
    
    fn normalize_key(&self, key: &str) -> String {
        if let Ok(url) = Url::parse(key) {
            let mut u = url;
            u.set_fragment(None);
            u.query_pairs_mut().clear();
            return u.to_string().to_lowercase();
        }
        
        key.to_lowercase()
    }
}

#[derive(Debug, Clone)]
pub struct DefaultTargetValidator {
    client: Arc<Client>,
    allowed_protocols: HashSet<String>,
    max_url_length: usize,
}

impl DefaultTargetValidator {
    pub fn new(client: Arc<Client>) -> Self {
        let mut allowed_protocols = HashSet::new();
        allowed_protocols.insert("http".to_string());
        allowed_protocols.insert("https".to_string());
        
        DefaultTargetValidator {
            client,
            allowed_protocols,
            max_url_length: 2048,
        }
    }
}

#[async_trait]
impl TargetValidator for DefaultTargetValidator {
    async fn validate(&self, target: &str) -> Result<Target> {
        if target.is_empty() {
            return Err(ScannerError::InvalidTargetFormat("Empty target".to_string()));
        }
        
        if target.len() > self.max_url_length {
            return Err(ScannerError::InvalidTargetFormat(
                format!("Target too long (max {} characters)", self.max_url_length)
            ));
        }
        
        let target_type = if let Ok(url) = Url::parse(target) {
            if !self.allowed_protocols.contains(url.scheme()) {
                return Err(ScannerError::InvalidTargetFormat(
                    format!("Unsupported protocol: {}", url.scheme())
                ));
            }
            if url.host_str().is_none() {
                return Err(ScannerError::InvalidTargetFormat("URL missing host".to_string()));
            }
            TargetType::Url(url)
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            TargetType::IpAddress(ip)
        } else {
            let normalized_domain = target.to_lowercase();
            if !self.is_valid_domain(&normalized_domain) {
                return Err(ScannerError::InvalidTargetFormat(
                    format!("Invalid domain format: {}", target)
                ));
            }
            TargetType::Domain(normalized_domain)
        };
        
        Ok(Target::new(target_type))
    }
    
    async fn is_reachable(&self, target: &Target) -> Result<bool> {
        let url = match &target.target_type {
            TargetType::Url(u) => u.clone(),
            TargetType::Domain(d) => Url::parse(&format!("https://{}", d))
                .or_else(|_| Url::parse(&format!("http://{}", d)))
                .map_err(ScannerError::UrlParse)?,
            TargetType::IpAddress(ip) => Url::parse(&format!("https://{}", ip))
                .or_else(|_| Url::parse(&format!("http://{}", ip)))
                .map_err(ScannerError::UrlParse)?,
        };
        
        let timeout = Duration::from_secs(10);
        let result = tokio::time::timeout(timeout, async {
            self.client.head(url.as_str()).send().await.is_ok()
        }).await;
        
        match result {
            Ok(reachable) => Ok(reachable),
            Err(_) => Err(ScannerError::ConnectionTimeout(
                format!("Timeout checking reachability for {}", target.target_type)
            )),
        }
    }
    
    async fn is_authorized(&self, target: &Target) -> Result<bool> {
        Ok(target.is_authorized)
    }
}

impl DefaultTargetValidator {
    fn is_valid_domain(&self, domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        
        for part in parts {
            if part.is_empty() || part.len() > 63 {
                return false;
            }
            
            if !part.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-'
            }) {
                return false;
            }
            
            if part.starts_with('-') || part.ends_with('-') {
                return false;
            }
        }
        
        true
    }
}

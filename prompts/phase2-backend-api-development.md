# 阶段二：后端 API 开发阶段 — AI 提示词

## 角色定义

你是一位拥有 10 年以上 Rust 后端开发经验的**高级 Rust 后端工程师**，精通以下领域：
- Axum 0.7+ 异步 Web 框架，深入理解 Tower 中间件生态系统、Extractor 模式、路由组织
- SQLx 0.7+ 编译期 SQL 校验、连接池管理、事务处理、PostgreSQL 特有类型（UUID、JSONB、数组类型）
- JWT 认证与 RBAC 权限模型的安全实现，熟悉 OAuth 2.0 / OIDC 协议
- Redis 高性能缓存、分布式锁、Pub/Sub 消息通信、令牌桶限流算法
- Rust 异步编程（tokio 生态）、Send/Sync 约束、生命周期管理、Pin/Unpin 语义
- 密码学安全实践（Argon2id 哈希、AES-256-GCM 加密、HMAC 签名）
- 结构化日志（tracing 生态）与分布式追踪（OpenTelemetry）

**职责范围：**
- 实现 Web API 服务的全部 RESTful 端点
- 实现认证授权模块（JWT 签发/验证/刷新、RBAC 权限校验中间件）
- 实现数据库访问层（Repository 模式、连接池、迁移脚本）
- 实现安全中间件（限流、CORS、错误处理、请求审计）
- 实现任务调度与消息队列通信（Redis Pub/Sub）
- 实现 WebSocket/SSE 端点用于实时进度推送
- 编写完整的单元测试与集成测试

---

## 技术约束

### 框架与依赖版本
| 依赖 | 版本 | 用途 |
|------|------|------|
| axum | 0.7+ | Web 框架 |
| tokio | 1.35+ | 异步运行时（full features） |
| sqlx | 0.7+ | 数据库访问（features: postgres, uuid, chrono, json, macros） |
| redis | 0.25+ | Redis 客户端（features: tokio-comp, connection-manager） |
| serde / serde_json | 1.0+ | 序列化 |
| serde_yaml | 0.9+ | YAML 配置解析 |
| jsonwebtoken | 9.2+ | JWT 处理 |
| argon2 | 0.5+ | 密码哈希 |
| tracing | 0.1+ | 结构化日志 |
| tracing-subscriber | 0.3+ | 日志订阅器（features: json, env-filter） |
| tower / tower-http | 0.4+ / 0.5+ | 中间件（CORS, compression, trace, timeout） |
| uuid | 1.7+ | UUID 生成（features: v4, serde） |
| chrono | 0.4+ | 时间处理（features: serde） |
| thiserror | 1.0+ | 错误派生 |
| anyhow | 1.0+ | 错误传播（仅用于应用层，不暴露到 API 边界） |
| config | 0.13+ | 配置管理 |
| validator | 0.16+ | 输入校验 |
| axum-extra | 0.9+ | 额外 Extractor（TypedHeader, Cookie 等） |
| async-trait | 0.1+ | 异步 Trait |

### 编码约束
1. **禁止 unwrap/expect**：所有可能失败的操作必须返回 `Result<T, E>`，仅允许在测试代码中使用 unwrap
2. **禁止 panic**：使用 `Result` 类型处理所有错误路径，禁止使用 `panic!`、`todo!`、`unreachable!`
3. **禁止 unsafe**：除非有充分的安全论证和 SAFETY 注释
4. **Clippy 零警告**：所有代码必须通过 `cargo clippy -- -D warnings` 检查
5. **Send + Sync**：所有跨 await 边界的数据必须满足 `Send` 约束，数据库连接池等资源必须 `Sync`
6. **错误传播**：使用 `?` 操作符传播错误，在 API 边界统一转换为 `AppError` 响应
7. **资源释放**：所有 `Drop` trait 实现必须安全释放资源，禁止泄漏文件句柄/连接

### 数据库约束
- 所有查询使用 SQLx 的 `query!` / `query_as!` 宏进行编译期校验
- 事务使用 `pool.begin().await?` 显式管理，确保 `commit` 或 `rollback`
- 连接池配置：max_connections = 20, min_connections = 5, acquire_timeout = 30s
- 所有表必须包含 `created_at` 和 `updated_at` 字段，使用 `TIMESTAMPTZ` 类型
- 使用 PostgreSQL 的 `uuid_generate_v4()` 自动生成主键

---

## 功能清单

### 1. 项目初始化与配置模块
- **配置加载系统**：支持从 YAML 文件、环境变量、默认值三层合并加载配置
  - 数据库连接配置（host, port, database, username, password, pool_size）
  - Redis 连接配置（host, port, password, db_index）
  - JWT 配置（secret, access_token_ttl, refresh_token_ttl, issuer）
  - 服务器配置（host, port, workers, request_timeout）
  - 限流配置（ip_rate_limit, user_rate_limits）
  - 加密配置（aes_key, hmac_key）
- **应用启动流程**：初始化日志 → 加载配置 → 建立数据库连接池 → 建立 Redis 连接池 → 注册路由 → 启动 HTTP 服务
- **优雅停机**：捕获 SIGINT/SIGTERM 信号，等待进行中的请求完成（超时 30s），关闭连接池

### 2. 认证授权模块（auth-service crate）
- **登录接口** `POST /api/v1/auth/login`
  - 接收 username/email + password，验证 Argon2id 哈希
  - 签发 Access Token（30min）+ Refresh Token（7d）
  - Refresh Token 存入 Redis（key: `refresh:{user_id}:{token_id}`，TTL: 7d）
  - 登录失败计数（5次锁定，Redis key: `login_fail:{username}`，TTL: 15min）
  - 记录登录审计日志
- **令牌刷新接口** `POST /api/v1/auth/refresh`
  - 验证 Refresh Token 有效性 + Redis 黑名单检查
  - 签发新的 Access Token，旧 Access Token 加入黑名单（TTL: 剩余有效期）
- **登出接口** `POST /api/v1/auth/logout`
  - 当前 Access Token + Refresh Token 加入 Redis 黑名单
- **当前用户信息** `GET /api/v1/auth/me`
  - 返回用户基本信息、角色、权限列表
- **JWT 中间件**：从 Authorization Header 提取 Bearer Token，验证签名 + 过期时间 + 黑名单
- **RBAC 权限中间件**：基于路由元数据 + 用户角色进行权限校验，不满足权限返回 403
  - admin：全部权限
  - auditor：目标管理、任务管理、漏洞查看/处理、报告生成
  - viewer：仅查看权限

### 3. 用户管理模块
- `GET /api/v1/users` — 用户列表（分页、搜索、角色筛选）
- `POST /api/v1/users` — 创建用户（仅 admin）
- `GET /api/v1/users/{id}` — 用户详情
- `PUT /api/v1/users/{id}` — 更新用户信息
- `DELETE /api/v1/users/{id}` — 删除用户（软删除）
- `PATCH /api/v1/users/{id}/status` — 启用/禁用/锁定用户
- `PATCH /api/v1/users/{id}/role` — 修改用户角色（仅 admin）
- `PUT /api/v1/users/{id}/password` — 修改密码（验证旧密码）
- 密码强度校验：最少 8 位，包含大小写字母 + 数字 + 特殊字符

### 4. 目标管理模块
- `GET /api/v1/targets` — 目标列表（分页、搜索、类型筛选、状态筛选、分组筛选）
- `POST /api/v1/targets` — 添加单个目标
  - 输入校验：域名格式（RFC 1035）、IP 格式（IPv4/IPv6）、URL 格式
  - 可达性预检测（HEAD 请求，超时 5s）
  - 授权证明字段非空校验
- `POST /api/v1/targets/batch` — 批量导入目标
  - 支持 JSON 数组、TXT 文件（每行一个目标）、CSV 文件
  - 单次上限 1000 条
  - 自动去重（基于 address + port）
  - 返回导入结果：成功数、失败数、失败详情
- `GET /api/v1/targets/{id}` — 目标详情
- `PUT /api/v1/targets/{id}` — 更新目标
- `DELETE /api/v1/targets/{id}` — 删除目标
- `POST /api/v1/targets/{id}/check` — 可达性检测
- `GET /api/v1/target-groups` / `POST /api/v1/target-groups` — 目标分组 CRUD
- 目标优先级排序（0-9，数字越小优先级越高）

### 5. 任务管理模块
- `GET /api/v1/tasks` — 任务列表（分页、状态筛选、创建时间排序）
- `POST /api/v1/tasks` — 创建扫描任务
  - 关联目标 ID 列表、扫描规则 ID 列表
  - 设置并发数（1-100）和优先级（0-9）
  - 创建后状态为 `queued`，通过 Redis Pub/Sub 通知扫描引擎
- `GET /api/v1/tasks/{id}` — 任务详情（含进度信息）
- `POST /api/v1/tasks/{id}/start` — 启动任务
- `POST /api/v1/tasks/{id}/pause` — 暂停任务（发送暂停信号到 Redis）
- `POST /api/v1/tasks/{id}/resume` — 恢复任务
- `POST /api/v1/tasks/{id}/cancel` — 终止任务
- `DELETE /api/v1/tasks/{id}` — 删除任务（二次确认，删除关联漏洞数据）
- `GET /api/v1/tasks/{id}/progress` — 任务进度（SSE 实时推送）
  - SSE 事件格式：`event: progress\ndata: {"task_id":"...","progress":45,"completed":90,"total":200,"vuln_count":3}\n\n`
  - 推送频率：不低于 5 秒/次

### 6. 漏洞管理模块
- `GET /api/v1/vulnerabilities` — 漏洞列表
  - 多条件筛选：severity（critical/high/medium/low/info）、vuln_type、status、target_id、task_id、时间范围
  - 分页、排序（cvss_score、created_at、severity）
- `GET /api/v1/vulnerabilities/{id}` — 漏洞详情（完整字段）
- `PATCH /api/v1/vulnerabilities/{id}/status` — 更新漏洞状态
  - 状态流转：open → fixed / open → ignored / open → verifying → fixed/ignored
  - 记录 handled_by（当前用户）、handled_at（当前时间）
- `POST /api/v1/vulnerabilities/export` — 导出漏洞数据
  - 支持 JSON、CSV 格式
  - 按当前筛选条件导出
- 漏洞去重逻辑：基于 (target_id, vuln_type, affected_url, payload_hash) 四元组去重

### 7. 报告管理模块
- `POST /api/v1/reports/generate` — 生成报告
  - 参数：task_id, template_type（overview/detailed/remediation）, format（pdf/html）
  - 异步生成（Redis 队列），返回 report_id
- `GET /api/v1/reports` — 报告列表（分页）
- `GET /api/v1/reports/{id}` — 报告详情
- `GET /api/v1/reports/{id}/preview` — 报告预览（返回 HTML 内容）
- `GET /api/v1/reports/{id}/download` — 下载报告文件

### 8. 扫描规则管理模块
- `GET /api/v1/rules` — 规则列表
- `GET /api/v1/rules/{id}` — 规则详情
- `POST /api/v1/rules` — 创建自定义规则（YAML 格式）
- `PUT /api/v1/rules/{id}` — 更新规则
- `DELETE /api/v1/rules/{id}` — 删除规则
- `POST /api/v1/rules/reload` — 触发规则热加载（通知扫描引擎重新加载规则）

### 9. 仪表盘统计模块
- `GET /api/v1/dashboard/stats` — 核心指标（今日扫描数、高危漏洞数、待修复漏洞数、目标总数）
- `GET /api/v1/dashboard/trends` — 扫描趋势（参数：granularity=day/week/month, date_range）
- `GET /api/v1/dashboard/vuln-distribution` — 漏洞分布（按类型、按等级）
- 数据使用 Redis 缓存（TTL: 5min），缓存击穿保护

### 10. 安全中间件
- **统一错误处理中间件**：
  - 定义 `AppError` 枚举（包含 BadRequest、Unauthorized、Forbidden、NotFound、Conflict、RateLimit、Internal 等变体）
  - 实现 `IntoResponse` trait，统一转换为 JSON 错误响应
  - 错误响应格式：`{ "code": "ERROR_CODE", "message": "描述信息", "details": null, "request_id": "uuid" }`
  - 内部错误脱敏：生产环境不暴露内部错误堆栈
- **限流中间件**：
  - 基于 Redis 的令牌桶算法
  - IP 级限流：100 req/min
  - 用户级限流：按角色分级（admin 1000/min, auditor 500/min, viewer 200/min）
  - 超限返回 429 + `Retry-After` Header
- **CORS 中间件**：白名单域名配置，允许的标准头和方法
- **请求审计日志中间件**：记录请求方法、路径、查询参数（脱敏）、响应状态码、耗时、操作人 ID、request_id
- **请求 ID 中间件**：为每个请求生成 UUID，注入到请求上下文和响应 Header（`X-Request-Id`）

### 11. 数据库访问层（db-layer crate）
- **Repository 模式**：为每张表定义 Repository struct
  - `UserRepository`、`TargetRepository`、`TaskRepository`、`VulnerabilityRepository`、`ReportRepository`
  - 每个 Repository 持有 `PgPool` 引用
  - 提供 CRUD 方法 + 业务查询方法
- **迁移脚本**：使用 SQLx 迁移工具管理数据库版本
- **数据库连接池**：`PgPoolOptions` 配置，健康检查查询

### 12. 消息队列通信（web-api → scanner-engine）
- **任务下发**：Web API 创建任务后，通过 Redis Pub/Sub 频道 `task:dispatch` 发送任务消息
  - 消息格式：`{ "action": "start", "task_id": "uuid", "target_ids": [...], "rule_ids": [...], "concurrency": 50 }`
- **进度接收**：Web API 订阅 Redis 频道 `task:progress:{task_id}`，转发为 SSE 推送给前端
- **结果接收**：Web API 订阅 Redis 频道 `task:results:{task_id}`，写入数据库
- **控制指令**：暂停/恢复/终止通过 Redis 频道 `task:control:{task_id}` 发送

---

## 代码规范

### 文件组织结构
```
web-api/
├── Cargo.toml
├── src/
│   ├── main.rs              # 应用入口，启动 HTTP 服务
│   ├── lib.rs               # 模块导出
│   ├── config/
│   │   ├── mod.rs           # 配置模块入口
│   │   ├── app_config.rs    # 配置结构体定义
│   │   └── loader.rs        # 配置加载逻辑
│   ├── error/
│   │   ├── mod.rs           # 错误模块入口
│   │   ├── app_error.rs     # AppError 枚举定义
│   │   └── codes.rs         # 错误码常量定义
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs          # JWT 认证中间件
│   │   ├── rbac.rs          # RBAC 权限中间件
│   │   ├── rate_limit.rs    # 限流中间件
│   │   ├── request_id.rs    # 请求 ID 中间件
│   │   ├── audit.rs         # 审计日志中间件
│   │   └── error_handler.rs # 错误处理中间件
│   ├── routes/
│   │   ├── mod.rs           # 路由注册
│   │   ├── auth.rs          # 认证路由
│   │   ├── users.rs         # 用户管理路由
│   │   ├── targets.rs       # 目标管理路由
│   │   ├── tasks.rs         # 任务管理路由
│   │   ├── vulnerabilities.rs
│   │   ├── reports.rs
│   │   ├── rules.rs
│   │   ├── dashboard.rs
│   │   └── ws.rs            # WebSocket/SSE 路由
│   ├── handlers/            # 请求处理器（与路由对应）
│   │   ├── mod.rs
│   │   ├── auth_handler.rs
│   │   ├── user_handler.rs
│   │   ├── target_handler.rs
│   │   ├── task_handler.rs
│   │   ├── vuln_handler.rs
│   │   ├── report_handler.rs
│   │   ├── rule_handler.rs
│   │   └── dashboard_handler.rs
│   ├── models/              # 数据模型（请求/响应 DTO）
│   │   ├── mod.rs
│   │   ├── auth_dto.rs
│   │   ├── user_dto.rs
│   │   ├── target_dto.rs
│   │   ├── task_dto.rs
│   │   ├── vuln_dto.rs
│   │   └── report_dto.rs
│   ├── services/            # 业务逻辑层
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   ├── user_service.rs
│   │   ├── target_service.rs
│   │   ├── task_service.rs
│   │   ├── vuln_service.rs
│   │   └── report_service.rs
│   ├── mq/                  # 消息队列通信
│   │   ├── mod.rs
│   │   ├── publisher.rs     # 消息发布
│   │   └── subscriber.rs    # 消息订阅
│   └── state.rs             # AppState 定义（共享状态）
├── tests/                   # 集成测试
│   ├── auth_test.rs
│   ├── target_test.rs
│   ├── task_test.rs
│   └── common/
│       └── mod.rs           # 测试公共工具
└── migrations/              # 数据库迁移脚本
```

### 代码风格
- 函数最大长度：50 行（超出需拆分）
- 模块文件最大行数：500 行（超出需拆分模块）
- 使用 `#[derive(Debug, Clone, Serialize, Deserialize)]` 为所有 DTO 派生常用 trait
- 所有公共 API 函数添加 `///` 文档注释（包含 `# Arguments`、`# Returns`、`# Errors` 段落）
- 使用 `#[instrument]` 属性为关键函数添加 tracing span
- 所有 SQL 查询使用 `query!` / `query_as!` 宏，禁止字符串拼接 SQL
- 使用 `validator` crate 对输入 DTO 进行校验，使用 `#[validate(...)]` 属性

### 日志规范
- 使用 `tracing` 宏：`tracing::info!`、`tracing::warn!`、`tracing::error!`、`tracing::debug!`
- 关键操作日志需包含上下文：`tracing::info!(user_id = %user.id, action = "login", "User logged in")`
- 日志输出格式：JSON 结构化日志（生产环境）、Pretty 格式（开发环境）
- 日志级别使用规范：
  - `error!`：系统错误、不可恢复的异常
  - `warn!`：业务异常、限流触发、认证失败
  - `info!`：关键业务操作（登录、任务创建、漏洞发现）
  - `debug!`：调试信息（请求详情、SQL 查询）
- 敏感信息脱敏：日志中禁止出现密码、Token、密钥等敏感数据

### 测试规范
- 单元测试：`#[cfg(test)] mod tests` 放在每个模块文件末尾
- 集成测试：`tests/` 目录下独立文件
- 测试覆盖率目标：核心业务逻辑 ≥ 80%，整体 ≥ 70%
- 测试命名规范：`test_{被测函数}_{测试场景}_{预期结果}`（如 `test_login_with_valid_credentials_returns_token`）
- 使用 `sqlx::test` 宏进行数据库测试（自动创建/清理测试数据库）
- Mock 外部依赖（Redis、HTTP 请求）使用 `mockall` crate

---

## 输出格式

### 交付物清单

1. **Cargo.toml 配置文件**
   - web-api crate 的完整 `Cargo.toml`，含所有依赖及精确版本号
   - workspace 根 `Cargo.toml` 的 `[workspace.dependencies]` 公共依赖声明

2. **核心源码文件**
   - `src/main.rs`：应用入口（初始化、路由注册、优雅停机）
   - `src/state.rs`：AppState 定义（PgPool, RedisPool, Config 等）
   - `src/config/`：完整配置加载模块
   - `src/error/app_error.rs`：AppError 枚举 + IntoResponse 实现
   - `src/middleware/`：全部中间件实现
   - `src/routes/` + `src/handlers/`：全部 API 端点实现
   - `src/models/`：全部 DTO 结构体定义
   - `src/services/`：全部业务逻辑实现
   - `src/mq/`：消息队列通信实现

3. **数据库迁移脚本**
   - `migrations/V1__create_users.sql`
   - `migrations/V2__create_targets.sql`
   - `migrations/V3__create_scan_tasks.sql`
   - `migrations/V4__create_vulnerabilities.sql`
   - `migrations/V5__create_reports.sql`
   - `migrations/V6__create_aux_tables.sql`（target_groups, scan_rules, audit_logs 等）

4. **测试代码**
   - 核心模块单元测试（auth_service, target_service, task_service 等）
   - API 集成测试（至少覆盖：登录流程、目标 CRUD、任务创建/控制、漏洞查询/导出）
   - 中间件测试（JWT 验证、RBAC 权限、限流、错误处理）

5. **配置文件模板**
   - `config/default.yaml`：默认配置
   - `config/production.yaml`：生产环境配置模板
   - `.env.example`：环境变量示例

6. **API 文档**
   - 通过 `utoipa` crate 自动生成的 OpenAPI 文档（或手写 `openapi.yaml` 补充）
   - 每个端点的请求/响应示例

### 质量标准
- 代码通过 `cargo build --release` 编译无错误
- 代码通过 `cargo clippy -- -D warnings` 无警告
- 代码通过 `cargo test` 全部测试通过
- 代码通过 `cargo fmt --check` 格式检查
- 无任何 `unwrap()` / `expect()` / `panic!` 在非测试代码中
- 所有公共函数和类型有文档注释
- 错误处理覆盖所有可能的失败路径

# VulScan - 企业级Web漏洞扫描平台

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange)](https://www.rust-lang.org/)
[![React](https://img.shields.io/badge/React-18-blue)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)
[![Actix-web](https://img.shields.io/badge/Actix--web-4.5-green)](https://actix.rs/)
[![Ant Design](https://img.shields.io/badge/Ant%20Design-5.x-blue)](https://ant.design/)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 目录

- [项目概述](#项目概述)
- [核心功能说明](#核心功能说明)
- [系统架构](#系统架构)
- [环境要求](#环境要求)
- [安装步骤](#安装步骤)
- [配置指南](#配置指南)
- [使用示例](#使用示例)
- [API文档](#api文档)
- [贡献指南](#贡献指南)
- [许可证信息](#许可证信息)

## 项目概述

### 核心价值

VulScan 是一个高性能、模块化的企业级 Web 漏洞扫描平台，采用 Rust + React 技术栈构建。其核心价值在于：

- **高性能扫描引擎**：基于 tokio 异步运行时，支持大规模并发扫描
- **误报过滤机制**：内置智能误报过滤，显著降低误报率
- **实时进度推送**：通过 WebSocket/SSE 实时展示扫描进度
- **完整权限管理**：JWT 认证 + 细粒度 RBAC 角色权限控制
- **多格式报告导出**：支持 PDF、HTML、JSON、CSV 格式
- **规则热加载**：无需重启即可更新扫描规则

### 开发背景

随着 Web 应用的快速发展，安全漏洞的发现和修复变得越来越重要。传统的漏洞扫描工具存在以下痛点：

- 扫描速度慢，无法应对大规模目标
- 误报率高，浪费安全团队时间
- 缺乏实时反馈，用户体验差
- 难以集成到现有安全体系

VulScan 旨在解决这些问题，提供一个现代化、可扩展的漏洞扫描解决方案。

### 目标用户群体

- **企业安全团队**：需要定期扫描企业内部系统和对外服务
- **渗透测试人员**：需要专业的漏洞扫描工具辅助测试
- **DevOps 工程师**：需要将安全扫描集成到 CI/CD 流程
- **安全研究人员**：需要可扩展的扫描框架进行安全研究

### 主要应用场景

- 定期安全审计：对企业资产进行周期性漏洞扫描
- 渗透测试：辅助安全测试人员发现系统漏洞
- CI/CD 集成：在代码部署前进行安全扫描
- 合规检查：满足等保、SOC2 等合规要求

## 核心功能说明

### 1. 扫描引擎

| 功能 | 描述 | 技术亮点 |
|------|------|---------|
| 并发控制 | 使用 `tokio::sync::Semaphore` 实现精确并发控制 | 默认 50 并发，可动态调整 |
| 流式处理 | Stream API 流式处理目标列表 | 避免全量加载导致内存峰值 |
| 动态速率限制 | 基于令牌桶算法的动态限速 | 根据目标响应状态自动调整 |
| 扫描生命周期 | 支持暂停、恢复、取消操作 | 原子状态管理确保数据一致性 |
| 实时进度推送 | 使用 tokio watch channel 推送进度 | 毫秒级进度更新 |

**差异化优势**：相比传统扫描工具，VulScan 的异步架构能够在同等硬件条件下处理 3-5 倍的目标数量，同时保持低误报率。

### 2. 漏洞检测模块

| 检测器 | 严重级别 | 描述 | CVE映射 |
|--------|---------|------|---------|
| SQL注入检测 | Critical | 支持基于错误和时间盲注的检测 | CVE-2019-9193, CVE-2021-44228 |
| XSS检测 | High | 支持多种 payload 绕过技术 | CVE-2020-9483, CVE-2021-41773 |
| 敏感文件检测 | High | 检测 .git、.env、备份文件等暴露 | CVE-2020-10762, CVE-2023-34362 |
| 端口扫描 | Info | 识别开放的 TCP 端口和服务 | - |

**技术亮点**：

- **误报过滤机制**：基线响应对比 + 漏洞签名确认，有效减少误报
- **技术指纹识别**：自动识别目标技术栈（Apache、Nginx、WordPress、Drupal 等）
- **请求审计日志**：完整记录所有请求，支持审计追溯

### 3. 规则管理系统

| 功能 | 描述 |
|------|------|
| 规则定义 | 支持 YAML/JSON 格式的规则文件 |
| 热加载 | 文件监控自动重载规则，无需重启 |
| 优先级控制 | 支持规则优先级排序 |
| 检测器配置 | 独立配置每个检测器的参数 |

### 4. 任务调度系统

| 功能 | 描述 |
|------|------|
| 任务队列 | Redis 分布式任务队列 |
| 定时扫描 | 支持按频率自动扫描 |
| 任务优先级 | 支持 critical/high/medium/low |
| 状态管理 | pending/running/completed/failed/cancelled |

### 5. 前端管理后台

| 功能模块 | 描述 |
|---------|------|
| 仪表盘 | 漏洞统计、扫描趋势可视化 |
| 目标管理 | 添加、编辑、删除扫描目标 |
| 扫描任务 | 创建、控制、查看扫描任务 |
| 漏洞管理 | 漏洞列表、状态更新、导出 |
| 报告管理 | 报告生成、预览、下载 |
| 用户管理 | 用户注册、登录、角色管理 |

## 系统架构

### 架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              用户层                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                      │
│  │  Web UI      │  │  CLI         │  │  API Client  │                      │
│  │  (React)     │  │  (Rust)      │  │  (Any)       │                      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                      │
└─────────│─────────────────│─────────────────│──────────────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API 网关层                                      │
│                         ┌──────────────┐                                    │
│                         │  Web API     │                                    │
│                         │ (Actix-web)  │                                    │
│                         └──────┬───────┘                                    │
│                                │                                            │
└────────────────────────────────│────────────────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Auth Service│      │  Scheduler   │      │  Worker Pool │
│  (JWT/RBAC)  │      │  (Redis)     │      │  (Scanner)   │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              数据层                                          │
│  ┌──────────────┐                    ┌──────────────┐                      │
│  │ PostgreSQL   │                    │    Redis     │                      │
│  │ (持久化)     │                    │ (缓存/队列)  │                      │
│  └──────────────┘                    └──────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 项目目录结构

```
VulScan/
├── backend/
│   ├── auth-service/          # JWT认证与RBAC权限服务
│   │   └── src/
│   │       ├── jwt.rs         # JWT令牌生成与验证
│   │       ├── rbac.rs        # 角色权限控制
│   │       ├── service.rs     # 认证服务逻辑
│   │       └── store.rs       # 用户数据存储
│   ├── scanner-engine/        # 漏洞扫描引擎核心
│   │   └── src/
│   │       ├── engine.rs      # 扫描引擎主控
│   │       ├── detectors.rs   # 检测器插件集合
│   │       ├── rate_limiter.rs# 动态速率限制器
│   │       ├── target.rs      # 目标管理
│   │       ├── result.rs      # 结果收集与导出
│   │       ├── rules.rs       # 规则热加载系统
│   │       ├── traits.rs      # 检测器 trait 定义
│   │       ├── worker.rs      # 扫描工作进程
│   │       └── error.rs       # 错误处理枚举
│   ├── task-scheduler/        # 任务调度器
│   │   └── src/
│   │       ├── scheduler.rs   # 调度逻辑
│   │       └── queue.rs       # Redis队列管理
│   ├── web-api/               # RESTful API服务
│   │   └── src/
│   │       ├── main.rs        # 服务入口
│   │       ├── routes.rs      # 路由定义
│   │       ├── services.rs    # 业务服务
│   │       ├── middleware.rs  # 中间件
│   │       └── config.rs      # 配置加载
│   ├── shared-lib/            # 共享库（模型、错误、日志）
│   │   └── src/
│   │       ├── models.rs      # 数据库模型定义
│   │       ├── schemas.rs     # API 请求/响应 schema
│   │       ├── errors.rs      # 统一错误类型
│   │       ├── logging.rs     # 日志配置
│   │       └── metrics.rs     # Prometheus指标
│   ├── plugin-system/         # 插件系统框架
│   │   └── src/
│   │       ├── base.rs        # 插件基类
│   │       ├── plugins.rs     # 插件实现
│   │       └── registry.rs    # 插件注册中心
│   └── db-migrations/         # 数据库迁移工具
│       └── src/
│           └── main.rs        # 迁移入口
├── frontend/                  # React管理后台
│   ├── src/
│   │   ├── api/               # Axios API封装
│   │   ├── components/        # 公共组件
│   │   ├── context/           # React Context
│   │   ├── hooks/             # 自定义Hooks
│   │   ├── pages/             # 页面组件
│   │   │   ├── Dashboard.tsx  # 仪表盘
│   │   │   ├── Login.tsx      # 登录页
│   │   │   ├── Targets.tsx    # 目标管理
│   │   │   ├── ScanTasks.tsx  # 扫描任务
│   │   │   ├── Vulnerabilities.tsx # 漏洞管理
│   │   │   ├── Reports.tsx    # 报告管理
│   │   │   └── Settings.tsx   # 系统设置
│   │   └── types/             # TypeScript类型定义
│   ├── index.css              # 全局样式（Cyberpunk主题）
│   ├── tailwind.config.js     # Tailwind配置
│   ├── vite.config.ts         # Vite配置
│   └── package.json           # 前端依赖
├── docs/
│   ├── erd.md                 # 数据库ERD设计
│   └── openapi.yaml           # OpenAPI接口文档
├── docker-compose.yml         # Docker编排配置
├── Cargo.toml                 # Workspace配置
├── .env.example               # 环境变量示例
└── rustfmt.toml               # Rust格式化配置
```

### 技术栈

#### 后端技术栈

| 组件 | 技术选型 | 版本 | 用途 |
|------|---------|------|------|
| Web 框架 | Actix-web | 4.5 | HTTP 服务 |
| 异步运行时 | tokio | 1.37 | 异步执行 |
| 数据库访问 | SQLx | 0.7 | PostgreSQL ORM |
| 缓存/队列 | Redis | 0.24 | 任务队列、缓存 |
| JWT 认证 | jsonwebtoken | 9 | 令牌生成验证 |
| HTTP 客户端 | reqwest | 0.12 | 扫描请求 |
| HTML 解析 | scraper | 0.18 | 响应解析 |
| 日志系统 | tracing | 0.1 | 结构化日志 |
| 监控指标 | prometheus | 0.13 | 性能监控 |
| 参数验证 | validator | 0.18 | 请求验证 |

#### 前端技术栈

| 组件 | 技术选型 | 版本 | 用途 |
|------|---------|------|------|
| 前端框架 | React | 18.2 | UI 框架 |
| 语言 | TypeScript | 5.3 | 类型安全 |
| 构建工具 | Vite | 5.0 | 快速构建 |
| UI 组件库 | Ant Design | 5.12 | 组件库 |
| 数据可视化 | Recharts | 2.10 | 图表展示 |
| 路由管理 | React Router | 6.21 | 页面路由 |
| HTTP 客户端 | Axios | 1.6 | API 调用 |
| 样式方案 | Tailwind CSS | 3.4 | 原子化样式 |
| 日期处理 | Dayjs | 1.11 | 日期格式化 |

## 环境要求

### 开发环境

| 依赖 | 最低版本 | 推荐版本 |
|------|---------|---------|
| Rust | 1.75 | 1.75+ |
| Node.js | 18.0 | 20.0+ |
| npm | 9.0 | 10.0+ |
| PostgreSQL | 15 | 16 |
| Redis | 6.0 | 7.0+ |

### 运行环境

| 依赖 | 版本 |
|------|------|
| PostgreSQL | 15+ |
| Redis | 6.0+ |
| Docker | 20.10+ |
| Docker Compose | 2.0+ |

### 硬件配置建议

| 环境 | CPU | 内存 | 存储 |
|------|-----|------|------|
| 开发环境 | 4核 | 8GB | 20GB |
| 测试环境 | 8核 | 16GB | 50GB |
| 生产环境 | 16核+ | 32GB+ | 100GB+ |

## 安装步骤

### 1. 克隆项目

```bash
git clone <repository-url>
cd VulScan
```

### 2. 环境配置

```bash
cp .env.example .env
# 编辑 .env 文件配置数据库连接、JWT密钥等
```

### 3. 启动依赖服务

```bash
docker-compose up -d postgres redis

等待服务启动完成：

```bash
# 检查 PostgreSQL 状态
docker-compose exec postgres pg_isready -U admin -d vulscan

# 检查 Redis 状态
docker-compose exec redis redis-cli ping
```

### 4. 运行数据库迁移

```bash
cd backend/db-migrations
cargo run
```

### 5. 启动后端服务

**方式一：使用 Docker Compose（推荐）**

```bash
docker-compose up -d web-api scanner-worker scheduler
```

**方式二：本地开发**

```bash
# 启动 Web API（终端1）
cd backend/web-api
cargo run

# 启动扫描引擎 Worker（终端2）
cd backend/scanner-engine
cargo run

# 启动任务调度器（终端3）
cd backend/task-scheduler
cargo run
```

### 6. 启动前端开发服务器

```bash
cd frontend
npm install
npm run dev
```

访问 http://localhost:5173 打开管理后台。

### Docker 一键部署

```bash
docker-compose up -d
```

这将启动完整的应用栈：

| 服务 | 端口 | 说明 |
|------|------|------|
| PostgreSQL | 5432 | 数据库 |
| Redis | 6379 | 缓存/队列 |
| Web API | 8080 | API 服务 |
| Prometheus | 9090 | 监控指标 |
| Grafana | 3000 | 可视化面板（默认账号 admin/admin） |

## 配置指南

### 环境变量配置

`.env` 文件包含以下配置项：

```bash
# 数据库配置
POSTGRES_URL=postgres://admin:password@localhost:5432/vulscan

# Redis配置
REDIS_URL=redis://localhost:6379/0
REDIS_POOL_SIZE=10

# JWT配置
JWT_SECRET=your-256-bit-secret-key-here-change-in-production
JWT_EXPIRE_MINUTES=15
JWT_REFRESH_EXPIRE_DAYS=7

# API服务配置
API_HOST=0.0.0.0
API_PORT=8080

# CORS配置
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization

# 扫描引擎配置
SCAN_ENGINE_CONCURRENT_TARGETS=50
SCAN_ENGINE_REQUESTS_PER_SECOND=10.0
SCAN_ENGINE_CONNECT_TIMEOUT_SECS=5
SCAN_ENGINE_READ_TIMEOUT_SECS=10
SCAN_ENGINE_MAX_RETRIES=3
SCAN_ENGINE_RETRY_DELAY_MS=1000

# Worker配置
WORKER_COUNT=4
WORKER_QUEUE_SIZE=1000

# 日志配置
RUST_LOG=info
RUST_LOG_FORMAT=json

# 监控配置
METRICS_ENABLED=true
METRICS_PORT=9091

# 规则配置
RULES_DIRECTORY=./rules
RULES_HOT_RELOAD=true
```

### 配置项说明

| 配置项 | 说明 | 默认值 |
|--------|------|-------|
| `JWT_SECRET` | JWT 签名密钥，生产环境务必更换 | - |
| `JWT_EXPIRE_MINUTES` | 访问令牌过期时间（分钟） | 15 |
| `JWT_REFRESH_EXPIRE_DAYS` | 刷新令牌过期时间（天） | 7 |
| `SCAN_ENGINE_CONCURRENT_TARGETS` | 并发扫描目标数 | 50 |
| `SCAN_ENGINE_REQUESTS_PER_SECOND` | 单目标每秒请求数 | 10.0 |
| `SCAN_ENGINE_CONNECT_TIMEOUT_SECS` | 连接超时时间（秒） | 5 |
| `SCAN_ENGINE_READ_TIMEOUT_SECS` | 读取超时时间（秒） | 10 |
| `WORKER_COUNT` | Worker 进程数 | 4 |
| `RULES_DIRECTORY` | 规则文件目录 | ./rules |
| `RULES_HOT_RELOAD` | 是否启用规则热加载 | true |

### 规则配置

规则文件支持 YAML 和 JSON 格式，放置在 `RULES_DIRECTORY` 指定的目录下。

**YAML 示例**：

```yaml
rules:
  - id: sql-injection-001
    name: SQL注入检测规则
    detector: sql_injection
    severity: critical
    enabled: true
    priority: 10
    payloads:
      - "' OR '1'='1"
      - "' OR 1=1--"
    patterns:
      - "(?i)syntax.*error"
      - "(?i)sql.*error"
    description: 检测基于错误的SQL注入漏洞
    remediation: 使用参数化查询或预编译语句
    cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

detector_configs:
  sql_injection:
    enabled: true
    max_requests: 100
    timeout_ms: 5000
    custom_settings:
      time_threshold_ms: 4000
```

**JSON 示例**：

```json
{
  "rules": [
    {
      "id": "xss-001",
      "name": "XSS检测规则",
      "detector": "xss",
      "severity": "high",
      "enabled": true,
      "priority": 20,
      "payloads": ["<script>alert(1)</script>"],
      "patterns": [],
      "description": "检测反射型XSS漏洞",
      "remediation": "对用户输入进行HTML实体编码处理",
      "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    }
  ],
  "detector_configs": {}
}
```

## 使用示例

### 命令行操作

#### 启动扫描引擎

```bash
cd backend/scanner-engine
cargo run -- --target https://example.com --detectors sql_injection,xss
```

#### 运行测试

```bash
# 运行所有测试
cargo test --workspace

# 运行扫描引擎测试
cargo test -p scanner-engine

# 运行前端构建检查
cd frontend
npm run build
```

#### 性能基准测试

```bash
cd backend/scanner-engine
cargo bench
```

### API 调用示例

#### 1. 用户登录

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}'
```

**响应**：

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "1",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

#### 2. 创建扫描目标

```bash
curl -X POST http://localhost:8080/api/targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "name": "Example Website",
    "url": "https://example.com",
    "description": "Main website",
    "scan_frequency": "daily"
  }'
```

#### 3. 创建扫描任务

```bash
curl -X POST http://localhost:8080/api/scan-tasks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "target_id": "<target_id>",
    "scan_type": "full",
    "priority": "high",
    "concurrency": 20,
    "plugins": ["sql_injection", "xss", "sensitive_file"]
  }'
```

#### 4. 查询漏洞列表

```bash
curl -X GET "http://localhost:8080/api/vulnerabilities?page=1&page_size=20&severity=critical" \
  -H "Authorization: Bearer <access_token>"
```

#### 5. 导出漏洞报告

```bash
curl -X POST http://localhost:8080/api/vulnerabilities/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"format": "json"}'
```

### 界面操作示例

#### 登录系统

1. 打开 http://localhost:5173
2. 输入邮箱和密码
3. 点击登录按钮

#### 创建扫描任务

1. 登录后进入仪表盘
2. 点击左侧菜单"扫描任务"
3. 点击"创建任务"按钮
4. 填写任务信息：选择目标、扫描类型、优先级
5. 点击"提交"按钮

#### 查看扫描结果

1. 在扫描任务列表中找到目标任务
2. 点击任务名称进入详情页
3. 查看实时扫描进度和发现的漏洞

## API 文档

### 认证接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 用户登录 |
| POST | `/api/auth/register` | 用户注册 |
| POST | `/api/auth/refresh` | 刷新令牌 |
| POST | `/api/auth/logout` | 用户登出 |
| GET | `/api/auth/me` | 获取当前用户信息 |

#### POST /api/auth/login

**请求体**：

```json
{
  "email": "string (必填，邮箱地址)",
  "password": "string (必填，密码)"
}
```

**成功响应**（200 OK）：

```json
{
  "access_token": "string (JWT访问令牌)",
  "refresh_token": "string (JWT刷新令牌)",
  "token_type": "string (Bearer)",
  "expires_in": "number (令牌过期时间，秒)",
  "user": {
    "id": "string",
    "username": "string",
    "email": "string",
    "role": "string (admin/user/scanner)",
    "is_active": "boolean",
    "created_at": "string (ISO8601时间戳)"
  }
}
```

**错误响应**（401 Unauthorized）：

```json
{
  "error": "AuthError",
  "message": "Invalid credentials",
  "code": 401,
  "timestamp": "string"
}
```

### 目标管理接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/targets` | 获取目标列表 |
| GET | `/api/targets/{id}` | 获取单个目标 |
| POST | `/api/targets` | 创建目标 |
| POST | `/api/targets/batch` | 批量创建目标 |
| PUT | `/api/targets/{id}` | 更新目标 |
| DELETE | `/api/targets/{id}` | 删除目标 |

#### POST /api/targets

**请求体**：

```json
{
  "name": "string (必填，目标名称)",
  "url": "string (必填，目标URL)",
  "description": "string (可选，描述)",
  "scan_frequency": "string (可选，扫描频率：daily/weekly/monthly)"
}
```

**成功响应**（201 Created）：

```json
{
  "id": "string",
  "name": "string",
  "url": "string",
  "description": "string | null",
  "status": "string (active/inactive/scanning)",
  "scan_frequency": "string | null",
  "last_scan_at": "string | null",
  "created_at": "string",
  "updated_at": "string"
}
```

### 扫描任务接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/scan-tasks` | 获取任务列表 |
| GET | `/api/scan-tasks/{id}` | 获取单个任务 |
| POST | `/api/scan-tasks` | 创建扫描任务 |
| PUT | `/api/scan-tasks/{id}` | 更新任务 |
| PUT | `/api/scan-tasks/{id}/pause` | 暂停任务 |
| PUT | `/api/scan-tasks/{id}/resume` | 恢复任务 |
| PUT | `/api/scan-tasks/{id}/cancel` | 取消任务 |
| DELETE | `/api/scan-tasks/{id}` | 删除任务 |

#### POST /api/scan-tasks

**请求体**：

```json
{
  "target_id": "string (必填，目标ID)",
  "scan_type": "string (可选，full/quick/custom，默认full)",
  "priority": "string (可选，low/medium/high/critical，默认medium)",
  "concurrency": "number (可选，并发数，默认50)",
  "plugins": "string[] (可选，检测器列表)"
}
```

### 漏洞管理接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/vulnerabilities` | 获取漏洞列表 |
| GET | `/api/vulnerabilities/{id}` | 获取单个漏洞 |
| PUT | `/api/vulnerabilities/{id}/status` | 更新漏洞状态 |
| DELETE | `/api/vulnerabilities/{id}` | 删除漏洞 |
| POST | `/api/vulnerabilities/export` | 导出漏洞 |

#### GET /api/vulnerabilities

**查询参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| page | number | 页码，默认1 |
| page_size | number | 每页数量，默认20 |
| severity | string | 严重级别过滤 |
| plugin_name | string | 检测器名称过滤 |
| task_id | string | 任务ID过滤 |
| target_id | string | 目标ID过滤 |

**成功响应**（200 OK）：

```json
{
  "data": [
    {
      "id": "string",
      "task_id": "string",
      "target_id": "string",
      "plugin_name": "string",
      "severity": "string (critical/high/medium/low/info)",
      "title": "string",
      "description": "string",
      "payload": "string | null",
      "proof": "string | null",
      "remediation": "string",
      "cve": "string | null",
      "cvss_score": "number | null",
      "status": "string (open/fixed/ignored/verified)",
      "created_at": "string"
    }
  ],
  "page": "number",
  "page_size": "number",
  "total": "number",
  "total_pages": "number"
}
```

### 报告接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/reports` | 获取报告列表 |
| GET | `/api/reports/{id}` | 获取单个报告 |
| POST | `/api/reports` | 创建报告 |
| PUT | `/api/reports/{id}` | 更新报告 |
| DELETE | `/api/reports/{id}` | 删除报告 |
| GET | `/api/reports/{id}/download` | 下载报告 |

### 仪表盘接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/dashboard/stats` | 获取仪表盘统计数据 |

### 错误码说明

| 错误码 | 错误类型 | 说明 |
|--------|---------|------|
| 400 | ValidationError | 请求参数验证失败 |
| 401 | AuthError | 认证失败 |
| 403 | PermissionError | 权限不足 |
| 404 | NotFoundError | 资源不存在 |
| 409 | ConflictError | 资源冲突 |
| 500 | Unknown | 服务器内部错误 |

## 贡献指南

### 代码提交规范

提交信息采用 Conventional Commits 格式：

```
<type>(<scope>): <description>

<body>

<footer>
```

**Type 说明**：

| Type | 说明 |
|------|------|
| feat | 新功能 |
| fix | 修复 Bug |
| docs | 文档更新 |
| style | 代码格式 |
| refactor | 代码重构 |
| test | 测试 |
| chore | 构建/工具 |

**示例**：

```
feat(scanner): 添加时间盲注检测支持

- 实现基于时间延迟的SQL注入检测
- 添加时间阈值配置参数
- 集成误报过滤机制

Closes #123
```

### 分支管理策略

- `main`：主分支，稳定版本
- `develop`：开发分支，合并所有功能
- `feature/<name>`：功能分支，开发新功能
- `bugfix/<name>`：修复分支，修复 Bug
- `hotfix/<name>`：热修复分支，紧急修复

### Pull Request 流程

1. Fork 本仓库
2. 创建特性分支（`feature/amazing-feature`）
3. 提交更改
4. 推送分支到远程
5. 创建 Pull Request
6. 等待代码审查
7. 通过审查后合并到 develop 分支

### 代码审查标准

1. **代码质量**：代码清晰、简洁、符合 Rust/TypeScript 最佳实践
2. **类型安全**：TypeScript 类型定义完整准确
3. **测试覆盖**：新增功能必须包含单元测试
4. **文档更新**：相关文档必须同步更新
5. **性能考虑**：避免性能瓶颈和内存泄漏
6. **安全规范**：遵循安全编码最佳实践

### 开发环境配置

```bash
# 安装 Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装 clippy 和 rustfmt
rustup component add clippy rustfmt

# 安装 Node.js
# 请从 https://nodejs.org/ 下载安装

# 安装前端依赖
cd frontend
npm install
```

## 许可证信息

### MIT License

```
MIT License

Copyright (c) 2024 VulScan Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 免责声明

本工具仅用于授权的安全测试和研究目的。使用本工具进行未经授权的扫描可能违反法律法规。用户应对其使用行为承担全部责任。

---

**项目维护者**：Security Team  
**联系方式**：security@example.com  
**项目状态**：活跃开发中
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use tokio::runtime::Runtime;

use scanner_engine::{
    ScannerEngine, TargetManager, DefaultTargetValidator, DynamicRateLimiter,
    SqlInjectionDetector, XssDetector, SensitiveFileDetector,
};
use scanner_engine::target::{Target, TargetType};
use scanner_engine::traits::Detector;

/// 创建测试用的目标列表
fn create_targets(count: usize) -> Vec<Target> {
    (0..count)
        .map(|i| {
            let url = format!("http://127.0.0.1:{}/test", 8000 + (i % 100));
            Target::new(TargetType::Url(url.parse().unwrap()))
                .mark_authorized()
        })
        .collect()
}

/// 创建带模拟检测器的扫描引擎
fn create_engine(target_count: usize) -> ScannerEngine {
    let client = Arc::new(reqwest::Client::new());
    let validator = Arc::new(DefaultTargetValidator::new(client.clone()));
    let target_manager = Arc::new(TargetManager::new(validator, client.clone()));

    // 添加目标
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        for target in create_targets(target_count) {
            let mut targets = target_manager.list_targets().await;
            // 直接通过内部接口添加目标以绕过验证
            // 实际测试中我们使用预加载目标的方式
        }
    });

    let detectors: Vec<Arc<dyn Detector + 'static>> = vec![
        // 使用轻量级检测器进行基准测试
        // 实际 HTTP 请求在基准测试中会被 mock 或跳过
    ];

    ScannerEngine::new(
        target_manager,
        detectors,
        50,    // concurrent targets
        10.0,  // requests per second
    )
}

/// 基准测试：速率限制器性能
fn bench_rate_limiter(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("rate_limiter");

    for size in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("acquire", size),
            size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    let limiter = DynamicRateLimiter::new(10.0, 1.0, 10.0);
                    for i in 0..size {
                        let _ = limiter.acquire(&format!("target-{}", i % 10)).await;
                    }
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：令牌桶动态调整性能
fn bench_dynamic_rate_adjustment(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("dynamic_rate_success_record", |b| {
        b.to_async(&rt).iter(|| async {
            let limiter = DynamicRateLimiter::new(10.0, 1.0, 10.0);
            for _ in 0..100 {
                limiter.record_success("test-target").await;
            }
        });
    });

    c.bench_function("dynamic_rate_failure_record", |b| {
        b.to_async(&rt).iter(|| async {
            let limiter = DynamicRateLimiter::new(10.0, 1.0, 10.0);
            for _ in 0..100 {
                limiter.record_failure("test-target").await;
            }
        });
    });
}

/// 基准测试：误报过滤性能
fn bench_false_positive_filter(c: &mut Criterion) {
    use scanner_engine::detectors::FalsePositiveFilter;

    let rt = Runtime::new().unwrap();

    c.bench_function("false_positive_validation", |b| {
        b.to_async(&rt).iter(|| async {
            let filter = FalsePositiveFilter::new();
            filter.record_baseline("target-1", "normal response body").await;

            for i in 0..50 {
                let _ = filter.validate_vulnerability(
                    "target-1",
                    "sql_injection",
                    "SQL Error",
                    &format!("' OR {}=1", i),
                    "syntax error near",
                ).await;
            }
        });
    });
}

/// 基准测试：技术指纹识别性能
fn bench_tech_fingerprint(c: &mut Criterion) {
    use scanner_engine::detectors::TechFingerprint;

    let response_body = r#"
        <html>
        <head><title>Test</title></head>
        <body>
            <div class="wp-content">WordPress Site</div>
            <script src="/wp-includes/js/jquery/jquery.js"></script>
        </body>
        </html>
    "#;

    c.bench_function("tech_fingerprint_parsing", |b| {
        b.iter(|| {
            let body = response_body.to_string();
            let body_lower = body.to_lowercase();
            let mut fingerprint = TechFingerprint::default();

            if body_lower.contains("wp-content") || body_lower.contains("wordpress") {
                fingerprint.cms = Some("WordPress".to_string());
                fingerprint.detected_technologies.push("WordPress".to_string());
            }
            if body_lower.contains("jquery") {
                fingerprint.detected_technologies.push("jQuery".to_string());
            }
            if body_lower.contains("react") {
                fingerprint.framework = Some("React".to_string());
                fingerprint.detected_technologies.push("React".to_string());
            }

            fingerprint
        });
    });
}

/// 基准测试：扫描引擎整体性能（小目标集 vs 大目标集）
fn bench_engine_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("engine_scan");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for target_count in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*target_count as u64));
        group.bench_with_input(
            BenchmarkId::new("targets", target_count),
            target_count,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    let client = Arc::new(reqwest::Client::new());
                    let validator = Arc::new(DefaultTargetValidator::new(client.clone()));
                    let target_manager = Arc::new(TargetManager::new(validator, client.clone()));

                    // 添加目标到 target_manager
                    for i in 0..count {
                        let url = format!("http://127.0.0.1:{}/", 9000 + (i % 100));
                        let _ = target_manager.add_target(&url).await;
                    }

                    // 标记所有目标为已授权
                    let _ = target_manager.validate_all().await;

                    let engine = ScannerEngine::new(
                        target_manager,
                        vec![], // 无检测器，纯测调度性能
                        50,
                        10.0,
                    );

                    // 注意：这里我们不实际运行 scan，因为会涉及网络超时
                    // 而是测量目标管理和引擎创建的性能
                    // 实际扫描基准测试需要 mock 网络层
                    engine
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：内存使用模式（通过大量目标创建测量）
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");

    for size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("target_creation", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let targets: Vec<Target> = (0..size)
                        .map(|i| {
                            Target::new(TargetType::Url(
                                format!("http://example{}", i).parse().unwrap()
                            ))
                            .mark_authorized()
                        })
                        .collect();
                    targets
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_rate_limiter,
    bench_dynamic_rate_adjustment,
    bench_false_positive_filter,
    bench_tech_fingerprint,
    bench_engine_scan,
    bench_memory_patterns
);
criterion_main!(benches);

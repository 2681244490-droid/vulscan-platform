use crate::plugins::sql_injection_scanner::SqlInjectionScanner;
use crate::traits::ScanPlugin;

#[test]
fn test_sql_injection_scanner_name() {
    let scanner = SqlInjectionScanner;
    assert_eq!(scanner.name(), "sql_injection_scanner");
}

#[test]
fn test_sql_injection_scanner_description() {
    let scanner = SqlInjectionScanner;
    assert!(scanner.description().contains("SQL injection"));
}

#[test]
fn test_sql_injection_scanner_severity() {
    let scanner = SqlInjectionScanner;
    assert_eq!(scanner.severity(), "critical");
}

#[test]
fn test_sql_injection_scanner_has_payloads() {
    let scanner = SqlInjectionScanner;
    let payloads = scanner.payloads();
    assert!(!payloads.is_empty());
    assert!(payloads.contains(&"' OR '1'='1".to_string()));
}

#[test]
fn test_sql_injection_scanner_check_error_based() {
    let scanner = SqlInjectionScanner;
    let response = "You have an error in your SQL syntax";
    assert!(scanner.check("test' OR '1'='1", response));
}

#[test]
fn test_sql_injection_scanner_check_true_condition() {
    let scanner = SqlInjectionScanner;
    let response = "Welcome admin";
    assert!(scanner.check("test' OR '1'='1", response));
}

#[test]
fn test_sql_injection_scanner_no_false_positive() {
    let scanner = SqlInjectionScanner;
    assert!(!scanner.check("Hello World", "Hello World"));
}

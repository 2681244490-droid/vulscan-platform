use crate::plugins::weak_password_scanner::WeakPasswordScanner;
use crate::traits::ScanPlugin;

#[test]
fn test_weak_password_scanner_name() {
    let scanner = WeakPasswordScanner;
    assert_eq!(scanner.name(), "weak_password_scanner");
}

#[test]
fn test_weak_password_scanner_description() {
    let scanner = WeakPasswordScanner;
    assert!(scanner.description().contains("weak password"));
}

#[test]
fn test_weak_password_scanner_severity() {
    let scanner = WeakPasswordScanner;
    assert_eq!(scanner.severity(), "high");
}

#[test]
fn test_weak_password_scanner_has_payloads() {
    let scanner = WeakPasswordScanner;
    let payloads = scanner.payloads();
    assert!(!payloads.is_empty());
    assert!(payloads.contains(&"admin:admin".to_string()));
    assert!(payloads.contains(&"admin:password".to_string()));
}

#[test]
fn test_weak_password_scanner_check_success() {
    let scanner = WeakPasswordScanner;
    assert!(scanner.check("admin:admin", "Login successful"));
}

#[test]
fn test_weak_password_scanner_check_redirect() {
    let scanner = WeakPasswordScanner;
    assert!(scanner.check("admin:password", "Location: /dashboard"));
}

#[test]
fn test_weak_password_scanner_no_false_positive() {
    let scanner = WeakPasswordScanner;
    assert!(!scanner.check("admin:wrongpass", "Invalid credentials"));
}

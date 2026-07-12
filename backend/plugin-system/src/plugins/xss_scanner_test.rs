use crate::plugins::xss_scanner::XssScanner;
use crate::traits::ScanPlugin;

#[test]
fn test_xss_scanner_name() {
    let scanner = XssScanner;
    assert_eq!(scanner.name(), "xss_scanner");
}

#[test]
fn test_xss_scanner_description() {
    let scanner = XssScanner;
    assert!(scanner.description().contains("XSS"));
}

#[test]
fn test_xss_scanner_severity() {
    let scanner = XssScanner;
    assert_eq!(scanner.severity(), "high");
}

#[test]
fn test_xss_scanner_has_payloads() {
    let scanner = XssScanner;
    let payloads = scanner.payloads();
    assert!(!payloads.is_empty());
    assert!(payloads.contains(&"<script>alert('xss')</script>".to_string()));
}

#[test]
fn test_xss_scanner_has_check_function() {
    let scanner = XssScanner;
    assert!(scanner.check("<script>alert('xss')</script>", "<script>alert('xss')</script>"));
}

#[test]
fn test_xss_scanner_no_false_positive() {
    let scanner = XssScanner;
    assert!(!scanner.check("Hello World", "Hello World"));
}

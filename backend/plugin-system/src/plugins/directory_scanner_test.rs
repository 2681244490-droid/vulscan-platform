use crate::plugins::directory_scanner::DirectoryScanner;
use crate::traits::ScanPlugin;

#[test]
fn test_directory_scanner_name() {
    let scanner = DirectoryScanner;
    assert_eq!(scanner.name(), "directory_scanner");
}

#[test]
fn test_directory_scanner_description() {
    let scanner = DirectoryScanner;
    assert!(scanner.description().contains("sensitive directory"));
}

#[test]
fn test_directory_scanner_severity() {
    let scanner = DirectoryScanner;
    assert_eq!(scanner.severity(), "medium");
}

#[test]
fn test_directory_scanner_has_paths() {
    let scanner = DirectoryScanner;
    let paths = scanner.payloads();
    assert!(!paths.is_empty());
    assert!(paths.contains(&"/admin".to_string()));
    assert!(paths.contains(&"/backup".to_string()));
}

#[test]
fn test_directory_scanner_check_200() {
    let scanner = DirectoryScanner;
    assert!(scanner.check("/admin", "HTTP/1.1 200 OK"));
}

#[test]
fn test_directory_scanner_check_403() {
    let scanner = DirectoryScanner;
    assert!(scanner.check("/admin", "HTTP/1.1 403 Forbidden"));
}

#[test]
fn test_directory_scanner_no_false_positive() {
    let scanner = DirectoryScanner;
    assert!(!scanner.check("/nonexistent", "HTTP/1.1 404 Not Found"));
}

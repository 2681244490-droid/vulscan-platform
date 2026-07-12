pub mod xss_scanner;
pub mod sql_injection_scanner;
pub mod directory_scanner;
pub mod weak_password_scanner;

pub use xss_scanner::XssScanner;
pub use sql_injection_scanner::SqlInjectionScanner;
pub use directory_scanner::DirectoryScanner;
pub use weak_password_scanner::WeakPasswordScanner;

use crate::registry::PluginRegistry;

pub fn register_builtin_plugins(registry: &PluginRegistry) {
    registry.register(Box::new(XssScanner::new()));
    registry.register(Box::new(SqlInjectionScanner::new()));
    registry.register(Box::new(DirectoryScanner::new()));
    registry.register(Box::new(WeakPasswordScanner::new()));
}

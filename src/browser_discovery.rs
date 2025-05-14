use log::warn;
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use winreg::{RegKey, enums::*};

/// Helper function to extract executable path from a command string
pub fn extract_executable_path_from_command(command: String) -> Option<String> {
    let trimmed_command = command.trim();
    if let Some(stripped) = trimmed_command.strip_prefix('"') {
        if let Some(end_quote_index) = stripped.find('"') {
            let path = &stripped[..end_quote_index];
            Some(path.to_string())
        } else {
            None
        }
    } else {
        trimmed_command
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
    }
}

/// Helper function to check if a path likely points to a browser executable
fn is_browser_executable(path: &str) -> bool {
    let lower_path = path.to_lowercase();
    lower_path.contains("chrome.exe")
        || lower_path.contains("firefox.exe")
        || lower_path.contains("msedge.exe")
        || lower_path.contains("brave.exe")
        || lower_path.contains("opera.exe")
        || lower_path.contains("vivaldi.exe")
        || lower_path.contains("thorium.exe")
        || lower_path.contains("librewolf.exe")
        || lower_path.contains("waterfox.exe")
        || lower_path.contains("floorp.exe")
}

/// Gets a displayable browser name from its path
pub fn get_browser_name_from_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Generate possible Windows paths for browser executables
fn generate_common_browser_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Standard installation locations
    let prefixes = vec![
        env::var("PROGRAMFILES").unwrap_or_default(),
        env::var("PROGRAMFILES(X86)").unwrap_or_default(),
        env::var("LOCALAPPDATA").unwrap_or_default(),
    ];

    // Common browser paths
    let browser_paths = [
        "Google\\Chrome\\Application\\chrome.exe",
        "Mozilla Firefox\\firefox.exe",
        "Microsoft\\Edge\\Application\\msedge.exe",
        "BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        "Opera\\launcher.exe",
        "Opera\\opera.exe",
        "Vivaldi\\Application\\vivaldi.exe",
        "LibreWolf\\librewolf.exe",
        "Waterfox\\waterfox.exe",
        "Thorium\\Application\\thorium.exe",
        "Ablaze Floorp\\floorp.exe",
    ];

    for prefix in prefixes {
        if !prefix.is_empty() {
            for &browser_path in &browser_paths {
                let mut full_path = PathBuf::from(&prefix);
                full_path.push(browser_path);
                paths.push(full_path);
            }
        }
    }

    // Scoop installations
    if let Ok(user_profile) = env::var("USERPROFILE") {
        paths.push(PathBuf::from(format!(
            "{}\\scoop\\apps\\googlechrome\\current\\chrome.exe",
            user_profile
        )));
        paths.push(PathBuf::from(format!(
            "{}\\scoop\\apps\\firefox\\current\\firefox.exe",
            user_profile
        )));
        paths.push(PathBuf::from(format!(
            "{}\\scoop\\apps\\brave\\current\\brave.exe",
            user_profile
        )));
        paths.push(PathBuf::from(format!(
            "{}\\scoop\\apps\\opera\\current\\opera.exe",
            user_profile
        )));
        paths.push(PathBuf::from(format!(
            "{}\\scoop\\apps\\vivaldi\\current\\vivaldi.exe",
            user_profile
        )));
    }

    paths
}

/// Finds installed browsers by querying the registry and checking common paths
pub fn find_browsers() -> Vec<String> {
    let mut browsers = HashSet::new();

    // Check common installation paths first
    for path in generate_common_browser_paths() {
        if path.exists() {
            if let Some(path_str) = path.to_str() {
                browsers.insert(path_str.to_string());
            }
        }
    }

    // Check registry
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let registry_paths = [
        (&hklm, "SOFTWARE\\Clients\\StartMenuInternet"),
        (
            &hklm,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
        ),
        (&hkcu, "SOFTWARE\\Clients\\StartMenuInternet"),
        (
            &hkcu,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
        ),
    ];

    for (hive, path) in &registry_paths {
        match hive.open_subkey(path) {
            Ok(base_key) => {
                for entry_result in base_key.enum_keys() {
                    match entry_result {
                        Ok(entry) => {
                            match base_key.open_subkey(&entry) {
                                Ok(entry_key) => {
                                    // Check for shell/open/command
                                    if let Ok(command_key) =
                                        entry_key.open_subkey("shell\\open\\command")
                                    {
                                        if let Ok(command_string) =
                                            command_key.get_value::<String, _>("")
                                        {
                                            if let Some(executable_path) =
                                                extract_executable_path_from_command(command_string)
                                            {
                                                if !executable_path.is_empty()
                                                    && is_browser_executable(&executable_path)
                                                {
                                                    browsers.insert(executable_path);
                                                }
                                            }
                                        }
                                    }

                                    // Check direct value
                                    if let Ok(command_string) = entry_key.get_value::<String, _>("")
                                    {
                                        if let Some(executable_path) =
                                            extract_executable_path_from_command(command_string)
                                        {
                                            if !executable_path.is_empty()
                                                && is_browser_executable(&executable_path)
                                            {
                                                browsers.insert(executable_path);
                                            }
                                        }
                                    }
                                }
                                Err(e) => warn!("Failed to open registry entry '{}': {}", entry, e),
                            }
                        }
                        Err(e) => warn!("Failed to enumerate registry entry: {}", e),
                    }
                }
            }
            Err(e) => warn!("Failed to open registry path '{}': {}", path, e),
        }
    }

    browsers.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_executable_path_from_command() {
        assert_eq!(
            extract_executable_path_from_command(
                r#""C:\Program Files\Browser\browser.exe""#.to_string()
            ),
            Some(r#"C:\Program Files\Browser\browser.exe"#.to_string())
        );
        assert_eq!(
            extract_executable_path_from_command(
                "\"C:\\Program Files (x86)\\Other Browser\\other_browser.exe\" %1".to_string()
            ),
            Some("C:\\Program Files (x86)\\Other Browser\\other_browser.exe".to_string())
        );
        assert_eq!(
            extract_executable_path_from_command("browser.exe --arg".to_string()),
            Some("browser.exe".to_string())
        );
        assert_eq!(
            extract_executable_path_from_command(
                "\"browser with spaces.exe\" %1 --profile default".to_string()
            ),
            Some("browser with spaces.exe".to_string())
        );
        assert_eq!(extract_executable_path_from_command("".to_string()), None);
        assert_eq!(
            extract_executable_path_from_command("   ".to_string()),
            None
        );
    }

    #[test]
    fn test_is_browser_executable() {
        assert!(is_browser_executable(
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        ));
        assert!(is_browser_executable(
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
        ));
        assert!(!is_browser_executable(
            "C:\\Program Files\\Browser\\browser.dll"
        ));
        assert!(!is_browser_executable(""));
        assert!(!is_browser_executable(
            "C:\\Program Files\\Browser\\browser.exe.txt"
        ));
    }

    #[test]
    fn test_get_browser_name_from_path() {
        assert_eq!(
            get_browser_name_from_path("C:\\Program Files\\Browser\\browser.exe"),
            "browser.exe".to_string()
        );
        assert_eq!(
            get_browser_name_from_path("/usr/bin/firefox"),
            "firefox".to_string()
        );
        assert_eq!(get_browser_name_from_path(""), "".to_string());
        assert_eq!(
            get_browser_name_from_path("C:\\not_a_browser.txt"),
            "not_a_browser.txt".to_string()
        );
    }
}

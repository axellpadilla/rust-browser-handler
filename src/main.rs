use clap::{Parser, Subcommand};
use log::{error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use winreg::RegKey;
use winreg::enums::*;

#[derive(Debug, Serialize, Deserialize)]
struct Rule {
    pattern: String,
    browser: String,
    is_regex: Option<bool>, // Optional field to indicate if the pattern is a regex
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    url: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add a new rule
    Add {
        pattern: String,
        browser: String,
        #[arg(long)]
        regex: bool,
    },
    /// List all rules
    List,
    /// Remove a rule by pattern
    Remove { pattern: String },
    /// Import rules from a file
    Import { path: String },
    /// Export rules to a file
    Export { path: String },
    /// Register the application as the default browser handler
    Register,
    /// Open Windows Default Apps settings
    OpenSettings,
}

fn print_help() {
    println!("Available commands:");
    println!("  add <pattern> [--regex]: Add a new rule with interactive browser selection");
    println!("  list: List all rules");
    println!("  remove <pattern>: Remove a rule by pattern");
    println!("  import <path>: Import rules from a file");
    println!("  export <path>: Export rules to a file");
    //println!("  register: Register as browser handler");
    println!("  open-settings: Open Windows Default Apps settings");
    println!("  exit: Exit interactive mode");
}

fn set_as_default_handler() -> io::Result<()> {
    warn!("set_as_default_handler is not implemented yet.");
    Err(io::Error::new(
        io::ErrorKind::Other,
        "set_as_default_handler is not implemented yet.",
    ))
}
fn extract_executable_path_from_command(command: String) -> Option<String> {
    let trimmed_command = command.trim();
    if let Some(stripped) = trimmed_command.strip_prefix('"') {
        // Find the closing quote
        if let Some(end_quote_index) = stripped.find('"') {
            let path = &stripped[..end_quote_index];
            Some(path.to_string())
        } else {
            // No closing quote found
            None
        }
    } else {
        // Split by the first whitespace for non-quoted paths
        trimmed_command
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
    }
}

fn is_browser_executable(path: &str) -> bool {
    let lower_path = path.to_lowercase();
    lower_path.contains("chrome.exe")
        || lower_path.contains("firefox.exe")
        || lower_path.contains("msedge.exe")
        || lower_path.contains("brave.exe")
        || lower_path.contains("opera.exe")
}

fn get_rules_file_path() -> io::Result<PathBuf> {
    let mut path = dirs::config_dir().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "Could not find config directory")
    })?;
    path.push("RustBrowserHandler");
    path.push("rules.json");
    Ok(path)
}

fn read_rules() -> io::Result<Vec<Rule>> {
    let path = get_rules_file_path()?;
    if !path.exists() {
        return Ok(Vec::new()); // Return empty vec if file doesn't exist
    }
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let rules = serde_json::from_reader(reader)?;
    Ok(rules)
}

fn write_rules(rules: &Vec<Rule>) -> io::Result<()> {
    let path = get_rules_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?; // Create directories if they don't exist
    }
    let file = std::fs::File::create(path)?;
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, rules)?;
    Ok(())
}

fn add_rule(pattern: String, browser: String, is_regex: bool) -> io::Result<()> {
    let mut rules = read_rules().unwrap_or_else(|_| Vec::new()); // Read existing rules or start with empty
    rules.push(Rule {
        pattern,
        browser,
        is_regex: Some(is_regex),
    });
    write_rules(&rules)?;
    Ok(())
}

fn list_rules() -> io::Result<()> {
    let rules = read_rules().unwrap_or_else(|_| Vec::new());
    if rules.is_empty() {
        println!("No rules defined.");
    } else {
        for (i, rule) in rules.iter().enumerate() {
            println!(
                "{}: Pattern: {}, Browser: {}, Is Regex: {}",
                i,
                rule.pattern,
                rule.browser,
                rule.is_regex.unwrap_or(false)
            );
        }
    }
    Ok(())
}

fn remove_rule(pattern: &str) -> io::Result<()> {
    let mut rules = read_rules().unwrap_or_else(|_| Vec::new());
    let initial_len = rules.len();
    rules.retain(|rule| rule.pattern != pattern);
    if rules.len() < initial_len {
        write_rules(&rules)?;
        println!("Rule with pattern '{}' removed.", pattern);
    } else {
        println!("No rule found with pattern '{}'.", pattern);
    }
    Ok(())
}

fn import_rules_from_file(path: &str) -> io::Result<()> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let rules: Vec<Rule> = serde_json::from_reader(reader)?;
    write_rules(&rules)?; // Write to the application's rules file
    println!("Rules imported successfully from '{}'.", path);
    Ok(())
}

fn export_rules_to_file(path: &str) -> io::Result<()> {
    let rules = read_rules().unwrap_or_else(|_| Vec::new()); // Read from the application's rules file
    let file = std::fs::File::create(path)?;
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &rules)?;
    println!("Rules exported successfully to '{}'.", path);
    Ok(())
}

fn get_browser_name_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| path.to_string()) // Fallback to full path if name extraction fails
}

fn find_browsers() -> Vec<String> {
    let mut browsers = Vec::new();
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
                                    // Check for command in shell\open\command (common for StartMenuInternet)
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
                                                    browsers.push(executable_path);
                                                }
                                            }
                                        }
                                    }
                                    // Check the default value of the key itself (common for App Paths)
                                    if let Ok(command_string) = entry_key.get_value::<String, _>("")
                                    {
                                        if let Some(executable_path) =
                                            extract_executable_path_from_command(command_string)
                                        {
                                            if !executable_path.is_empty()
                                                && is_browser_executable(&executable_path)
                                            {
                                                browsers.push(executable_path);
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

    // Remove duplicates and return
    browsers
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_executable_path_from_command() {
        // Test cases for extract_executable_path_from_command
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
}

#[cfg(test)]
mod rule_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_rules_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(file, "{}", content).expect("Failed to write to temp file");
        file
    }

    #[test]
    fn test_read_rules_empty() {
        let file = create_temp_rules_file("[]");
        let result = read_rules_from_path(file.path().to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_read_rules_with_data() {
        let content = r#"[
            { "pattern": "google.com", "browser": "chrome" },
            { "pattern": "firefox.com", "browser": "firefox", "is_regex": false }
        ]"#;
        let file = create_temp_rules_file(content);
        let result = read_rules_from_path(file.path().to_str().unwrap());
        assert!(result.is_ok());
        let rules = result.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pattern, "google.com");
        assert_eq!(rules[0].browser, "chrome");
        assert_eq!(rules[0].is_regex, None);
        assert_eq!(rules[1].pattern, "firefox.com");
        assert_eq!(rules[1].browser, "firefox");
        assert_eq!(rules[1].is_regex, Some(false));
    }

    #[test]
    fn test_write_rules() {
        let rules = vec![Rule {
            pattern: "test.com".to_string(),
            browser: "edge".to_string(),
            is_regex: Some(true),
        }];
        let file = NamedTempFile::new().expect("Failed to create temp file");
        let path = file.path().to_str().unwrap().to_string();
        drop(file); // Close the file so write_rules can open it

        let result = write_rules_to_path(&rules, &path);
        assert!(result.is_ok());

        let read_back_rules = read_rules_from_path(&path).expect("Failed to read back rules");
        assert_eq!(read_back_rules.len(), 1);
        assert_eq!(read_back_rules[0].pattern, "test.com");
        assert_eq!(read_back_rules[0].browser, "edge");
        assert_eq!(read_back_rules[0].is_regex, Some(true));
    }

    #[test]
    fn test_add_rule() {
        let file = create_temp_rules_file("[]");
        let path = file.path().to_str().unwrap().to_string();
        drop(file); // Close the file so add_rule can open it

        // Add a rule
        add_rule_to_path(
            &path,
            "example.com".to_string(),
            "chrome".to_string(),
            false,
        )
        .expect("Failed to add rule");

        // Read back and verify
        let rules = read_rules_from_path(&path).expect("Failed to read back rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "example.com");
        assert_eq!(rules[0].browser, "chrome");
        assert_eq!(rules[0].is_regex, Some(false));

        // Add another rule
        add_rule_to_path(&path, "regex.*".to_string(), "firefox".to_string(), true)
            .expect("Failed to add rule");

        // Read back and verify
        let rules = read_rules_from_path(&path).expect("Failed to read back rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].pattern, "regex.*");
        assert_eq!(rules[1].browser, "firefox");
        assert_eq!(rules[1].is_regex, Some(true));
    }

    #[test]
    fn test_remove_rule() {
        let content = r#"[
            { "pattern": "google.com", "browser": "chrome" },
            { "pattern": "firefox.com", "browser": "firefox" }
        ]"#;
        let file = create_temp_rules_file(content);
        let path = file.path().to_str().unwrap().to_string();
        // drop(file); // Close the file so remove_rule can open it - Removed to keep file alive

        // Remove a rule
        remove_rule_from_path(&path, "google.com").expect("Failed to remove rule");

        // Read back and verify
        let rules = read_rules_from_path(&path).expect("Failed to read back rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "firefox.com");

        // Try to remove a non-existent rule
        remove_rule_from_path(&path, "nonexistent.com").expect("Failed to remove rule");

        // Read back and verify (should be unchanged)
        let rules = read_rules_from_path(&path).expect("Failed to read back rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "firefox.com");
    }

    // Helper functions to read/write/add/remove from a specific path for testing
    fn read_rules_from_path(path: &str) -> io::Result<Vec<Rule>> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let rules = serde_json::from_reader(reader)?;
        Ok(rules)
    }

    fn write_rules_to_path(rules: &Vec<Rule>, path: &str) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, rules)?;
        Ok(())
    }

    fn add_rule_to_path(
        path: &str,
        pattern: String,
        browser: String,
        is_regex: bool,
    ) -> io::Result<()> {
        let mut rules = read_rules_from_path(path).unwrap_or_else(|_| Vec::new());
        rules.push(Rule {
            pattern,
            browser,
            is_regex: Some(is_regex),
        });
        write_rules_to_path(&rules, path)?;
        Ok(())
    }

    fn remove_rule_from_path(path: &str, pattern: &str) -> io::Result<()> {
        let mut rules = read_rules_from_path(path).unwrap_or_else(|_| Vec::new());
        let initial_len = rules.len();
        rules.retain(|rule| rule.pattern != pattern);
        if rules.len() < initial_len {
            write_rules_to_path(&rules, path)?;
        }
        Ok(())
    }
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Add {
            pattern,
            browser,
            regex,
        }) => {
            info!(
                "Adding rule: pattern='{}', browser='{}', regex={}",
                pattern, browser, regex
            );
            match add_rule(pattern.clone(), browser.clone(), *regex) {
                Ok(_) => info!("Rule added successfully."),
                Err(e) => error!("Failed to add rule: {}", e),
            }
        }
        Some(Commands::List) => {
            info!("Listing rules:");
            match list_rules() {
                Ok(_) => {} // list_rules prints directly
                Err(e) => error!("Failed to list rules: {}", e),
            }
        }
        Some(Commands::Remove { pattern }) => {
            info!("Removing rule with pattern: '{}'", pattern);
            match remove_rule(pattern) {
                Ok(_) => {} // remove_rule prints directly
                Err(e) => error!("Failed to remove rule: {}", e),
            }
        }
        Some(Commands::Import { path }) => {
            info!("Importing rules from: {}", path);
            match import_rules_from_file(path) {
                Ok(_) => info!("Import successful."),
                Err(e) => error!("Failed to import rules: {}", e),
            }
        }
        Some(Commands::Export { path }) => {
            info!("Exporting rules to: {}", path);
            match export_rules_to_file(path) {
                Ok(_) => info!("Export successful."),
                Err(e) => error!("Failed to export rules: {}", e),
            }
        }
        Some(Commands::Register) => {
            info!("Registering as default browser handler...");
            println!("Registering as default browser handler...");
            match set_as_default_handler() {
                Ok(_) => {
                    info!("Successfully registered as default handler.");
                    println!("Successfully registered as default handler.");
                }
                Err(e) => {
                    error!("Failed to register as default handler: {}", e);
                    println!("Failed to register as default handler: {}", e);
                }
            }
        }
        Some(Commands::OpenSettings) => {
            info!("Opening Windows Default Apps settings...");
            println!("Please add this app as a default browser handler for HTTP and HTTP.");
            std::thread::sleep(std::time::Duration::from_secs(4));
            match Command::new("cmd")
                .args(["/C", "start ms-settings:defaultapps"])
                .spawn()
            {
                Ok(_) => info!("Windows Default Apps settings opened successfully."),
                Err(e) => error!("Failed to open Windows Default Apps settings: {}", e),
            }
        }
        None => {
            // No subcommand provided
            if let Some(url) = cli.url {
                // URL provided, handle URL interception
                info!("Intercepted URL: {}", url);

                let rules = match read_rules() {
                    Ok(rules) => rules,
                    Err(e) => {
                        error!("Failed to read rules: {}", e);
                        Vec::new() // Use empty rules if reading fails
                    }
                };
                info!("Loaded rules: {:?}", rules);

                let browsers = find_browsers();
                info!("Detected browsers: {:?}", browsers);

                let mut matched_browser_path: Option<String> = None;

                for rule in rules {
                    let is_regex = rule.is_regex.unwrap_or(false); // Default to false if is_regex is not present

                    if is_regex {
                        match Regex::new(&rule.pattern) {
                            Ok(re) => {
                                if re.is_match(&url) {
                                    // Find the browser executable path based on the rule's browser name
                                    matched_browser_path = browsers
                                        .iter()
                                        .find(|browser_path| {
                                            browser_path
                                                .to_lowercase()
                                                .contains(&rule.browser.to_lowercase())
                                        })
                                        .cloned();
                                    if matched_browser_path.is_some() {
                                        break; // Found a matching rule and browser
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Invalid regex pattern '{}': {}", rule.pattern, e);
                                // Continue to the next rule if regex compilation fails
                            }
                        }
                    } else {
                        // Substring matching
                        if url.contains(&rule.pattern) {
                            // Find the browser executable path based on the rule's browser name
                            matched_browser_path = browsers
                                .iter()
                                .find(|browser_path| {
                                    browser_path
                                        .to_lowercase()
                                        .contains(&rule.browser.to_lowercase())
                                })
                                .cloned();
                            if matched_browser_path.is_some() {
                                break; // Found a matching rule and browser
                            }
                        }
                    }
                }

                if let Some(browser_path) = matched_browser_path {
                    info!("Launching browser: {} with URL: {}", browser_path, url);
                    match Command::new(browser_path).arg(url).spawn() {
                        Ok(_) => info!("Browser launched successfully."),
                        Err(e) => error!("Failed to launch browser: {}", e),
                    }
                } else {
                    // No rule matched, present browser selection
                    warn!("No rule matched for URL: {}", url);
                    if browsers.is_empty() {
                        error!("No browsers detected to open the URL.");
                    } else {
                        info!("Detected browsers:");
                        for (i, browser_path) in browsers.iter().enumerate() {
                            let browser_name = get_browser_name_from_path(browser_path);
                            println!("{}: {}", i + 1, browser_name);
                        }

                        println!(
                            "Enter the number of the browser to use (e.g., '1'), or '1s' to save as a rule, or 'cancel':"
                        );
                        let mut selection = String::new();
                        io::stdout().flush().expect("Failed to flush stdout");
                        io::stdin()
                            .read_line(&mut selection)
                            .expect("Failed to read line");
                        let selection = selection.trim().to_lowercase();

                        if selection == "cancel" {
                            info!("Browser selection cancelled.");
                        } else {
                            let save_rule = selection.ends_with('s');
                            let selection_str = if save_rule {
                                &selection[..selection.len() - 1]
                            } else {
                                &selection
                            };

                            if let Ok(index) = selection_str.parse::<usize>() {
                                if index > 0 && index <= browsers.len() {
                                    let selected_browser_path = &browsers[index - 1];
                                    info!(
                                        "Launching selected browser: {} with URL: {}",
                                        selected_browser_path, url
                                    );
                                    match Command::new(selected_browser_path)
                                        .arg(url.clone())
                                        .spawn()
                                    {
                                        Ok(_) => {
                                            info!("Browser launched successfully.");

                                            if save_rule {
                                                if let Some(domain) = url::Url::parse(&url)
                                                    .ok()
                                                    .and_then(|u| u.domain().map(|d| d.to_string()))
                                                {
                                                    info!(
                                                        "Adding rule for domain: {} with browser: {}",
                                                        domain, selected_browser_path
                                                    );
                                                    match add_rule(
                                                        domain,
                                                        selected_browser_path.clone(),
                                                        false,
                                                    ) {
                                                        // Assuming domain matching is not regex by default
                                                        Ok(_) => info!("Rule added successfully."),
                                                        Err(e) => {
                                                            error!("Failed to add rule: {}", e)
                                                        }
                                                    }
                                                } else {
                                                    warn!(
                                                        "Could not extract domain from URL: {}",
                                                        url
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => error!("Failed to launch browser: {}", e),
                                    }
                                } else {
                                    warn!("Invalid selection number: {}", selection_str);
                                }
                            } else {
                                warn!("Invalid input format: {}", selection);
                            }
                        }
                    }
                }
            } else {
                // No URL provided and no subcommand, enter interactive mode
                println!("Entering interactive mode. Type 'help' for commands.");
                io::stdout().flush().expect("Failed to flush stdout"); // Explicit flush
                println!(); // Add a blank line
                std::thread::sleep(std::time::Duration::from_millis(100)); // Add a small delay
                let mut input = String::new();
                loop {
                    print!("> ");
                    io::stdout().flush().expect("Failed to flush stdout");
                    input.clear();
                    match io::stdin().read_line(&mut input) {
                        Ok(_) => {
                            let input = input.trim();
                            if input.is_empty() {
                                continue;
                            }
                            if input == "exit" {
                                break;
                            }
                            if input == "help" {
                                print_help();
                                continue;
                            }

                            let parts: Vec<&str> = input.split_whitespace().collect();
                            if parts.is_empty() {
                                continue;
                            }

                            match parts[0] {
                                "add" => {
                                    if parts.len() >= 2 {
                                        let pattern = parts[1].to_string();
                                        let is_regex = parts.iter().any(|&p| p == "--regex");

                                        let browsers = find_browsers();
                                        if browsers.is_empty() {
                                            error!("No browsers detected to add a rule.");
                                        } else {
                                            println!("Detected browsers:");
                                            for (i, browser_path) in browsers.iter().enumerate() {
                                                let browser_name =
                                                    get_browser_name_from_path(browser_path);
                                                println!("{}: {}", i + 1, browser_name);
                                            }

                                            println!("Enter the number of the browser to use:");
                                            let mut selection = String::new();
                                            io::stdout().flush().expect("Failed to flush stdout");
                                            io::stdin()
                                                .read_line(&mut selection)
                                                .expect("Failed to read line");
                                            let selection = selection.trim();

                                            if let Ok(index) = selection.parse::<usize>() {
                                                if index > 0 && index <= browsers.len() {
                                                    let selected_browser_path =
                                                        &browsers[index - 1];
                                                    match add_rule(
                                                        pattern,
                                                        selected_browser_path.clone(),
                                                        is_regex,
                                                    ) {
                                                        Ok(_) => info!("Rule added successfully."),
                                                        Err(e) => {
                                                            error!("Failed to add rule: {}", e)
                                                        }
                                                    }
                                                } else {
                                                    warn!(
                                                        "Invalid selection number: {}",
                                                        selection
                                                    );
                                                }
                                            } else {
                                                warn!("Invalid input format: {}", selection);
                                            }
                                        }
                                    } else {
                                        warn!("Usage: add <pattern> [--regex]");
                                    }
                                }
                                "list" => match list_rules() {
                                    Ok(_) => {}
                                    Err(e) => error!("Failed to list rules: {}", e),
                                },
                                "remove" => {
                                    if parts.len() >= 2 {
                                        let pattern = parts[1];
                                        match remove_rule(pattern) {
                                            Ok(_) => {}
                                            Err(e) => error!("Failed to remove rule: {}", e),
                                        }
                                    } else {
                                        warn!("Usage: remove <pattern>");
                                    }
                                }
                                "import" => {
                                    if parts.len() >= 2 {
                                        let path = parts[1];
                                        match import_rules_from_file(path) {
                                            Ok(_) => info!("Import successful."),
                                            Err(e) => error!("Failed to import rules: {}", e),
                                        }
                                    } else {
                                        warn!("Usage: import <path>");
                                    }
                                }
                                "export" => {
                                    if parts.len() >= 2 {
                                        let path = parts[1];
                                        match export_rules_to_file(path) {
                                            Ok(_) => info!("Export successful."),
                                            Err(e) => error!("Failed to export rules: {}", e),
                                        }
                                    } else {
                                        warn!("Usage: export <path>");
                                    }
                                }
                                "register" => {
                                    info!("Registering as browser handler...");
                                    match set_as_default_handler() {
                                        Ok(_) => {
                                            info!("Successfully registered as handler.")
                                        }
                                        Err(e) => {
                                            error!("Failed to register as handler: {}", e)
                                        }
                                    }
                                }
                                _ => {
                                    warn!("Unknown command. Type 'help' for commands.");
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to read input: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }
}

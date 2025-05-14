mod browser_discovery;
mod registry_handler;
mod rules;

use browser_discovery::*;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use regex::Regex;
use registry_handler::*;
use rules::*;
use std::io;
use std::io::Write;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    url: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
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
    /// Unregister the application as the default browser handler
    Unregister,
    /// Open Windows Default Apps settings
    OpenSettings,
}

fn print_help() {
    println!("Available commands:");
    println!("  add <pattern> <browser> [--regex]: Add a new rule");
    println!("  list: List all rules");
    println!("  remove <pattern>: Remove a rule by pattern");
    println!("  import <path>: Import rules from a file");
    println!("  export <path>: Export rules to a file");
    println!("  register: Register as browser handler");
    println!("  unregister: Unregister as browser handler");
    println!("  open-settings: Open Windows Default Apps settings");
    println!("  exit: Exit interactive mode");
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    // If no command/url, enter interactive mode to get a command
    if cli.command.is_none() && cli.url.is_none() {
        println!("Entering interactive mode. Type 'help' for commands.");
        io::stdout().flush().expect("Failed to flush stdout");
        println!();
        std::thread::sleep(std::time::Duration::from_millis(100));
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
                    // Try to parse the input into a Commands variant
                    match parse_interactive_command(input) {
                        Ok(command) => {
                            handle_command(Some(command), None);
                        }
                        Err(e) => {
                            warn!("{}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read input: {}", e);
                    break;
                }
            }
        }
    } else {
        // If CLI provided a command or URL, handle it directly
        handle_command(cli.command, cli.url);
    }
}

// Handles all commands, regardless of how they were obtained
fn handle_command(command: Option<Commands>, url: Option<String>) {
    match command {
        Some(Commands::Add {
            pattern,
            browser,
            regex,
        }) => {
            info!(
                "Adding rule: pattern='{}', browser='{}', regex={}",
                pattern, browser, regex
            );
            match add_rule(pattern, browser, regex) {
                Ok(_) => info!("Rule added successfully."),
                Err(e) => error!("Failed to add rule: {}", e),
            }
        }
        Some(Commands::List) => {
            info!("Listing rules:");
            match list_rules() {
                Ok(_) => {}
                Err(e) => error!("Failed to list rules: {}", e),
            }
        }
        Some(Commands::Remove { pattern }) => {
            info!("Removing rule with pattern: '{}'", pattern);
            match remove_rule(&pattern) {
                Ok(_) => {}
                Err(e) => error!("Failed to remove rule: {}", e),
            }
        }
        Some(Commands::Import { path }) => {
            info!("Importing rules from: {}", path);
            match import_rules_from_file(&path) {
                Ok(_) => info!("Import successful."),
                Err(e) => error!("Failed to import rules: {}", e),
            }
        }
        Some(Commands::Export { path }) => {
            info!("Exporting rules to: {}", path);
            match export_rules_to_file(&path) {
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
        Some(Commands::Unregister) => {
            info!("Unregistering as default browser handler...");
            match unregister_handler() {
                Ok(_) => {
                    info!("Successfully unregistered as default handler.");
                    println!("Successfully unregistered as default handler.");
                }
                Err(e) => {
                    error!("Failed to unregister as default handler: {}", e);
                    println!("Failed to unregister as default handler: {}", e);
                }
            }
        }
        Some(Commands::OpenSettings) => {
            info!("Opening Windows Default Apps settings...");
            println!("Please add this app as a default browser handler for HTTP and HTTP.");
            std::thread::sleep(std::time::Duration::from_secs(2));
            match Command::new("cmd")
                .args(["/C", "start ms-settings:defaultapps"])
                .spawn()
            {
                Ok(_) => info!("Windows Default Apps settings opened successfully."),
                Err(e) => error!("Failed to open Windows Default Apps settings: {}", e),
            }
        }
        None => {
            // No subcommand provided, but maybe a URL
            if let Some(url) = url {
                handle_url_open(url);
            }
        }
    }
}

// Handles opening a URL, including rule matching and browser selection
fn handle_url_open(url: String) {
    let rules = match read_rules() {
        Ok(rules) => rules,
        Err(e) => {
            error!("Failed to read rules: {}", e);
            Vec::new()
        }
    };
    info!("Loaded rules: {:?}", rules);

    let browsers = find_browsers();
    info!("Detected browsers: {:?}", browsers);

    let mut matched_browser_path: Option<String> = None;

    for rule in &rules {
        let is_regex = rule.is_regex.unwrap_or(false);

        if is_regex {
            match Regex::new(&rule.pattern) {
                Ok(re) => {
                    if re.is_match(&url) {
                        matched_browser_path = browsers
                            .iter()
                            .find(|browser_path| {
                                browser_path
                                    .to_lowercase()
                                    .contains(&rule.browser.to_lowercase())
                            })
                            .cloned();
                        if matched_browser_path.is_some() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", rule.pattern, e);
                }
            }
        } else if url.contains(&rule.pattern) {
            matched_browser_path = browsers
                .iter()
                .find(|browser_path| {
                    browser_path
                        .to_lowercase()
                        .contains(&rule.browser.to_lowercase())
                })
                .cloned();
            if matched_browser_path.is_some() {
                break;
            }
        }
    }

    if let Some(browser_path) = matched_browser_path {
        info!("Launching browser: {} with URL: {}", browser_path, url);
        match Command::new(browser_path).arg(&url).spawn() {
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
                        match Command::new(selected_browser_path).arg(url.clone()).spawn() {
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
                                        match add_rule(domain, selected_browser_path.clone(), false)
                                        {
                                            Ok(_) => info!("Rule added successfully."),
                                            Err(e) => {
                                                error!("Failed to add rule: {}", e)
                                            }
                                        }
                                    } else {
                                        warn!("Could not extract domain from URL: {}", url);
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
}

// Parses interactive input into a Commands variant
fn parse_interactive_command(input: &str) -> Result<Commands, &'static str> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Err("No command entered");
    }
    match parts[0] {
        "add" => {
            // Usage: add <pattern> <browser> [--regex]
            if parts.len() < 3 {
                return Err("Usage: add <pattern> <browser> [--regex]");
            }
            let pattern = parts[1].to_string();
            let browser = parts[2].to_string();
            let regex = parts.iter().any(|&p| p == "--regex");
            Ok(Commands::Add {
                pattern,
                browser,
                regex,
            })
        }
        "list" => Ok(Commands::List),
        "remove" => {
            if parts.len() < 2 {
                return Err("Usage: remove <pattern>");
            }
            Ok(Commands::Remove {
                pattern: parts[1].to_string(),
            })
        }
        "import" => {
            if parts.len() < 2 {
                return Err("Usage: import <path>");
            }
            Ok(Commands::Import {
                path: parts[1].to_string(),
            })
        }
        "export" => {
            if parts.len() < 2 {
                return Err("Usage: export <path>");
            }
            Ok(Commands::Export {
                path: parts[1].to_string(),
            })
        }
        "register" => Ok(Commands::Register),
        "unregister" => Ok(Commands::Unregister),
        "open-settings" => Ok(Commands::OpenSettings),
        _ => Err("Unknown command. Type 'help' for commands."),
    }
}

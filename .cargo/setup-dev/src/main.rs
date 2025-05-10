use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("🦀 Setting up development environment...");
    
    // 1. Set up Git commit template
    if let Err(e) = setup_commit_template() {
        eprintln!("❌ Failed to set up commit template: {}", e);
        std::process::exit(1);
    }
    
    // 2. Install pre-commit hook from repository
    if let Err(e) = install_precommit_hook() {
        eprintln!("❌ Failed to install pre-commit hook: {}", e);
        std::process::exit(1);
    }
    
    // 3. Install required development tools
    if let Err(e) = install_dev_tools() {
        eprintln!("❌ Failed to install development tools: {}", e);
        std::process::exit(1);
    }
    
    println!("✅ Development environment setup complete!");
    println!("🚀 You can now start developing with:");
    println!("   - cargo build        # Build the project");
    println!("   - cargo test         # Run tests");
    println!("   - cargo run          # Run the application");
    println!("   - cargo dev          # Auto-rebuild and run on file changes");
}

fn setup_commit_template() -> io::Result<()> {
    println!("📝 Setting up Git commit template...");
    
    let status = Command::new("git")
        .args(["config", "--local", "commit.template", ".github/commit-template.txt"])
        .status()?;
        
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other, 
            "Git command failed to set commit template"
        ));
    }
    
    println!("✅ Git commit template configured successfully!");
    Ok(())
}

fn install_precommit_hook() -> io::Result<()> {
    println!("🔍 Installing pre-commit hook...");
    
    // Ensure .git/hooks directory exists
    let hooks_dir = Path::new(".git/hooks");
    if !hooks_dir.exists() {
        fs::create_dir_all(hooks_dir)?;
    }
    
    // Copy the pre-commit hook from the repository to .git/hooks
    let source_path = Path::new(".github/hooks/pre-commit");
    let target_path = hooks_dir.join("pre-commit");
    
    fs::copy(source_path, &target_path)?;
    
    // Make the hook executable on Unix-like systems
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&target_path)?.permissions();
        perms.set_mode(0o755); // rwxr-xr-x
        fs::set_permissions(&target_path, perms)?;
    }
    
    println!("✅ Pre-commit hook installed successfully!");
    Ok(())
}

fn install_dev_tools() -> io::Result<()> {
    println!("🔧 Installing development tools...");
    
    // Install rustfmt and clippy
    let status = Command::new("rustup")
        .args(["component", "add", "rustfmt", "clippy"])
        .status()?;
        
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other, 
            "Failed to install rustfmt and clippy"
        ));
    }
    
    // Check if cargo-watch is installed, install if not
    let watch_check = Command::new("cargo")
        .args(["watch", "--version"])
        .output();
        
    if watch_check.is_err() || !watch_check.unwrap().status.success() {
        println!("📦 Installing cargo-watch...");
        let status = Command::new("cargo")
            .args(["install", "cargo-watch"])
            .status()?;
            
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other, 
                "Failed to install cargo-watch"
            ));
        }
    } else {
        println!("✅ cargo-watch is already installed");
    }
    
    println!("✅ Development tools installed successfully!");
    Ok(())
}
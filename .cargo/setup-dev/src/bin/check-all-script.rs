fn main() {
    let steps: [(&str, &[&str]); 3] = [
        ("cargo", &["fmt", "--all"][..]),
        ("cargo", &["clippy", "--", "-D", "warnings"][..]),
        ("cargo", &["test"][..]),
    ];
    for (cmd, args) in steps {
        let status = std::process::Command::new(cmd)
            .args(args)
            .status()
            .expect("Failed to run command");
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

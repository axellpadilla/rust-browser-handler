# Browser Selector (Command-Line)

This project is a Rust-based command-line application that acts as a default browser handler for Windows. It allows users to intercept link clicks and apply rules to automatically open links in a specific browser or interactively select a browser.

## Features

- **Default Browser Handling:** Intercepts http and https links clicked from other applications when set as the default handler.
- **Rule-Based Automation:** Allows users to define rules based on URL patterns (substring or regular expressions) to automatically open links in a specific browser without manual intervention. Rules are stored in a `rules.json` file in the user's configuration directory.
- **Interactive Browser Selection:** If no rule matches an intercepted URL, the application presents a list of detected browsers and prompts the user to select one. The user can also choose to save this selection as a new rule for the URL's domain.
- **Command-Line Interface (CLI):** Provides a non-graphical interface for managing browser selection rules and preferences. Can be used via subcommands or an interactive mode.

## Usage

### Portable Version

1. Download the ZIP file
2. Extract to a permanent location
3. Execute `rust_browser_handler.exe` to add rules.
4. Use the `open-settings` command to set this .exe as the default handler.

### Building

To build the release version of the application, navigate to the project directory in your terminal and run:

```bash
cargo build --release
```

This will generate an executable file (likely `rust_browser_handler.exe` in the `target/release/` directory).

### Registration

To register the application as the default handler for http and https protocols, run the executable with the `register` subcommand:

```bash
target\release\rust_browser_handler.exe register
```

Alternatively, you can run the executable without arguments to enter interactive mode and use the `register` command there.

### Rule Management

Rules are stored in a `rules.json` file in your user's configuration directory (e.g., `%APPDATA%\Roaming\BrowserSelector\rules.json` on Windows).

You can manage rules using the command-line interface in two ways:

1.  **Direct Commands:** Run the executable with a subcommand and arguments:

    ```bash
    # Add a rule (substring match)
    target\release\rust_browser_handler.exe add "work.com" "C:\Program Files\Google\Chrome\Application\chrome.exe"

    # Add a rule (regex match)
    target\release\rust_browser_handler.exe add ".*\\.internal\\.net" "C:\Program Files\Mozilla Firefox\firefox.exe" --regex

    # List all rules
    target\release\rust_browser_handler.exe list

    # Remove a rule by pattern
    target\release\rust_browser_handler.exe remove "work.com"

    # Import rules from a file
    target\release\rust_browser_handler.exe import "path\to\your\rules.json"

    # Export rules to a file
    target\release\rust_browser_handler.exe export "path\to\save\rules.json"

    # Open Windows Settings to manage default handlers
    target\release\rust_browser_handler.exe open-settings
    ```

2.  **Interactive Mode:** Run the executable without any arguments to enter an interactive mode:

    ```bash
    target\release\rust_browser_handler.exe
    ```

    In interactive mode, type commands like `add`, `list`, `remove`, `import`, `export`, `register`, and `exit`. Type `help` for a list of commands and their usage within the interactive mode.

### Intercepting URLs

Once registered, simply click on an http or https link from any application.

- If a rule matches the URL, the corresponding browser will be launched automatically.
- If no rule matches, the application will list detected browsers and prompt you to select one. You can type the browser number to open the link in that browser, or type the number followed by 's' (e.g., '1s') to open in that browser and save a rule for the URL's domain.

## Future Development

- **Improved Browser Detection:** Further refine the process of automatically detecting installed browsers.
- **Integration with System Settings:** Deeper integration with Windows default app settings for a more seamless user experience.
- **More Advanced Rule Options:** Explore additional rule criteria beyond URL patterns.

## Development Setup

This project uses a standardized development environment with linting, formatting, and commit message conventions.

### Quick Setup

After cloning this repository, run:

```bash
cargo setup-dev
```

This will:
1. Configure Git to use our commit template
2. Install pre-commit hooks for linting and commit message validation
3. Install necessary development tools (rustfmt, clippy, cargo-watch)

### Development Commands

```bash
# Run the application
cargo run

# Development mode (auto-rebuild on changes)
cargo dev

# Run tests
cargo test

# Run tests with auto-rerun on changes
cargo test-watch

# Format code
cargo format

# Lint code
cargo lint

# Run all checks (format, lint, test)
cargo check-all
```

### Commit Message Format

This project uses Gitmoji Conventional Commits format. The commit template will guide you, but here's a quick example:

```
:sparkles: feat(auth): add login functionality
```

See `.github/commit-template.txt` for more details.


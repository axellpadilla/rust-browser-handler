use log::{info, warn};
use std::io;
use winreg::{RegKey, enums::*};

pub fn set_as_default_handler() -> io::Result<()> {
    info!("Attempting to register as default browser handler...");

    let exe_path = std::env::current_exe()?
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get executable path"))?
        .to_string();

    // Register custom URL scheme (rust-browser-handler)
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes_key = hkcu.open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS)?;

    let scheme_key = classes_key.create_subkey("rust-browser-handler")?;
    scheme_key
        .0
        .set_value("", &"URL:Rust Browser Handler Protocol".to_string())?;
    scheme_key.0.set_value("URL Protocol", &"")?;

    let default_icon_key = scheme_key.0.create_subkey("DefaultIcon")?;
    default_icon_key
        .0
        .set_value("", &format!("{},0", exe_path))?;

    let command_key = scheme_key.0.create_subkey("shell\\open\\command")?;
    command_key
        .0
        .set_value("", &format!("\"{}\" \"%1\"", exe_path))?;

    // Register as a capable application
    let registered_apps_key =
        hkcu.open_subkey_with_flags("Software\\RegisteredApplications", KEY_ALL_ACCESS)?;
    registered_apps_key.set_value(
        "RustBrowserHandler",
        &"Software\\Clients\\StartMenuInternet\\RustBrowserHandler\\Capabilities",
    )?;

    let capabilities_key = hkcu
        .create_subkey("Software\\Clients\\StartMenuInternet\\RustBrowserHandler\\Capabilities")?;
    capabilities_key.0.set_value(
        "ApplicationDescription",
        &"Handles URLs based on defined rules.",
    )?;
    capabilities_key
        .0
        .set_value("ApplicationIcon", &format!("{},0", exe_path))?;
    capabilities_key
        .0
        .set_value("ApplicationName", &"Rust Browser Handler")?;

    let url_associations_key = capabilities_key.0.create_subkey("URLAssociations")?;
    url_associations_key
        .0
        .set_value("http", &"rust-browser-handler")?;
    url_associations_key
        .0
        .set_value("https", &"rust-browser-handler")?;

    info!("Registry entries created/updated.");
    println!("Registry entries created/updated.");
    println!(
        "Please go to Windows Default Apps settings and set 'Rust Browser Handler' as the default for HTTP and HTTPS protocols."
    );

    Ok(())
}

pub fn unregister_handler() -> io::Result<()> {
    info!("Attempting to unregister as default browser handler...");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Remove URLAssociations
    if let Ok(capabilities_key) = hkcu.open_subkey_with_flags(
        "Software\\Clients\\StartMenuInternet\\RustBrowserHandler\\Capabilities",
        KEY_ALL_ACCESS,
    ) {
        let _ = capabilities_key.delete_subkey_all("URLAssociations");
        info!("URLAssociations key removed or did not exist.");
    } else {
        warn!("Could not open Capabilities key to remove URLAssociations.");
    }

    // Remove Capabilities key itself (which is RustBrowserHandler under StartMenuInternet)
    if let Ok(start_menu_internet_key) =
        hkcu.open_subkey_with_flags("Software\\Clients\\StartMenuInternet", KEY_ALL_ACCESS)
    {
        let _ = start_menu_internet_key.delete_subkey_all("RustBrowserHandler");
        info!(
            "Software\\Clients\\StartMenuInternet\\RustBrowserHandler key removed or did not exist."
        );
    } else {
        warn!("Could not open Software\\Clients\\StartMenuInternet key.");
    }

    // Remove from RegisteredApplications
    if let Ok(registered_apps_key) =
        hkcu.open_subkey_with_flags("Software\\RegisteredApplications", KEY_ALL_ACCESS)
    {
        let _ = registered_apps_key.delete_value("RustBrowserHandler");
        info!("RustBrowserHandler value removed from RegisteredApplications or did not exist.");
    } else {
        warn!("Could not open RegisteredApplications key.");
    }

    // Remove custom URL scheme (rust-browser-handler)
    if let Ok(classes_key) = hkcu.open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS) {
        let _ = classes_key.delete_subkey_all("rust-browser-handler");
        info!("Software\\Classes\\rust-browser-handler key removed or did not exist.");
    } else {
        warn!("Could not open Software\\Classes key.");
    }

    info!("Unregistration process completed. Some keys/values might have already been absent.");
    println!("Unregistration process completed.");
    println!(
        "You may need to manually select a new default browser in Windows Settings if Rust Browser Handler was previously set."
    );

    Ok(())
}

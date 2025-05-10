use std::fs;
use std::path::Path;

fn main() {
    // Get the output directory from cargo
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("../../../");

    // Copy README.md to the target directory
    println!("cargo:rerun-if-changed=README.md");
    fs::copy("README.md", dest_path.join("README.md")).expect("Failed to copy README.md");
}

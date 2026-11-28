// SPDX-License-Identifier: AGPL-3.0-or-later
use std::path::PathBuf;
use std::process::Command;

fn detect_build_node() -> Option<String> {
    if let Ok(out) = Command::new("which").arg("node").output() {
        if out.status.success() {
            let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !raw.is_empty() {
                let p = PathBuf::from(&raw);
                if let Ok(canon) = std::fs::canonicalize(&p) {
                    return Some(canon.to_string_lossy().to_string());
                }
                return Some(raw);
            }
        }
    }
    None
}

fn main() {
    if let Some(node_bin) = detect_build_node() {
        println!("cargo:rustc-env=BUILD_NODE_BIN={}", node_bin);
    }
    tauri_build::build();
}

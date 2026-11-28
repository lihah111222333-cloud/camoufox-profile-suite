// SPDX-License-Identifier: AGPL-3.0-or-later
// Camoufox Studio — Native macOS Tauri v2 Desktop Shell
// Spawns the bundled local loopback Node.js HTTP bridge on an ephemeral port,
// waits for /api/health, opens the native window, and cleans up on exit.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::Manager;

struct BridgeProcess(Mutex<Option<Child>>);

fn pick_free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to bind ephemeral loopback port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to read local port: {e}"))?
        .port();
    drop(listener);
    Ok(port)
}

fn resolve_node_binary() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(env_node) = std::env::var("CAMOUFOX_STUDIO_NODE") {
        if !env_node.trim().is_empty() {
            candidates.push(PathBuf::from(env_node.trim()));
        }
    }
    if let Some(build_node) = option_env!("BUILD_NODE_BIN") {
        candidates.push(PathBuf::from(build_node));
    }
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(&home).join(".local/bin/node"));
        candidates.push(PathBuf::from(&home).join(".volta/bin/node"));
        candidates.push(PathBuf::from(&home).join(".asdf/shims/node"));
    }
    candidates.push(PathBuf::from("/opt/homebrew/bin/node"));
    candidates.push(PathBuf::from("/usr/local/bin/node"));
    candidates.push(PathBuf::from("/usr/bin/node"));

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            candidates.push(dir.join("node"));
        }
    }

    for cand in candidates {
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn resolve_suite_root(app: &tauri::App) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(res_dir) = app.path().resource_dir() {
        candidates.push(res_dir.join("resources").join("suite"));
        candidates.push(res_dir.join("suite"));
    }

    // Development checkout fallback (desktop/src-tauri -> repo root)
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.clone());
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.to_path_buf());
            if let Some(grand) = parent.parent() {
                candidates.push(grand.to_path_buf());
            }
        }
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(".."));

    for root in candidates {
        if root.join("desktop").join("server.mjs").is_file() {
            return std::fs::canonicalize(&root).or(Ok(root));
        }
    }

    Err("Could not locate Camoufox Studio runtime (desktop/server.mjs).".to_string())
}

fn wait_for_health(port: u16, child: &mut Child, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    let request = format!(
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );

    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("Local Node.js bridge exited early with {status}."));
        }
        if let Ok(mut stream) = TcpStream::connect(&addr) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let head = String::from_utf8_lossy(&buf[..n]);
                    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
                        return Ok(());
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(60));
    }

    Err(format!("Timed out waiting for local HTTP bridge on {addr}."))
}

fn spawn_bridge(node_bin: &Path, suite_root: &Path, port: u16) -> Result<Child, String> {
    let script = suite_root.join("desktop").join("server.mjs");
    Command::new(node_bin)
        .arg(&script)
        .current_dir(suite_root)
        .env("CAMOUFOX_UI_HOST", "127.0.0.1")
        .env("CAMOUFOX_UI_PORT", port.to_string())
        .env("CAMOUFOX_UI_DESKTOP", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to start Node.js bridge ({}): {e}", node_bin.display()))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_state_flags(
                    tauri_plugin_window_state::StateFlags::SIZE
                        | tauri_plugin_window_state::StateFlags::POSITION
                        | tauri_plugin_window_state::StateFlags::MAXIMIZED,
                )
                .build(),
        )
        .setup(|app| {
            let node_bin = resolve_node_binary()
                .ok_or_else(|| "Node.js (>=18) was not found on this machine.".to_string())?;
            let suite_root = resolve_suite_root(app)?;
            let port = pick_free_port()?;

            let mut child = spawn_bridge(&node_bin, &suite_root, port)?;
            if let Err(err) = wait_for_health(port, &mut child, Duration::from_secs(10)) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err.into());
            }

            app.manage(BridgeProcess(Mutex::new(Some(child))));

            if let Some(win) = app.get_webview_window("main") {
                let url = format!("http://127.0.0.1:{port}/")
                    .parse::<tauri::Url>()
                    .map_err(|e| format!("Invalid local URL: {e}"))?;
                win.navigate(url)?;
                let _ = win.show();
                let _ = win.set_focus();
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Camoufox Studio")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(state) = app.try_state::<BridgeProcess>() {
                    if let Ok(mut guard) = state.0.lock() {
                        if let Some(mut child) = guard.take() {
                            let _ = child.kill();
                            let _ = child.wait();
                        }
                    }
                }
            }
        });
}

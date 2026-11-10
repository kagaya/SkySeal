#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::Value;
use std::{io::Write, path::PathBuf, process::{Command, Stdio}, sync::{Arc, Mutex}};
use tauri::{State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct EngineGate(Arc<Mutex<()>>);

const OPERATIONS: &[&str] = &[
    "status", "configure", "identity_enroll", "prepare", "seal", "list", "get",
    "resume", "export", "verify", "tls_status", "trust_local_certificate",
];

fn validate_request(request: &Value) -> Result<(), String> {
    let obj = request.as_object().ok_or("Invalid engine request")?;
    if obj.keys().any(|k| k != "op" && k != "params") {
        return Err("Unknown engine request field".into());
    }
    let op = request.get("op").and_then(Value::as_str).ok_or("Missing operation")?;
    if !OPERATIONS.contains(&op) { return Err("Operation not allowed".into()); }
    if !request.get("params").map(Value::is_object).unwrap_or(true) {
        return Err("Parameters must be an object".into());
    }
    if serde_json::to_vec(request).map_err(|_| "Invalid request")?.len() > 256 * 1024 {
        return Err("Request too large".into());
    }
    Ok(())
}

fn engine_command() -> Result<Command, String> {
    // Release can execute only the bundled fixed-name engine beside the app.
    // Debug uses this checkout, never a path received from the webview.
    if cfg!(debug_assertions) {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
        command.current_dir(repo).args(["-m", "desktop.engine"]);
        Ok(command)
    } else {
        let executable = std::env::current_exe().map_err(|_| "Cannot locate application")?;
        let parent = executable.parent().ok_or("Cannot locate application directory")?;
        let engine = parent.join(if cfg!(windows) { "desktop-engine.exe" } else { "desktop-engine" });
        if !engine.is_file() { return Err("Bundled SkySeal engine is missing. Reinstall the application.".into()); }
        Ok(Command::new(engine))
    }
}

#[tauri::command]
async fn backend(request: Value, gate: State<'_, EngineGate>) -> Result<Value, String> {
    validate_request(&request)?;
    let gate = gate.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = gate.try_lock().map_err(|_| "Another operation is running")?;
        let mut command = engine_command()?;
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        command.env("PYTHONUTF8", "1");
        #[cfg(windows)] {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW; Hello owns its native dialog.
        }
        let mut child = command.spawn().map_err(|e| format!("Cannot start SkySeal engine: {e}"))?;
        let mut input = serde_json::to_vec(&request).map_err(|_| "Cannot encode request")?;
        input.push(b'\n');
        let write_result = child.stdin.take().ok_or("Cannot open engine input")?.write_all(&input);
        if write_result.is_err() { let _ = child.kill(); let _ = child.wait(); return Err("Cannot write to SkySeal engine".into()); }
        let output = child.wait_with_output().map_err(|_| "Cannot read SkySeal engine response")?;
        // Errors are structured JSON; stderr is never surfaced because it may contain diagnostics.
        if output.stdout.len() > 16 * 1024 * 1024 { return Err("SkySeal response exceeds limit".into()); }
        serde_json::from_slice(&output.stdout).map_err(|_| "SkySeal engine did not return a valid response".into())
    }).await.map_err(|_| "SkySeal worker failed".to_string())?
}

#[tauri::command]
async fn choose_path(app: tauri::AppHandle, kind: String, suggested_name: Option<String>) -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = app.dialog().file();
        let selected = match kind.as_str() {
            "files" => dialog.set_title("封緘するファイルを選択").blocking_pick_files().unwrap_or_default(),
            "folder" => dialog.set_title("封緘するフォルダーを選択").blocking_pick_folder().into_iter().collect(),
            "evidence_folder" => dialog.set_title("証拠フォルダーを選択").blocking_pick_folder().into_iter().collect(),
            "evidence" => dialog.set_title("SkySeal 証拠 ZIP を選択").add_filter("SkySeal evidence", &["zip"]).blocking_pick_file().into_iter().collect(),
            "candidate" => dialog.set_title("一致を調べるファイルを選択").blocking_pick_file().into_iter().collect(),
            "export" => {
                if let Some(name) = suggested_name {
                    if name.contains('/') || name.contains('\\') || name.len() > 160 { return Err("Invalid suggested file name".into()); }
                    dialog = dialog.set_file_name(name);
                }
                dialog.set_title("証拠を書き出す").add_filter("ZIP archive", &["zip"]).blocking_save_file().into_iter().collect()
            },
            _ => return Err("Unknown file dialog".into()),
        };
        selected.into_iter().map(|file| file.into_path().map(|path| path.to_string_lossy().into_owned()).map_err(|_| "Only local file paths are supported".to_string())).collect()
    }).await.map_err(|_| "File dialog failed".to_string())?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(EngineGate::default())
        .invoke_handler(tauri::generate_handler![backend, choose_path])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("SkySeal")
                .inner_size(1160.0, 790.0)
                .min_inner_size(850.0, 650.0)
                .on_navigation(|url| {
                    // Never grant the command bridge to a remote page.
                    (url.scheme() == "tauri" && url.host_str() == Some("localhost"))
                        || ((url.scheme() == "http" || url.scheme() == "https") && url.host_str() == Some("tauri.localhost"))
                })
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("SkySeal failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn allowlist_rejects_arbitrary_process_requests() {
        assert!(validate_request(&json!({"op":"status", "params":{}})).is_ok());
        assert!(validate_request(&json!({"op":"exec", "params":{"cmd":"anything"}})).is_err());
        assert!(validate_request(&json!({"op":"status", "program":"other.exe"})).is_err());
        assert!(validate_request(&json!({"op":"prepare", "params":"bad"})).is_err());
    }
}

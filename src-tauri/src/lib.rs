// MobileCheck desktop shell (Tauri 2.x) — the mobile sibling of ComputerCheck.
//
// The user plugs their OWN phone into this laptop over USB; the Python engine
// scans it read-only (adb for Android; pymobiledevice3/MVT for iOS in later
// phases) and this shell renders the report.
//
// Responsibilities of the Rust core:
//   1. Run the engine, stream its stderr NDJSON progress to the webview as
//      `scan://progress` events, and hand the final stdout JSON back.
//   2. Derive a stable per-PHONE pseudonym: HMAC-SHA256(key, usb_serial),
//      where the key lives in the OS keystore. Not reversible to the serial,
//      not linkable across installs.
//   3. Keep scan history ENCRYPTED AT REST (AES-256-GCM, key in the keystore).
//
// Hard rule: read-only on the audited phone. The only writes are to this app's
// own data directory (history) and to user-chosen export paths.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Emitter, Manager};

const KEYCHAIN_SERVICE: &str = "com.luisassardo.mobilecheck";
const KEY_ENTRY: &str = "history-data-key";
const PHONE_HMAC_ENTRY: &str = "phone-pseudonym-hmac-key";

// PID of the currently running scan engine, for cancel_scan.
pub struct ScanState(pub Mutex<Option<u32>>);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn app_data(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn history_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app_data(app)?.join("history.enc"))
}

// --- Secret storage: native OS keystore (macOS Keychain / Windows Credential
//     Manager via the keyring crate), with a file fallback on other OSes (Linux
//     dev) so the crate still compiles everywhere. ---------------------------

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn secret_get_or_create(entry: &str, factory: impl FnOnce() -> String) -> Result<String, String> {
    let kr = keyring::Entry::new(KEYCHAIN_SERVICE, entry).map_err(|e| e.to_string())?;
    match kr.get_password() {
        Ok(v) => Ok(v),
        Err(_) => {
            let v = factory();
            kr.set_password(&v).map_err(|e| e.to_string())?;
            Ok(v)
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn secret_delete(entry: &str) -> Result<(), String> {
    if let Ok(kr) = keyring::Entry::new(KEYCHAIN_SERVICE, entry) {
        let _ = kr.delete_credential();
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn secret_get_or_create(entry: &str, factory: impl FnOnce() -> String) -> Result<String, String> {
    // Linux/dev fallback: a file in the app dir. Keeps cross-platform builds compiling.
    use std::io::Write;
    let dir = dirs_fallback()?;
    let p = dir.join(format!("{}.secret", entry));
    if let Ok(v) = std::fs::read_to_string(&p) {
        return Ok(v);
    }
    let v = factory();
    let mut f = std::fs::File::create(&p).map_err(|e| e.to_string())?;
    f.write_all(v.as_bytes()).map_err(|e| e.to_string())?;
    Ok(v)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn secret_delete(entry: &str) -> Result<(), String> {
    let dir = dirs_fallback()?;
    let _ = std::fs::remove_file(dir.join(format!("{}.secret", entry)));
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn dirs_fallback() -> Result<PathBuf, String> {
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|e| e.to_string())?;
    let dir = PathBuf::from(base).join(".mobile-check");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

// 32-byte AES key, stored base64 in the Keychain.
fn data_key() -> Result<[u8; 32], String> {
    use base64::Engine;
    let b64 = secret_get_or_create(KEY_ENTRY, || {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        base64::engine::general_purpose::STANDARD.encode(k)
    })?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    if raw.len() != 32 {
        return Err("history key has wrong length".into());
    }
    key.copy_from_slice(&raw);
    Ok(key)
}

fn encrypt(plaintext: &str) -> Result<Vec<u8>, String> {
    let key = data_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(blob: &[u8]) -> Result<String, String> {
    if blob.len() < 13 {
        return Err("history file truncated".into());
    }
    let key = data_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let pt = cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| e.to_string())?;
    String::from_utf8(pt).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Per-phone pseudonym: HMAC-SHA256(keystore key, usb serial), hex, 16 chars.
// Stable for the same phone on this install; meaningless anywhere else.
// ---------------------------------------------------------------------------

fn phone_pseudonym(serial: &str) -> Result<String, String> {
    let key_hex = secret_get_or_create(PHONE_HMAC_ENTRY, || random_hex(32))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key_hex.as_bytes())
        .map_err(|e| e.to_string())?;
    mac.update(serial.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect::<String>()[..16].to_string())
}

// ---------------------------------------------------------------------------
// Encrypted export (age, to the C-LAB recipient public key)
// ---------------------------------------------------------------------------
//
// The export is encrypted to ONE recipient: C-LAB's age public key, baked in
// below. Only the holder of the matching private key (Luis) can decrypt it, so
// the file is safe to send over any channel (Proton, Signal, upload, in person).
//
// C-LAB production recipient (set 2026-06-05, same key family as ComputerCheck).
// The matching private key is held offline by Luis only; it never lives in this
// repo. To rotate, replace with a new `age1...` public key from `age-keygen`.
const CLAB_AGE_RECIPIENT: &str = "age1p20uvq4wl0kfs6wga2jldszu4f6k4t7mf565vp8j4dptuq9m7ppspsq83e";

fn age_encrypt(plaintext: &[u8], recipient_str: &str) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let recipient = recipient_str
        .parse::<age::x25519::Recipient>()
        .map_err(|e| format!("invalid C-LAB recipient key: {e}"))?;
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .ok_or("no recipients configured")?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| e.to_string())?;
    writer.write_all(plaintext).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    Ok(encrypted)
}

// ---------------------------------------------------------------------------
// Engine invocation
// ---------------------------------------------------------------------------

// Dev interpreter: Windows ships `python` (not `python3`); macOS/Linux use python3.
fn python_cmd() -> &'static str {
    if cfg!(target_os = "windows") { "python" } else { "python3" }
}

// Release sidecar: PyInstaller emits a .exe on Windows.
fn bundled_engine_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let name = if cfg!(target_os = "windows") {
        "mobile-check-engine.exe"
    } else {
        "mobile-check-engine"
    };
    let res = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join("engine-dist")
        .join(name);
    if !res.exists() {
        return Err(format!(
            "bundled engine not found at {}. Build it with scripts/build-engine.sh (or build-engine.ps1 on Windows) before packaging.",
            res.display()
        ));
    }
    Ok(res)
}

fn dev_project_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "cannot locate project root".to_string())
}

// MC_RESOURCES tells the engine where the bundled adb (and, later, the python
// runtime tarballs) live. Dev points at the source tree's resources dir.
fn resources_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        Ok(dev_project_root()?.join("src-tauri").join("resources"))
    } else {
        app.path().resource_dir().map_err(|e| e.to_string())
    }
}

// Build a Command for the engine with the given args (dev = python source tree,
// release = PyInstaller sidecar) and MC_RESOURCES set.
fn engine_command(app: &tauri::AppHandle, args: &[String]) -> Result<std::process::Command, String> {
    let res_dir = resources_dir(app)?;
    let mut cmd = if cfg!(debug_assertions) {
        let mut c = std::process::Command::new(python_cmd());
        c.arg("-m").arg("engine.mobilecheck").args(args);
        c.current_dir(dev_project_root()?);
        c
    } else {
        let bin = bundled_engine_path(app)?;
        let mut c = std::process::Command::new(bin);
        c.args(args);
        c
    };
    cmd.env("MC_RESOURCES", res_dir);
    if let Ok(data) = app_data(app) {
        cmd.env("MC_APPDATA", data);
    }
    Ok(cmd)
}

// Run the engine streaming stderr lines to the webview under `event_name`,
// returning the final stdout. Shared by run_scan and ios_toolchain_install.
fn run_engine_streaming(
    app: &tauri::AppHandle,
    state: &tauri::State<'_, ScanState>,
    args: &[String],
    event_name: &str,
    extra_env: &[(&str, String)],
) -> Result<String, String> {
    use std::process::Stdio;

    let mut cmd = engine_command(app, args)?;
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to launch engine: {e}"))?;

    *state.0.lock().unwrap() = Some(child.id());

    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let app_for_events = app.clone();
    let event_owned = event_name.to_string();
    let reader_thread = std::thread::spawn(move || {
        let mut tail: Vec<String> = Vec::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = app_for_events.emit(&event_owned, &line);
            tail.push(line);
            if tail.len() > 40 {
                tail.remove(0);
            }
        }
        tail.join("\n")
    });

    let mut stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let mut payload = String::new();
    stdout
        .read_to_string(&mut payload)
        .map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    let stderr_tail = reader_thread.join().unwrap_or_default();

    *state.0.lock().unwrap() = None;

    // Exit 2 = engine spoke JSON ({"error": ...}); hand it to the frontend.
    // Other non-zero = engine itself broke; surface the stderr tail.
    if !status.success() && payload.trim().is_empty() {
        return Err(format!("engine exited with error:\n{stderr_tail}"));
    }
    Ok(payload)
}

// Run the engine in "pdf" mode: feed the payload on stdin, write a PDF to dest.
fn run_engine_pdf(app: &tauri::AppHandle, payload: &str, lang: &str, dest: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let pdf_args = vec![
        "--out".to_string(), dest.to_string(),
        "--lang".to_string(), lang.to_string(),
    ];

    let mut cmd = if cfg!(debug_assertions) {
        let mut c = Command::new(python_cmd());
        c.arg("-m").arg("engine.report_pdf").args(&pdf_args).current_dir(dev_project_root()?);
        c
    } else {
        let res = bundled_engine_path(app)?;
        let mut c = Command::new(&res);
        c.arg("pdf").args(&pdf_args);
        c
    };

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to launch engine for PDF: {e}"))?;
    child.stdin.take().ok_or("no stdin")?
        .write_all(payload.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("PDF generation failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

// Quick poll: which phone is plugged in? Returns the engine's detection JSON.
#[tauri::command]
fn detect_device(app: tauri::AppHandle) -> Result<String, String> {
    let output = engine_command(&app, &["--detect".to_string()])?
        .output()
        .map_err(|e| format!("failed to launch engine: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "device detection failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Run a scan. Blocking command (Tauri runs it off the main thread); progress
// arrives in the webview as `scan://progress` events, one NDJSON line each.
// `backup_password` (iOS deep scans only) travels to the engine via env var,
// never argv, and is not logged.
#[tauri::command]
fn run_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, ScanState>,
    platform: String,
    serial: String,
    org_code: Option<String>,
    ios_mode: Option<String>,
    backup_password: Option<String>,
) -> Result<String, String> {
    let pseudonym = phone_pseudonym(&serial)?;
    let mut args: Vec<String> = vec![
        "--platform".into(), platform,
        "--device-pseudonym".into(), pseudonym,
    ];
    if !serial.is_empty() {
        args.push("--serial".into());
        args.push(serial);
    }
    if let Some(mode) = ios_mode {
        if !mode.is_empty() {
            args.push("--ios-mode".into());
            args.push(mode);
        }
    }
    if let Some(org) = org_code {
        if !org.is_empty() {
            args.push("--org-code".into());
            args.push(org);
        }
    }
    let mut env: Vec<(&str, String)> = Vec::new();
    if let Some(pw) = backup_password {
        if !pw.is_empty() {
            env.push(("MC_BACKUP_PASSWORD", pw));
        }
    }
    run_engine_streaming(&app, &state, &args, "scan://progress", &env)
}

// iOS toolchain management. Status is quick and silent; install streams its
// progress to `toolchain://progress` (pip download can take minutes).
#[tauri::command]
fn ios_toolchain_status(app: tauri::AppHandle) -> Result<String, String> {
    let output = engine_command(&app, &["--toolchain".into(), "status".into()])?
        .output()
        .map_err(|e| format!("failed to launch engine: {e}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn ios_toolchain_install(
    app: tauri::AppHandle,
    state: tauri::State<'_, ScanState>,
    wheelhouse: Option<String>,
) -> Result<String, String> {
    let mut args: Vec<String> = vec!["--toolchain".into(), "install".into()];
    if let Some(wh) = wheelhouse {
        if !wh.is_empty() {
            args.push("--wheelhouse".into());
            args.push(wh);
        }
    }
    run_engine_streaming(&app, &state, &args, "toolchain://progress", &[])
}

#[tauri::command]
fn refresh_iocs(
    app: tauri::AppHandle,
    state: tauri::State<'_, ScanState>,
) -> Result<String, String> {
    run_engine_streaming(
        &app, &state,
        &["--toolchain".into(), "refresh-iocs".into()],
        "toolchain://progress", &[],
    )
}

// Cancel a running scan: SIGTERM the engine process (it traps the signal and
// cleans up; iOS backup temp deletion is guaranteed by the engine's own finally).
#[tauri::command]
fn cancel_scan(state: tauri::State<'_, ScanState>) -> Result<(), String> {
    let pid = state.0.lock().unwrap().take();
    let Some(pid) = pid else { return Ok(()) };
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    {
        std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn history_load(app: tauri::AppHandle) -> Result<String, String> {
    let p = history_path(&app)?;
    match std::fs::read(&p) {
        Ok(blob) => decrypt(&blob),
        Err(_) => Ok("[]".to_string()), // no history yet
    }
}

// Append one scan record (a JSON object string) to the encrypted history array.
#[tauri::command]
fn history_append(app: tauri::AppHandle, record: String) -> Result<(), String> {
    let current = history_load(app.clone())?;
    let mut arr: Vec<serde_json::Value> =
        serde_json::from_str(&current).map_err(|e| e.to_string())?;
    let rec: serde_json::Value = serde_json::from_str(&record).map_err(|e| e.to_string())?;
    arr.push(rec);
    let serialized = serde_json::to_string(&arr).map_err(|e| e.to_string())?;
    let blob = encrypt(&serialized)?;
    std::fs::write(history_path(&app)?, blob).map_err(|e| e.to_string())?;
    Ok(())
}

// Wipe history: remove the file AND the Keychain data key, so nothing remains.
#[tauri::command]
fn history_wipe(app: tauri::AppHandle) -> Result<(), String> {
    let _ = std::fs::remove_file(history_path(&app)?);
    secret_delete(KEY_ENTRY)?;
    Ok(())
}

// Generate a PDF report from a scan payload, written to a path the user picked
// via the save dialog. On request only; PDFs are never automatic.
#[tauri::command]
fn export_pdf(app: tauri::AppHandle, payload: String, lang: Option<String>, dest: String) -> Result<(), String> {
    let lang = lang.unwrap_or_else(|| "en".to_string());
    let lang = if lang == "en" || lang == "de" || lang == "es" { lang } else { "en".to_string() };
    run_engine_pdf(&app, &payload, &lang, &dest)
}

// Encrypt a payload (already prepared by the frontend: IoC stripped for routine
// exports, or full for the urgent channel) to the C-LAB recipient and write the
// .age file to a path the user picked. Networking is the user's job (they send
// the file). On request only.
#[tauri::command]
fn export_encrypted(payload: String, dest: String) -> Result<(), String> {
    let bytes = age_encrypt(payload.as_bytes(), CLAB_AGE_RECIPIENT)?;
    std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("unsupported scheme".into());
    }
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";
    std::process::Command::new(program)
        .arg(&url)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanState(Mutex::new(None)))
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            detect_device,
            run_scan,
            cancel_scan,
            ios_toolchain_status,
            ios_toolchain_install,
            refresh_iocs,
            history_load,
            history_append,
            history_wipe,
            export_pdf,
            export_encrypted,
            open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Verifies the export round-trips AND prints a fresh keypair for Luis to bake
    // in. Run:  cargo test age_roundtrip -- --nocapture
    #[test]
    fn age_roundtrip() {
        use secrecy::ExposeSecret;
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public();
        println!("\n=== FRESH AGE KEYPAIR (use for C-LAB) ===");
        println!("PUBLIC  (bake into CLAB_AGE_RECIPIENT): {}", recipient);
        println!("PRIVATE (keep offline, never commit):   {}", id.to_string().expose_secret());
        println!("=========================================\n");

        let pt = b"{\"schema\":\"securityscan.findings/2\",\"hello\":\"world\"}";
        let ct = age_encrypt(pt, &recipient.to_string()).expect("encrypt");
        assert!(ct.starts_with(b"age-encryption.org/v1"), "not an age file");

        let dec = match age::Decryptor::new(&ct[..]).expect("decryptor") {
            age::Decryptor::Recipients(d) => d,
            _ => panic!("expected recipients decryptor"),
        };
        let mut reader = dec
            .decrypt(std::iter::once(&id as &dyn age::Identity))
            .expect("decrypt");
        let mut out = Vec::new();
        reader.read_to_end(&mut out).expect("read");
        assert_eq!(out, pt, "round-trip mismatch");
    }

    // The baked C-LAB recipient must be a valid age public key and produce a real
    // age file. We can't decrypt here (only Luis holds the private key), so we
    // assert the recipient parses and the encrypt path yields an age envelope.
    #[test]
    fn baked_recipient_valid() {
        CLAB_AGE_RECIPIENT
            .parse::<age::x25519::Recipient>()
            .expect("CLAB_AGE_RECIPIENT is not a valid age public key");
        let ct = age_encrypt(b"{\"export_kind\":\"routine\"}", CLAB_AGE_RECIPIENT)
            .expect("encrypt to baked key");
        assert!(ct.starts_with(b"age-encryption.org/v1"), "not an age file");
    }

    // Same serial -> same pseudonym; different serial -> different pseudonym.
    #[test]
    fn phone_pseudonym_stable() {
        let a1 = phone_pseudonym("R58M12ABCDE").expect("pseudonym");
        let a2 = phone_pseudonym("R58M12ABCDE").expect("pseudonym");
        let b = phone_pseudonym("00008110-001E30EC2222801E").expect("pseudonym");
        assert_eq!(a1, a2, "pseudonym must be stable per serial");
        assert_ne!(a1, b, "different phones must get different pseudonyms");
        assert_eq!(a1.len(), 16);
    }
}

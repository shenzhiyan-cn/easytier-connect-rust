pub mod api;
mod frb_generated;

// ============================================================================
// C FFI 胶水层
//
// 由于 easytier-ffi crate 的 crate-type 仅为 cdylib，无法被其他 Rust crate
// 直接 `pub use`。这里直接依赖 easytier 主 crate，重新实现 C FFI 函数，
// 供 iOS Network Extension (PacketTunnel) 通过 Bridging Header 调用。
//
// 实现参考: easytier-contrib/easytier-ffi/src/lib.rs (v2.6.4)
// ============================================================================

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use dashmap::DashMap;
use easytier::{
    common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
};
use once_cell::sync::Lazy;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static INSTANCE_NAME_ID_MAP: Lazy<DashMap<String, uuid::Uuid>> =
    Lazy::new(DashMap::new);
static INSTANCE_MANAGER: Lazy<NetworkInstanceManager> =
    Lazy::new(NetworkInstanceManager::new);

static ERROR_MSG: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));

// 全局 stop 标志，用于 stop_network_instance
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

// ── 日志收集 ──────────────────────────────────────────────────────────────

const MAX_LOG_BYTES: usize = 256 * 1024; // 256 KB

static LOG_BUFFER: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));
static LOG_INIT: std::sync::Once = std::sync::Once::new();

// 文件日志路径（init_logger 设置）
static LOG_FILE_PATH: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

struct RingBufferWriter;

impl Write for RingBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut buffer = LOG_BUFFER.lock().unwrap();
        buffer.extend_from_slice(buf);
        while buffer.len() > MAX_LOG_BYTES {
            if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                buffer.drain(..=pos);
            } else {
                buffer.clear();
                break;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct LogWriterFactory;

impl<'a> MakeWriter<'a> for LogWriterFactory {
    type Writer = RingBufferWriter;

    fn make_writer(&self) -> Self::Writer {
        RingBufferWriter
    }

    fn make_writer_for(&self, _meta: &tracing::Metadata<'_>) -> Self::Writer {
        RingBufferWriter
    }
}

fn init_log_subscriber() {
    LOG_INIT.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(LogWriterFactory)
            .with_ansi(false)
            .with_target(true)
            .with_level(true)
            .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339());
        let _ = tracing_subscriber::registry().with(layer).try_init();
    });
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────

fn set_error_msg(msg: &str) {
    let bytes = msg.as_bytes();
    let mut msg_buf = ERROR_MSG.lock().unwrap();
    let len = bytes.len();
    msg_buf.resize(len, 0);
    msg_buf[..len].copy_from_slice(bytes);
}

fn set_err_msg_ptr(err_msg: *mut *const c_char, msg: &str) {
    if err_msg.is_null() {
        return;
    }
    if let Ok(cstr) = CString::new(msg) {
        unsafe {
            *err_msg = cstr.into_raw();
        }
    }
}

fn get_instance_id() -> Option<uuid::Uuid> {
    INSTANCE_NAME_ID_MAP
        .iter()
        .next()
        .map(|entry| *entry.value())
}

// ── 新版 C FFI（对齐参考项目 easytier_ios.h）──────────────────────────────

/// # Safety
/// Initialize logger with file path, level, and os_log subsystem.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_logger(
    path: *const c_char,
    level: *const c_char,
    subsystem: *const c_char,
    err_msg: *mut *const c_char,
) -> i32 {
    if !path.is_null() {
        let path_str = unsafe { CStr::from_ptr(path).to_string_lossy().into_owned() };
        let mut log_path = LOG_FILE_PATH.lock().unwrap();
        *log_path = Some(path_str);
    }
    init_log_subscriber();
    0
}

/// # Safety
/// Run network instance with TOML config string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn run_network_instance(
    cfg_str: *const c_char,
    err_msg: *mut *const c_char,
) -> i32 {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        CStr::from_ptr(cfg_str).to_string_lossy().into_owned()
    };
    let cfg = match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            let msg = format!("failed to parse config: {}", e);
            set_error_msg(&msg);
            set_err_msg_ptr(err_msg, &msg);
            return -1;
        }
    };

    let inst_name = cfg.get_inst_name();

    init_log_subscriber();
    STOP_REQUESTED.store(false, Ordering::SeqCst);

    if INSTANCE_NAME_ID_MAP.contains_key(&inst_name) {
        let msg = "instance already exists";
        set_error_msg(msg);
        set_err_msg_ptr(err_msg, msg);
        return -1;
    }

    let instance_id =
        match INSTANCE_MANAGER.run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG) {
            Ok(id) => id,
            Err(e) => {
                let msg = format!("failed to start instance: {}", e);
                set_error_msg(&msg);
                set_err_msg_ptr(err_msg, &msg);
                return -1;
            }
        };

    INSTANCE_NAME_ID_MAP.insert(inst_name, instance_id);
    0
}

/// Stop the running network instance.
#[unsafe(no_mangle)]
pub extern "C" fn stop_network_instance() -> i32 {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    if let Err(e) = INSTANCE_MANAGER.retain_network_instance(Vec::new()) {
        set_error_msg(&format!("failed to stop instances: {}", e));
        return -1;
    }
    INSTANCE_NAME_ID_MAP.clear();
    0
}

/// # Safety
/// Set the TUN file descriptor for the running instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn set_tun_fd(fd: i32, err_msg: *mut *const c_char) -> i32 {
    let inst_id = match get_instance_id() {
        Some(id) => id,
        None => {
            let msg = "no running instance";
            set_error_msg(msg);
            set_err_msg_ptr(err_msg, msg);
            return -1;
        }
    };

    match INSTANCE_MANAGER.set_tun_fd(&inst_id, fd) {
        Ok(_) => 0,
        Err(e) => {
            let msg = format!("failed to set tun fd: {}", e);
            set_error_msg(&msg);
            set_err_msg_ptr(err_msg, &msg);
            -1
        }
    }
}

/// # Safety
/// Register a callback that fires when the Rust core stops.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn register_stop_callback(
    callback: Option<unsafe extern "C" fn()>,
    err_msg: *mut *const c_char,
) -> i32 {
    if callback.is_none() {
        return 0;
    }
    let cb = callback.unwrap();

    // Spawn a thread that polls STOP_REQUESTED
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                unsafe { cb() };
                break;
            }
            // Also check if instance manager has no running instances
            if INSTANCE_NAME_ID_MAP.is_empty() {
                unsafe { cb() };
                break;
            }
        }
    });

    0
}

/// # Safety
/// Register a callback that fires when running info changes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn register_running_info_callback(
    callback: Option<unsafe extern "C" fn()>,
    err_msg: *mut *const c_char,
) -> i32 {
    if callback.is_none() {
        return 0;
    }
    let cb = callback.unwrap();

    // Spawn a thread that periodically polls for running info changes
    // The actual implementation in the reference project uses GlobalCtxEvent subscriptions.
    // Here we use a simpler polling approach since we don't have direct access to the event system.
    std::thread::spawn(move || {
        // Wait for instance to be running
        std::thread::sleep(std::time::Duration::from_secs(2));
        // Fire once after initial setup to trigger applySettingsNow
        unsafe { cb() }

        // Then poll every 30 seconds for route changes
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if STOP_REQUESTED.load(Ordering::SeqCst) || INSTANCE_NAME_ID_MAP.is_empty() {
                break;
            }
            unsafe { cb() }
        }
    });

    0
}

/// # Safety
/// Get the running info as a JSON string. Caller must free with free_string().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_running_info(
    json: *mut *const c_char,
    err_msg: *mut *const c_char,
) -> i32 {
    if json.is_null() {
        return -1;
    }

    let collected = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(e) => {
            let msg = format!("failed to collect running info: {}", e);
            set_error_msg(&msg);
            set_err_msg_ptr(err_msg, &msg);
            unsafe { *json = std::ptr::null() };
            return -1;
        }
    };

    // Combine all instance infos into a single JSON object
    let combined: serde_json::Value = if collected.len() == 1 {
        // Single instance: return its info directly
        let info = collected.into_values().next().unwrap();
        serde_json::to_value(&info).unwrap_or(serde_json::Value::Null)
    } else if collected.is_empty() {
        serde_json::Value::Null
    } else {
        // Multiple instances: return as array
        let values: Vec<serde_json::Value> = collected
            .into_values()
            .filter_map(|info| serde_json::to_value(&info).ok())
            .collect();
        serde_json::Value::Array(values)
    };

    let json_str = serde_json::to_string(&combined).unwrap_or_else(|_| "{}".to_string());
    unsafe {
        *json = CString::new(json_str).unwrap().into_raw();
    }

    0
}

/// # Safety
/// Get the latest error message. Caller must free with free_string().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_latest_error_msg(
    msg: *mut *const c_char,
    err_msg: *mut *const c_char,
) -> i32 {
    if msg.is_null() {
        return -1;
    }

    let msg_buf = ERROR_MSG.lock().unwrap();
    if msg_buf.is_empty() {
        unsafe { *msg = std::ptr::null() };
        return 0;
    }

    if let Ok(cstr) = CString::new(&msg_buf[..]) {
        unsafe {
            *msg = cstr.into_raw();
        }
    } else {
        unsafe { *msg = std::ptr::null() };
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *const c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s as *mut c_char);
    }
}

// ── 旧版 C FFI（保持向后兼容）──────────────────────────────────────────────

/// # Safety
/// Parse the config
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_config(cfg_str: *const c_char) -> i32 {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        CStr::from_ptr(cfg_str).to_string_lossy().into_owned()
    };

    if let Err(e) = TomlConfigLoader::new_from_str(&cfg_str) {
        set_error_msg(&format!("failed to parse config: {:?}", e));
        return -1;
    }

    0
}

/// # Safety
/// Get the last error message (legacy API)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_error_msg(out: *mut *const c_char) {
    let msg_buf = ERROR_MSG.lock().unwrap();
    if msg_buf.is_empty() {
        unsafe {
            *out = std::ptr::null();
        }
        return;
    }
    if let Ok(cstr) = CString::new(&msg_buf[..]) {
        unsafe {
            *out = cstr.into_raw();
        }
    }
}

/// # Safety
/// Export core logs as JSON array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_core_logs() -> *mut c_char {
    let buffer = LOG_BUFFER.lock().unwrap();
    let content = String::from_utf8_lossy(&buffer);

    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.is_empty())
        .enumerate()
        .map(|(i, line)| {
            let (timestamp, level, rest) = parse_tracing_line(line);
            let (target, message) = parse_target_message(&rest);
            serde_json::json!({
                "id": i.to_string(),
                "timestamp": timestamp,
                "level": level,
                "message": message,
                "tag": target,
            })
        })
        .collect();

    let json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
    CString::new(json).unwrap().into_raw()
}

/// # Safety
/// Retain the network instance (legacy API)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn retain_network_instance(
    inst_names: *const *const c_char,
    length: usize,
) -> i32 {
    if length == 0 {
        if let Err(e) = INSTANCE_MANAGER.retain_network_instance(Vec::new()) {
            set_error_msg(&format!("failed to retain instances: {}", e));
            return -1;
        }
        INSTANCE_NAME_ID_MAP.clear();
        return 0;
    }

    let inst_names = unsafe {
        assert!(!inst_names.is_null());
        std::slice::from_raw_parts(inst_names, length)
            .iter()
            .map(|&name| {
                assert!(!name.is_null());
                CStr::from_ptr(name).to_string_lossy().into_owned()
            })
            .collect::<Vec<_>>()
    };

    let inst_ids: Vec<uuid::Uuid> = inst_names
        .iter()
        .filter_map(|name| INSTANCE_NAME_ID_MAP.get(name).map(|id| *id))
        .collect();

    if let Err(e) = INSTANCE_MANAGER.retain_network_instance(inst_ids) {
        set_error_msg(&format!("failed to retain instances: {}", e));
        return -1;
    }

    INSTANCE_NAME_ID_MAP.retain(|k, _| inst_names.contains(k));

    0
}

/// # Safety
/// Collect the network infos (legacy API)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> i32 {
    if max_length == 0 {
        return 0;
    }

    let infos = unsafe {
        assert!(!infos.is_null());
        std::slice::from_raw_parts_mut(infos, max_length)
    };

    let collected_infos = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(e) => {
            set_error_msg(&format!("failed to collect network infos: {}", e));
            return -1;
        }
    };

    let mut index = 0;
    for (instance_id, value) in collected_infos.iter() {
        if index >= max_length {
            break;
        }
        let Some(key) = INSTANCE_MANAGER.get_instance_name(instance_id) else {
            continue;
        };
        let value = match serde_json::to_string(&value) {
            Ok(value) => value,
            Err(e) => {
                set_error_msg(&format!("failed to serialize instance info: {}", e));
                return -1;
            }
        };

        infos[index] = KeyValuePair {
            key: CString::new(key).unwrap().into_raw(),
            value: CString::new(value).unwrap().into_raw(),
        };
        index += 1;
    }

    index as i32
}

// ── 日志解析辅助 ──────────────────────────────────────────────────────────

fn parse_tracing_line(line: &str) -> (String, String, String) {
    // The tracing timestamp may contain spaces (e.g., "2026-06-28 14:50:01"),
    // so simple whitespace-splitting misidentifies the level. Instead, locate
    // the level keyword as a standalone word in the line.
    let level_keywords = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    for keyword in level_keywords {
        if let Some(pos) = line.find(keyword) {
            let before_ok =
                pos == 0 || line.as_bytes().get(pos - 1).map_or(false, |b| b.is_ascii_whitespace());
            let after = pos + keyword.len();
            let after_ok = after >= line.len()
                || line.as_bytes().get(after).map_or(false, |b| b.is_ascii_whitespace());
            if before_ok && after_ok {
                let timestamp = line[..pos].trim_end().to_string();
                let rest = line[after..].trim_start().to_string();
                return (timestamp, keyword.to_string(), rest);
            }
        }
    }
    (line.to_string(), "INFO".to_string(), String::new())
}

fn parse_target_message(rest: &str) -> (String, String) {
    let trimmed = rest.trim_start();
    // Find the first ": " (colon-space) to separate target from message,
    // avoiding splitting on Rust path separators "::".
    if let Some(pos) = trimmed.find(": ") {
        let target = trimmed[..pos].trim().to_string();
        let message = trimmed[pos + 2..].trim().to_string();
        (target, message)
    } else {
        (String::new(), trimmed.to_string())
    }
}

#[repr(C)]
pub struct KeyValuePair {
    pub key: *const c_char,
    pub value: *const c_char,
}

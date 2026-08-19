use crate::{
    collect_network_infos_inner, get_core_logs_inner, get_latest_error_msg_inner,
    parse_config_inner, run_network_instance_inner, set_tun_fd_inner, stop_network_instance_inner,
};

#[flutter_rust_bridge::frb(sync)] // Synchronous mode for simple calls
pub fn parse_config(config_str: String) -> String {
    match parse_config_inner(&config_str) {
        Ok(()) => "ok".to_string(),
        Err(e) => e,
    }
}

pub fn run_network_instance(config_json: String) -> bool {
    run_network_instance_inner(&config_json).is_ok()
}

pub fn set_tun_fd(fd: i32) -> bool {
    set_tun_fd_inner(fd).is_ok()
}

pub fn stop_network_instance() -> bool {
    stop_network_instance_inner().is_ok()
}

pub fn collect_network_infos() -> String {
    collect_network_infos_inner().unwrap_or_else(|_| "{}".to_string())
}

pub fn get_latest_error_msg() -> String {
    get_latest_error_msg_inner().unwrap_or_default()
}

// Log rotation/export
pub fn get_core_logs() -> String {
    get_core_logs_inner()
}

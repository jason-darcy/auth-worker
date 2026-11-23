//! Logging helpers.
//!
//! `worker::console_*!` expand to `web_sys` calls, which abort the process when
//! the crate is built for the host target. Unit tests run on the host, so on
//! non-wasm targets the same macros fall back to `eprintln!`.

#[cfg(target_arch = "wasm32")]
macro_rules! log_info {
    ($($arg:tt)*) => {
        worker::console_log!($($arg)*)
    };
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! log_info {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}

#[cfg(target_arch = "wasm32")]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        worker::console_warn!($($arg)*)
    };
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}

#[cfg(target_arch = "wasm32")]
macro_rules! log_error {
    ($($arg:tt)*) => {
        worker::console_error!($($arg)*)
    };
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}

pub(crate) use log_error;
pub(crate) use log_info;
pub(crate) use log_warn;

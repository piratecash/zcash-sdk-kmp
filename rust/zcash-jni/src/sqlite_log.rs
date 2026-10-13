//! Registers SQLite's error log with rlz's ring. The FFI call lives here, the ring's rules in rlz.

use libsqlite3_sys::{sqlite3_config, SQLITE_CONFIG_LOG};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::panic::catch_unwind;
use std::sync::OnceLock;

/// Once per process; SQLite's rc, `SQLITE_OK` when the log is installed.
pub(crate) fn install() -> i32 {
    static RC: OnceLock<i32> = OnceLock::new();
    *RC.get_or_init(|| {
        let log: extern "C" fn(*mut c_void, c_int, *const c_char) = callback;
        // SAFETY: SQLITE_CONFIG_LOG takes exactly a log function and its context pointer.
        unsafe { sqlite3_config(SQLITE_CONFIG_LOG, log, std::ptr::null_mut::<c_void>()) }
    })
}

/// Unwinding into SQLite's C frames would be undefined behaviour.
extern "C" fn callback(_context: *mut c_void, code: c_int, message: *const c_char) {
    let _ = catch_unwind(|| {
        if message.is_null() {
            return;
        }
        // SAFETY: SQLite passes a NUL-terminated string valid for the duration of the call.
        let text = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        rlz::api::sqlite_log::record(code, &text);
    });
}

/// A real `sqlx::Error::Database` with code 14, as an open in a missing directory produces it.
#[cfg(test)]
pub(crate) fn cantopen_error() -> anyhow::Error {
    use sqlx::ConnectOptions;
    let missing = std::env::temp_dir()
        .join(format!("zcash-jni-missing-{}", std::process::id()))
        .join("wallet.sqlite3");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(missing)
                .create_if_missing(true)
                .connect(),
        )
        .expect_err("a database in a missing directory cannot be opened")
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_routes_sqlite_os_errors_into_the_ring() {
        assert_eq!(libsqlite3_sys::SQLITE_OK, install());

        cantopen_error();

        let log = rlz::api::sqlite_log::snapshot();
        // Windows logs `winOpen(`.
        assert!(
            log.iter()
                .any(|e| e.to_lowercase().contains("open(*.sqlite3)")),
            "{log:?}"
        );
    }
}

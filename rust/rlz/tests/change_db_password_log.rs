//! Its own test binary: statements log on SQLx's worker thread, so only a process-wide
//! subscriber sees them.
use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions, Connection};
use std::io::Write;
use std::sync::{Arc, Mutex};

const OLD_PASSWORD: &str = "old-password-probe";
const NEW_PASSWORD: &str = "new-password-probe";
const CONTROL_STATEMENT: &str = "SELECT 'statement-log-control'";

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn change_db_password_statement_log_carries_neither_password() {
    let captured = CapturedLog::default();
    let writer = captured.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .init();

    let directory =
        std::env::temp_dir().join(format!("rlz-change-password-log-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("wallet.db");
    let mut connection = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .pragma("key", format!("'{OLD_PASSWORD}'"))
        .disable_statement_logging()
        .connect()
        .await
        .expect("create the encrypted database");
    sqlx::query("CREATE TABLE t(v)")
        .execute(&mut connection)
        .await
        .expect("create a table");
    connection.close().await.expect("close");

    rlz::db::change_db_password(
        path.to_str().expect("utf-8 path"),
        directory.to_str().expect("utf-8 path"),
        OLD_PASSWORD,
        NEW_PASSWORD,
    )
    .await
    .expect("change the password");

    // A plain connection proves the capture sees statements at all.
    let mut control = SqliteConnectOptions::new()
        .in_memory(true)
        .connect()
        .await
        .expect("control connection");
    sqlx::query(CONTROL_STATEMENT)
        .execute(&mut control)
        .await
        .expect("control statement");
    control.close().await.expect("close");
    std::fs::remove_dir_all(&directory).expect("clean up");

    let log = String::from_utf8(captured.0.lock().unwrap().clone()).expect("utf-8 log");
    assert!(log.contains("statement-log-control"), "capture saw nothing");
    assert!(!log.contains(OLD_PASSWORD), "old password logged");
    assert!(!log.contains(NEW_PASSWORD), "new password logged");
}

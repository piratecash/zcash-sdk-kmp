//! SQLite's own error log, kept in a small in-process ring so errno and syscall reach the caller.
//!
//! Everything SQLite logs can carry SQL text (the key pragma) and file paths (the account id), so
//! each message is sanitized before it is stored.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

const CAPACITY: usize = 16;
pub(crate) const SQLITE_CANTOPEN: i32 = 14;
const SQLITE_NOTICE: i32 = 27;
const SQLITE_WARNING: i32 = 28;
/// Text of `sqlite3CantopenError`, which every `SQLITE_CANTOPEN_BKPT` goes through.
const CANTOPEN_BREAKPOINT: &str = "cannot open file at line";
const DESCRIBE_WINDOW: Duration = Duration::from_secs(10);
const DB_SUFFIXES: [&str; 4] = [
    ".sqlite3",
    ".sqlite3-journal",
    ".sqlite3-wal",
    ".sqlite3-shm",
];
/// Ends the path in SQLite's os-layer format `%s(%s) - %s`. The last one is taken: errno text never
/// holds it, while a directory name may.
const OS_ERROR_DELIMITER: &str = ") - ";
/// Ends a path SQLite quotes, as in `attempt to open "%s" as file descriptor %d`; the last quote,
/// since a directory name may hold one.
const QUOTE: &str = "\"";
const MIN_HEX_RUN: usize = 16;

static RING: Mutex<LogRing> = Mutex::new(LogRing::new());
static NATIVE_CANTOPEN: AtomicU64 = AtomicU64::new(0);

struct Entry {
    at: Instant,
    code: i32,
    text: String,
}

impl Entry {
    fn render(&self) -> String {
        format!("{}: {}", self.code, self.text)
    }
}

struct LogRing {
    entries: VecDeque<Entry>,
}

impl LogRing {
    const fn new() -> Self {
        LogRing {
            entries: VecDeque::new(),
        }
    }

    fn push(&mut self, at: Instant, code: i32, text: String) {
        if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry { at, code, text });
    }

    fn recent(&self, now: Instant, window: Duration) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| now.saturating_duration_since(e.at) <= window)
            .map(Entry::render)
            .collect()
    }

    fn snapshot(&self) -> Vec<String> {
        self.entries.iter().map(Entry::render).collect()
    }

    fn last_error(&self) -> Option<String> {
        self.entries
            .iter()
            .rev()
            .find(|e| !matches!(e.code & 0xff, SQLITE_NOTICE | SQLITE_WARNING))
            .map(Entry::render)
    }
}

/// A panic elsewhere must not poison the log and silence every later entry.
fn ring() -> MutexGuard<'static, LogRing> {
    RING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The single entry point, called from SQLite's log callback on any thread.
pub fn record(code: i32, message: &str) {
    if code & 0xff == SQLITE_CANTOPEN && message.starts_with(CANTOPEN_BREAKPOINT) {
        NATIVE_CANTOPEN.fetch_add(1, Ordering::Relaxed);
    }
    let text = sanitize(message);
    ring().push(Instant::now(), code, text);
}

/// `SQLITE_CANTOPEN_BKPT` emissions, not distinct failures: an `lstat` failure emits twice.
pub fn native_cantopen() -> u64 {
    NATIVE_CANTOPEN.load(Ordering::Relaxed)
}

/// Entries newer than `window`, oldest first, each as `<code>: <text>`.
pub fn recent(window: Duration) -> Vec<String> {
    ring().recent(Instant::now(), window)
}

pub fn snapshot() -> Vec<String> {
    ring().snapshot()
}

/// The latest entry that is neither `SQLITE_NOTICE` nor `SQLITE_WARNING`.
pub fn last_error() -> Option<String> {
    ring().last_error()
}

/// The one formatter for every error that crosses to Kotlin: a database error carries SQLite's
/// recent log as a ` [sqlite: …]` tail.
pub fn describe(err: &anyhow::Error) -> String {
    let message = format!("{err:#}");
    if !is_database_error(err) {
        return message;
    }
    let recent = recent(DESCRIBE_WINDOW);
    if recent.is_empty() {
        return message;
    }
    format!("{message} [sqlite: {}]", recent.join(" | "))
}

fn is_database_error(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        matches!(
            e.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::Database(_))
        )
    })
}

fn sanitize(message: &str) -> String {
    redact_paths(&redact_hex(&redact_sql(message)))
}

/// SQLite echoes SQL as `%s in "%s"` (parser) and `statement aborts at %d: [%s] %s`.
fn redact_sql(message: &str) -> String {
    let message = match message.find(" in \"") {
        Some(start) => format!("{} <sql>", &message[..start]),
        None => message.to_string(),
    };
    match (message.find('['), message.rfind(']')) {
        (Some(open), Some(close)) if open < close => {
            format!("{}<sql>{}", &message[..open], &message[close + 1..])
        }
        _ => message,
    }
}

fn redact_hex(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut run = String::new();
    for c in message.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        flush_hex_run(&mut out, &mut run);
        out.push(c);
    }
    flush_hex_run(&mut out, &mut run);
    out
}

fn flush_hex_run(out: &mut String, run: &mut String) {
    out.push_str(if run.len() >= MIN_HEX_RUN {
        "<hex>"
    } else {
        run.as_str()
    });
    run.clear();
}

/// Default-deny: no character of a path survives except a known database suffix.
pub fn redact_paths(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some((start, opener)) = path_start(rest) {
        out.push_str(&rest[..start]);
        let path = &rest[start..];
        let end = if opener == Some('"') {
            QUOTE
        } else {
            OS_ERROR_DELIMITER
        };
        let len = path.rfind(end).unwrap_or(path.len());
        out.push_str(&redacted(&path[..len]));
        rest = &path[len..];
    }
    out.push_str(rest);
    out
}

/// A root counts after anything that cannot continue a path word, so no SQLite format is missed.
fn path_start(s: &str) -> Option<(usize, Option<char>)> {
    let mut previous = None;
    for (i, c) in s.char_indices() {
        if !previous.is_some_and(is_path_word_char) && is_path_root(&s[i..]) {
            return Some((i, previous));
        }
        previous = Some(c);
    }
    None
}

fn is_path_word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '~' | '/' | '\\')
}

fn is_path_root(s: &str) -> bool {
    let bytes = s.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    s.starts_with('/') || s.starts_with("\\\\") || windows_drive
}

fn redacted(path: &str) -> String {
    DB_SUFFIXES
        .iter()
        .find(|suffix| path.ends_with(*suffix))
        .map_or_else(|| "<path>".to_string(), |suffix| format!("*{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::ConnectOptions;

    const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// `NATIVE_CANTOPEN` is process-wide; the tests that read it must not interleave.
    static COUNTER_TESTS: Mutex<()> = Mutex::new(());

    async fn database_error() -> anyhow::Error {
        let missing = std::env::temp_dir()
            .join(format!("rlz-sqlite-log-missing-{}", std::process::id()))
            .join("wallet.sqlite3");
        SqliteConnectOptions::new()
            .filename(missing)
            .create_if_missing(true)
            .connect()
            .await
            .expect_err("a database in a missing directory cannot be opened")
            .into()
    }

    #[test]
    fn redact_paths_absolute_db_path_keeps_only_the_suffix() {
        assert_eq!(
            "os_unix.c:44000: (2) open(*.sqlite3) - No such file or directory",
            redact_paths(
                "os_unix.c:44000: (2) open(/data/user/0/cash.p.terminal/no_backup/zcash/wallet_7.sqlite3) - No such file or directory"
            )
        );
        assert_eq!(
            "os_unix.c:44000: (13) open(*.sqlite3-journal) - Permission denied",
            redact_paths(
                "os_unix.c:44000: (13) open(/data/user/0/x/wallet_7.sqlite3-journal) - Permission denied"
            )
        );
    }

    #[test]
    fn redact_paths_intermediate_directory_becomes_path_marker() {
        assert_eq!(
            "lstat(<path>) - No such file",
            redact_paths("lstat(/data/user/0/x/no_backup) - No such file")
        );
    }

    #[test]
    fn redact_paths_dotted_directory_leaves_no_fragment() {
        assert_eq!(
            "lstat(<path>) - Permission denied",
            redact_paths("lstat(/Users/John.Smith) - Permission denied")
        );
    }

    #[test]
    fn redact_paths_windows_path_with_spaces_and_parens_keeps_only_the_suffix() {
        assert_eq!(
            "os_win.c:1: (3) winOpen(*.sqlite3) - The system cannot find the path specified.",
            redact_paths(
                "os_win.c:1: (3) winOpen(C:\\Users\\John (Work)\\wallet_1.sqlite3) - The system cannot find the path specified."
            )
        );
        assert_eq!(
            "winOpen(*.sqlite3-wal) - Access is denied.",
            redact_paths("winOpen(C:/Users/John Smith/wallet_1.sqlite3-wal) - Access is denied.")
        );
    }

    #[test]
    fn redact_paths_unc_path_keeps_only_the_suffix() {
        assert_eq!(
            "winOpen(*.sqlite3-shm) - Access is denied.",
            redact_paths(
                "winOpen(\\\\server\\share\\John (Work)\\wallet_1.sqlite3-shm) - Access is denied."
            )
        );
    }

    #[test]
    fn redact_paths_directory_containing_the_delimiter_leaks_nothing() {
        assert_eq!(
            "open(*.sqlite3) - No such file or directory",
            redact_paths(
                "open(/tmp/Personal) - Alice/wallet_7.sqlite3) - No such file or directory"
            )
        );
    }

    #[test]
    fn redact_paths_quoted_path_keeps_only_the_suffix_and_the_rest_of_the_message() {
        assert_eq!(
            "attempt to open \"*.sqlite3\" as file descriptor 0",
            redact_paths(
                "attempt to open \"/data/user/0/cash.p.terminal/no_backup/zcash/wallet_7.sqlite3\" as file descriptor 0"
            )
        );
    }

    #[test]
    fn redact_paths_quoted_directory_containing_a_quote_leaks_nothing() {
        assert_eq!(
            "attempt to open \"*.sqlite3\" as file descriptor 1",
            redact_paths("attempt to open \"/tmp/Alice\"s/wallet_7.sqlite3\" as file descriptor 1")
        );
    }

    #[test]
    fn redact_paths_path_after_any_separator_is_redacted() {
        for (message, expected) in [
            ("path=/home/alice/notes", "path=<path>"),
            ("'/home/alice/notes'", "'<path>"),
            ("[/home/alice/notes]", "[<path>"),
        ] {
            assert_eq!(expected, redact_paths(message));
        }
    }

    #[test]
    fn redact_paths_path_at_the_end_of_the_message_is_redacted_to_the_end() {
        assert_eq!(
            "file unlinked while open: *.sqlite3",
            redact_paths("file unlinked while open: /a/wallet_1.sqlite3")
        );
    }

    #[test]
    fn redact_paths_message_without_a_path_is_unchanged() {
        for message in [
            "database is locked",
            "os_unix.c:44000: (5) read(<fd>) - Input/output error",
            "cannot open file at line 44000 of [abc]",
        ] {
            assert_eq!(message, redact_paths(message));
        }
    }

    #[test]
    fn redact_paths_several_paths_in_one_message_are_each_redacted() {
        assert_eq!(
            "open(*.sqlite3) - renamed to <path>",
            redact_paths("open(/a/wallet_1.sqlite3) - renamed to /b/c")
        );
        // Two os-layer segments merge into one token: over-redacted, never leaked.
        assert_eq!(
            "open(<path>) - Permission denied",
            redact_paths(
                "open(/a/wallet_1.sqlite3) - No such file | lstat(/b/c d) - Permission denied"
            )
        );
    }

    #[test]
    fn sanitize_parser_error_with_key_pragma_drops_the_sql() {
        let sanitized = sanitize(&format!(
            "near \"x\": syntax error in \"PRAGMA key = \"x'{KEY_HEX}'\"\""
        ));

        assert!(!sanitized.contains(&KEY_HEX[..16]), "{sanitized}");
        assert!(!sanitized.contains("PRAGMA key"), "{sanitized}");
        assert!(
            sanitized.starts_with("near \"x\": syntax error"),
            "{sanitized}"
        );
    }

    #[test]
    fn sanitize_statement_aborts_drops_bracketed_sql() {
        let sanitized = sanitize(&format!(
            "statement aborts at 3: [PRAGMA key = \"x'{KEY_HEX}'\"] file is not a database"
        ));

        assert!(!sanitized.contains(&KEY_HEX[..16]), "{sanitized}");
        assert!(!sanitized.contains("PRAGMA"), "{sanitized}");
        assert!(sanitized.ends_with("file is not a database"), "{sanitized}");
    }

    #[test]
    fn sanitize_long_hex_run_anywhere_is_removed() {
        assert_eq!(
            "unexpected key <hex> near line 44000",
            sanitize(&format!("unexpected key {KEY_HEX} near line 44000"))
        );
    }

    #[test]
    fn log_ring_recent_drops_entries_outside_the_window() {
        let start = Instant::now();
        let mut ring = LogRing::new();
        ring.push(start, 14, "old".to_string());
        ring.push(start + Duration::from_secs(15), 14, "new".to_string());

        assert_eq!(
            vec!["14: new".to_string()],
            ring.recent(start + Duration::from_secs(20), Duration::from_secs(10))
        );
    }

    #[test]
    fn log_ring_last_error_skips_notice_and_warning() {
        let now = Instant::now();
        let mut ring = LogRing::new();
        ring.push(now, 14, "cantopen".to_string());
        ring.push(now, 27 | (1 << 8), "recovered wal".to_string());
        ring.push(now, 28, "automatic index".to_string());

        assert_eq!(Some("14: cantopen".to_string()), ring.last_error());
    }

    #[test]
    fn log_ring_capacity_evicts_oldest() {
        let now = Instant::now();
        let mut ring = LogRing::new();
        for i in 0..=CAPACITY {
            ring.push(now, 14, format!("entry {i}"));
        }

        let snapshot = ring.snapshot();
        assert_eq!(CAPACITY, snapshot.len());
        assert_eq!("14: entry 1", snapshot[0]);
        assert_eq!(format!("14: entry {CAPACITY}"), snapshot[CAPACITY - 1]);
    }

    #[tokio::test]
    async fn describe_database_error_appends_recent_sqlite_log() {
        let error = database_error().await;
        record(
            14,
            "describe-marker open(/a/wallet_1.sqlite3) - No such file",
        );

        let described = describe(&error);

        assert!(
            described.starts_with(&format!("{error:#} [sqlite: ")),
            "{described}"
        );
        assert!(
            described.contains("14: describe-marker open(*.sqlite3) - No such file"),
            "{described}"
        );
    }

    #[test]
    fn describe_non_database_error_is_plain() {
        record(14, "describe-plain-marker");

        assert_eq!(
            "server unreachable",
            describe(&anyhow::anyhow!("server unreachable"))
        );
    }

    #[test]
    fn record_cantopen_breakpoint_message_counts_native_cantopen() {
        let _serial = COUNTER_TESTS.lock().unwrap_or_else(PoisonError::into_inner);
        let before = native_cantopen();

        record(14, "cannot open file at line 44000 of [abcdef0123]");

        assert_eq!(before + 1, native_cantopen());
    }

    #[test]
    fn record_other_code_14_message_does_not_count() {
        let _serial = COUNTER_TESTS.lock().unwrap_or_else(PoisonError::into_inner);
        let before = native_cantopen();

        record(
            14,
            "os_unix.c:44000: (2) open(/a/wallet_1.sqlite3) - No such file or directory",
        );
        record(1, "cannot open file at line 44000 of [abcdef0123]");

        assert_eq!(before, native_cantopen());
    }
}

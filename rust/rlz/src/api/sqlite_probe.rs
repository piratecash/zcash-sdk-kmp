//! One log line of file-system, thread and process facts taken right after a failed open.
//!
//! It runs inside SQLite's log callback, so it uses std file APIs only and never SQLite. It never
//! opens the database file itself: closing a second descriptor of it drops the process's locks.

use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::api::coin::pool_label;
use crate::api::sqlite_log::{self, SQLITE_NOTICE};

pub(crate) const OPEN_THREAD: &str = "open-thread";
pub(crate) const CALLER: &str = "caller";
const WINDOW: Duration = Duration::from_secs(60);
const USER_HZ: f64 = 100.0;
const START_TIME_FIELD: usize = 22;

type Throttle = HashMap<(&'static str, PathBuf), Instant>;

static THROTTLE: LazyLock<Mutex<Throttle>> = LazyLock::new(Default::default);

/// On the thread whose native open just failed.
pub(crate) fn after_failed_open(path: &Path) {
    probe_throttled(OPEN_THREAD, path);
}

/// On the long-lived thread that asked the pool for a connection.
pub(crate) fn after_failed_acquire(path: &Path) {
    probe_throttled(CALLER, path);
}

fn probe_throttled(site: &'static str, path: &Path) {
    let admitted = admit(&mut throttle(), site, path, Instant::now());
    if admitted {
        sqlite_log::record(SQLITE_NOTICE, &probe(site, path));
    }
}

fn throttle() -> MutexGuard<'static, Throttle> {
    THROTTLE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Forgets paths older than the window, so the map only holds recent failures.
fn admit(seen: &mut Throttle, site: &'static str, path: &Path, now: Instant) -> bool {
    seen.retain(|_, at| now.saturating_duration_since(*at) < WINDOW);
    let key = (site, path.to_path_buf());
    if seen.contains_key(&key) {
        return false;
    }
    seen.insert(key, now);
    true
}

/// Numbers only: the path, its file name and the account id never reach the line.
pub(crate) fn probe(site: &str, path: &Path) -> String {
    let facts = ProcFacts::read();
    let (walk, links) = walk(path);
    let (sibling_rw, sibling_ro) = open_sibling(path, &facts.sibling_tag());
    format!(
        "probe site={site} file={} stat={} walk={walk} links={links} siblingRw={sibling_rw} \
         siblingRo={sibling_ro} pid={} {}",
        pool_label(path),
        outcome(fs::metadata(path)),
        std::process::id(),
        facts.render()
    )
}

fn outcome<T>(result: io::Result<T>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(error) => errno(&error),
    }
}

fn errno(error: &io::Error) -> String {
    error
        .raw_os_error()
        .map_or_else(|| "err?".to_string(), |n| format!("err{n}"))
}

/// `lstat` of every ancestor from the root: where it first fails, and every symlink on the way.
fn walk(path: &Path) -> (String, String) {
    let mut ancestors: Vec<&Path> = path
        .ancestors()
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    ancestors.reverse();
    let mut links = Vec::new();
    for (depth, ancestor) in ancestors.into_iter().enumerate() {
        match fs::symlink_metadata(ancestor) {
            Err(error) => return (format!("d{depth}:{}", errno(&error)), joined(links)),
            Ok(meta) if meta.file_type().is_symlink() => links.push(link(depth, ancestor)),
            Ok(_) => {}
        }
    }
    ("ok".to_string(), joined(links))
}

fn link(depth: usize, path: &Path) -> String {
    let target = fs::read_link(path).map_or_else(
        |error| errno(&error),
        |target| target.as_os_str().len().to_string(),
    );
    format!("d{depth}:{target}:{}", outcome(fs::metadata(path)))
}

fn joined(links: Vec<String>) -> String {
    if links.is_empty() {
        "none".to_string()
    } else {
        links.join(",")
    }
}

/// Repeats SQLite's two open attempts on a sibling file, never on the database itself.
/// Created exclusively: a file that already has the sibling's name is never opened or removed.
fn open_sibling(path: &Path, tag: &str) -> (String, String) {
    let Some(parent) = path.parent() else {
        return ("n/a".to_string(), "n/a".to_string());
    };
    let sibling = parent.join(sibling_name(tag));
    let created = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&sibling);
    if let Err(error) = created {
        return (errno(&error), "n/a".to_string());
    }
    let ro = outcome(File::open(&sibling));
    let _ = fs::remove_file(&sibling);
    ("ok".to_string(), ro)
}

fn sibling_name(tag: &str) -> String {
    format!(".rlz-probe-{}-{tag}", std::process::id())
}

struct ProcFacts {
    tid: Option<u64>,
    thread_age: Option<f64>,
    process_age: Option<f64>,
    threads: Option<u64>,
    vm_size_kb: Option<u64>,
    vm_rss_kb: Option<u64>,
}

impl ProcFacts {
    /// Linux only; elsewhere every fact is `n/a`.
    fn read() -> Self {
        let thread = read_proc("/proc/thread-self/stat");
        let process = read_proc("/proc/self/stat");
        let uptime = read_proc("/proc/uptime").as_deref().and_then(uptime_secs);
        let status = read_proc("/proc/self/status").unwrap_or_default();
        let age = |stat: &Option<String>| {
            Some(age_secs(
                uptime?,
                stat_field(stat.as_deref()?, START_TIME_FIELD)?,
            ))
        };
        ProcFacts {
            tid: thread.as_deref().and_then(stat_pid),
            thread_age: age(&thread),
            process_age: age(&process),
            threads: status_value(&status, "Threads"),
            vm_size_kb: status_value(&status, "VmSize"),
            vm_rss_kb: status_value(&status, "VmRSS"),
        }
    }

    /// Unique per thread, so concurrent probes of one directory never share a sibling.
    fn sibling_tag(&self) -> String {
        self.tid.map_or_else(
            || format!("{:?}", thread::current().id()),
            |tid| tid.to_string(),
        )
    }

    fn render(&self) -> String {
        let seconds = |age: Option<f64>| age.map(|s| format!("{s:.2}"));
        format!(
            "tid={} threadAge={} procAge={} threads={} vmSizeKb={} vmRssKb={}",
            or_na(self.tid),
            or_na(seconds(self.thread_age)),
            or_na(seconds(self.process_age)),
            or_na(self.threads),
            or_na(self.vm_size_kb),
            or_na(self.vm_rss_kb)
        )
    }
}

fn or_na<T: Display>(value: Option<T>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| v.to_string())
}

fn read_proc(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn stat_pid(stat: &str) -> Option<u64> {
    stat.split_whitespace().next()?.parse().ok()
}

/// `comm` may hold spaces and parens, so fields are counted after its last `)`; it ends field 2.
fn stat_field(stat: &str, field: usize) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace()
        .nth(field.checked_sub(3)?)?
        .parse()
        .ok()
}

fn uptime_secs(uptime: &str) -> Option<f64> {
    uptime.split_whitespace().next()?.parse().ok()
}

fn status_value(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        line.strip_prefix(key)?
            .strip_prefix(':')?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn age_secs(uptime: f64, start_ticks: u64) -> f64 {
    (uptime - start_ticks as f64 / USER_HZ).max(0.0)
}

#[cfg(test)]
pub(crate) fn throttled(site: &'static str, path: &Path) -> bool {
    throttle().contains_key(&(site, path.to_path_buf()))
}

#[cfg(test)]
pub(crate) fn unique_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rlz-probe-{tag}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(test)]
pub(crate) fn depth(path: &Path) -> usize {
    path.components().count() - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str =
        "4321 (a) (b) S 1 4321 4321 0 -1 4194624 100 0 0 0 5 3 0 0 20 0 7 0 98765 123456789 900";

    #[test]
    fn stat_parsers_comm_with_parens_reads_fields_after_the_last_paren() {
        assert_eq!(Some(4321), stat_pid(STAT));
        assert_eq!(Some(98765), stat_field(STAT, START_TIME_FIELD));
        assert_eq!(Some(7), stat_field(STAT, 20));
    }

    #[test]
    fn status_value_reads_threads_and_memory_in_kb() {
        let status =
            "Name:\tx\nVmSizeMax:\t1 kB\nThreads:\t42\nVmSize:\t  123456 kB\nVmRSS:\t   7890 kB\n";

        assert_eq!(Some(42), status_value(status, "Threads"));
        assert_eq!(Some(123456), status_value(status, "VmSize"));
        assert_eq!(Some(7890), status_value(status, "VmRSS"));
        assert_eq!(None, status_value(status, "VmSwap"));
    }

    #[test]
    fn uptime_and_age_ticks_are_user_hz() {
        let uptime = uptime_secs("350.25 1200.50\n").expect("uptime");

        assert_eq!(350.25, uptime);
        assert_eq!(250.0, age_secs(uptime, 10_025));
    }

    #[test]
    fn admit_once_per_window_per_site_and_path() {
        let mut seen = Throttle::new();
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let wallet = Path::new("/w/a.sqlite3");
        let other = Path::new("/w/b.sqlite3");

        assert!(admit(&mut seen, CALLER, wallet, at(0)));
        assert!(!admit(&mut seen, CALLER, wallet, at(59)));
        assert!(admit(&mut seen, CALLER, other, at(1)));
        assert!(admit(&mut seen, OPEN_THREAD, wallet, at(1)));
        assert!(admit(&mut seen, CALLER, wallet, at(60)));
    }

    #[test]
    fn admit_drops_entries_older_than_the_window() {
        let mut seen = Throttle::new();
        let start = Instant::now();
        admit(&mut seen, CALLER, Path::new("/w/a.sqlite3"), start);
        admit(&mut seen, CALLER, Path::new("/w/b.sqlite3"), start);

        admit(&mut seen, CALLER, Path::new("/w/c.sqlite3"), start + WINDOW);

        assert_eq!(1, seen.len());
    }

    #[test]
    fn probe_missing_directory_reports_errno_and_the_failing_depth() {
        let missing = unique_dir("missing");
        let path = missing.join("wallet.sqlite3");

        let line = probe(CALLER, &path);

        // `file=` is pool_label's: a parallel test holding the registry turns it into `busy`.
        assert!(line.starts_with("probe site=caller file="), "{line}");
        assert!(line.contains(" stat=err2 "), "{line}");
        assert!(
            line.contains(&format!(" walk=d{}:err2 ", depth(&missing))),
            "{line}"
        );
        assert!(line.contains(" siblingRw=err2 siblingRo=n/a "), "{line}");
    }

    #[test]
    fn probe_existing_file_reports_ok_and_removes_the_sibling() {
        let directory = unique_dir("existing");
        fs::create_dir_all(&directory).expect("create the directory");
        let path = directory.join("wallet.sqlite3");
        fs::write(&path, b"").expect("create the file");

        let line = probe(CALLER, &path);

        assert!(line.contains(" stat=ok walk=ok "), "{line}");
        assert!(line.contains(" siblingRw=ok siblingRo=ok "), "{line}");
        let left: Vec<_> = fs::read_dir(&directory)
            .expect("list the directory")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(vec![std::ffi::OsString::from("wallet.sqlite3")], left);
    }

    #[cfg(unix)]
    #[test]
    fn probe_database_named_like_the_sibling_leaves_it_untouched() {
        let directory = unique_dir("sibling-name");
        fs::create_dir_all(&directory).expect("create the directory");
        let path = directory.join(sibling_name(&ProcFacts::read().sibling_tag()));
        fs::write(&path, b"wallet").expect("create the database");

        let line = probe(CALLER, &path);

        assert!(line.contains(" siblingRw=err17 siblingRo=n/a "), "{line}");
        assert_eq!(
            b"wallet".as_slice(),
            fs::read(&path).expect("the database survives")
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_symlinked_directory_reports_its_depth_target_length_and_resolution() {
        let real = unique_dir("real");
        fs::create_dir_all(&real).expect("create the directory");
        let link = unique_dir("link");
        std::os::unix::fs::symlink(&real, &link).expect("link the directory");
        let path = link.join("wallet.sqlite3");
        fs::write(&path, b"").expect("create the file");

        let line = probe(CALLER, &path);

        let expected = format!("d{}:{}:ok", depth(&link), real.as_os_str().len());
        assert!(line.contains(&expected), "{expected} in {line}");
        assert!(line.contains(" walk=ok "), "{line}");
    }

    #[test]
    fn probe_line_contains_no_part_of_the_path() {
        let directory = unique_dir("privacy-marker");
        let path = directory.join("account-marker.sqlite3");

        let line = probe(OPEN_THREAD, &path);

        assert!(line.starts_with("probe site=open-thread "), "{line}");
        let temp = std::env::temp_dir();
        for part in [
            "privacy-marker",
            "account-marker",
            "sqlite3",
            &temp.to_string_lossy(),
        ] {
            assert!(!line.contains(part), "{part} in {line}");
        }
    }
}

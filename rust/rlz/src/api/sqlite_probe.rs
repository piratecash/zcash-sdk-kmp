//! One log line of file-system, thread and process facts taken right after a failed open.
//!
//! It runs inside SQLite's log callback, so it uses std file APIs only and never SQLite. It never
//! opens the database file itself: closing a second descriptor of it drops the process's locks.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::api::coin::pool_match;
use crate::api::sqlite_log::{self, SQLITE_NOTICE};

const WINDOW: Duration = Duration::from_secs(60);
const USER_HZ: f64 = 100.0;
const START_TIME_FIELD: usize = 22;

type Throttle = HashMap<PathBuf, Instant>;

static THROTTLE: LazyLock<Mutex<Throttle>> = LazyLock::new(Default::default);

/// On the thread whose native open just failed.
pub(crate) fn after_failed_open(path: &Path) {
    let admitted = admit(&mut throttle(), path, Instant::now());
    if admitted {
        sqlite_log::record(SQLITE_NOTICE, &probe(path));
    }
}

fn throttle() -> MutexGuard<'static, Throttle> {
    THROTTLE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Forgets paths older than the window, so the map only holds recent failures.
fn admit(seen: &mut Throttle, path: &Path, now: Instant) -> bool {
    seen.retain(|_, at| now.saturating_duration_since(*at) < WINDOW);
    if seen.contains_key(path) {
        return false;
    }
    seen.insert(path.to_path_buf(), now);
    true
}

/// Numbers only: the path, its file name and the account id never reach the line.
pub(crate) fn probe(path: &Path) -> String {
    let (file, real) = pool_match(path);
    let (walk, links) = walk(path);
    format!(
        "probe file={file} stat={} walk={walk} links={links} {} pid={} {}",
        outcome(fs::metadata(path)),
        real_facts(path, real.as_deref()),
        std::process::id(),
        ProcFacts::read().render()
    )
}

/// Our real path, measured on the same failing thread.
fn real_facts(built: &Path, real: Option<&Path>) -> String {
    let Some(real) = real else {
        return "builtDir=n/a realStat=n/a realWalk=n/a realLinks=n/a".to_string();
    };
    let (walk, links) = walk(real);
    format!(
        "builtDir={} realStat={} realWalk={walk} realLinks={links}",
        dir_tokens(built, real),
        outcome(fs::metadata(real))
    )
}

/// Per built directory component: `=` ours at that depth, `r<d>` ours at depth d, else `?<bytes>`.
fn dir_tokens(built: &Path, real: &Path) -> String {
    let real_dir = directory_names(real);
    // Same numbering as `walk=`: the root is d0.
    let first_depth = usize::from(real.has_root());
    let token = |(i, name): (usize, &OsStr)| {
        if real_dir.get(i) == Some(&name) {
            return "=".to_string();
        }
        match real_dir.iter().position(|r| *r == name) {
            Some(j) => format!("r{}", j + first_depth),
            None => format!("?{}", name.len()),
        }
    };
    let tokens: Vec<String> = directory_names(built)
        .into_iter()
        .enumerate()
        .map(token)
        .collect();
    let kind = if built.has_root() { "abs" } else { "rel" };
    format!("{kind}:{}", tokens.join(","))
}

fn directory_names(path: &Path) -> Vec<&OsStr> {
    path.parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect()
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

struct ProcFacts {
    tid: Option<u64>,
    thread_age: Option<f64>,
    process_age: Option<f64>,
}

impl ProcFacts {
    /// Linux only; elsewhere every fact is `n/a`.
    fn read() -> Self {
        let thread = read_proc("/proc/thread-self/stat");
        let process = read_proc("/proc/self/stat");
        let uptime = read_proc("/proc/uptime").as_deref().and_then(uptime_secs);
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
        }
    }

    fn render(&self) -> String {
        let seconds = |age: Option<f64>| age.map(|s| format!("{s:.2}"));
        format!(
            "tid={} threadAge={} procAge={}",
            or_na(self.tid),
            or_na(seconds(self.thread_age)),
            or_na(seconds(self.process_age))
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

fn age_secs(uptime: f64, start_ticks: u64) -> f64 {
    (uptime - start_ticks as f64 / USER_HZ).max(0.0)
}

#[cfg(test)]
pub(crate) fn throttled(path: &Path) -> bool {
    throttle().contains_key(path)
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
    use crate::api::coin::{close_pool, Coin};

    const STAT: &str =
        "4321 (a) (b) S 1 4321 4321 0 -1 4194624 100 0 0 0 5 3 0 0 20 0 7 0 98765 123456789 900";

    /// `busy` only means another test holds the pool registry right now, so sample again.
    fn settled_probe(path: &Path) -> String {
        for _ in 0..5000 {
            let line = probe(path);
            if !line.contains(" file=busy ") {
                return line;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the pool registry stayed locked")
    }

    /// A pool registered at a canonical directory, and a missing directory beside it.
    async fn registered_pool_and_missing_twin(tag: &str) -> (PathBuf, PathBuf) {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonicalize the temp dir");
        let name = format!("{tag}.sqlite3");
        let leaf = |dir: PathBuf| base.join(dir.file_name().expect("a unique name"));
        let real = leaf(unique_dir(&format!("{tag}-real"))).join(&name);
        fs::create_dir_all(real.parent().expect("a parent")).expect("create the directory");
        Coin::new(None)
            .open_database_with_key(real.to_string_lossy().into_owned(), None)
            .await
            .expect("open the pool");
        let built = leaf(unique_dir(&format!("{tag}-built"))).join(&name);
        (real, built)
    }

    #[test]
    fn stat_parsers_comm_with_parens_reads_fields_after_the_last_paren() {
        assert_eq!(Some(4321), stat_pid(STAT));
        assert_eq!(Some(98765), stat_field(STAT, START_TIME_FIELD));
        assert_eq!(Some(7), stat_field(STAT, 20));
    }

    #[test]
    fn uptime_and_age_ticks_are_user_hz() {
        let uptime = uptime_secs("350.25 1200.50\n").expect("uptime");

        assert_eq!(350.25, uptime);
        assert_eq!(250.0, age_secs(uptime, 10_025));
    }

    #[test]
    fn admit_once_per_window_per_path() {
        let mut seen = Throttle::new();
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let wallet = Path::new("/w/a.sqlite3");
        let other = Path::new("/w/b.sqlite3");

        assert!(admit(&mut seen, wallet, at(0)));
        assert!(!admit(&mut seen, wallet, at(59)));
        assert!(admit(&mut seen, other, at(1)));
        assert!(admit(&mut seen, wallet, at(60)));
    }

    #[test]
    fn admit_drops_entries_older_than_the_window() {
        let mut seen = Throttle::new();
        let start = Instant::now();
        admit(&mut seen, Path::new("/w/a.sqlite3"), start);
        admit(&mut seen, Path::new("/w/b.sqlite3"), start);

        admit(&mut seen, Path::new("/w/c.sqlite3"), start + WINDOW);

        assert_eq!(1, seen.len());
    }

    #[test]
    fn dir_tokens_identical_directories_are_all_equal() {
        let tokens = dir_tokens(Path::new("/a/bb/ccc/w.db"), Path::new("/a/bb/ccc/w.db"));

        assert_eq!("abs:=,=,=", tokens);
    }

    #[test]
    fn dir_tokens_truncated_component_reports_its_length() {
        let tokens = dir_tokens(
            Path::new("/data/use/0/w.db"),
            Path::new("/data/user/0/w.db"),
        );

        assert_eq!("abs:=,?3,=", tokens);
    }

    #[test]
    fn dir_tokens_swapped_components_name_their_real_depth() {
        let tokens = dir_tokens(Path::new("/a/c/b/d/w.db"), Path::new("/a/b/c/d/w.db"));

        assert_eq!("abs:=,r3,r2,=", tokens);
    }

    #[test]
    fn dir_tokens_relative_built_path_is_marked_rel() {
        let tokens = dir_tokens(Path::new("b/x/w.db"), Path::new("/a/b/w.db"));

        assert_eq!("rel:r2,?1", tokens);
    }

    #[test]
    fn dir_tokens_built_longer_than_real_reports_the_extra_components() {
        let tokens = dir_tokens(Path::new("/a/b/c/dd/w.db"), Path::new("/a/b/w.db"));

        assert_eq!("abs:=,=,?1,?2", tokens);
    }

    #[test]
    fn dir_tokens_built_shorter_than_real_stops_at_its_own_end() {
        let tokens = dir_tokens(Path::new("/a/c/w.db"), Path::new("/a/b/c/w.db"));

        assert_eq!("abs:=,r3", tokens);
    }

    #[test]
    fn probe_missing_directory_reports_errno_and_the_failing_depth() {
        let missing = unique_dir("missing");
        let path = missing.join("wallet.sqlite3");

        let line = probe(&path);

        // `file=` is pool_match's: a parallel test holding the registry turns it into `busy`.
        assert!(line.starts_with("probe file="), "{line}");
        assert!(line.contains(" stat=err2 "), "{line}");
        assert!(
            line.contains(&format!(" walk=d{}:err2 ", depth(&missing))),
            "{line}"
        );
        assert!(
            line.contains(" builtDir=n/a realStat=n/a realWalk=n/a realLinks=n/a "),
            "{line}"
        );
    }

    #[test]
    fn probe_existing_file_reports_ok() {
        let directory = unique_dir("existing");
        fs::create_dir_all(&directory).expect("create the directory");
        let path = directory.join("wallet.sqlite3");
        fs::write(&path, b"").expect("create the file");

        let line = probe(&path);

        assert!(line.contains(" stat=ok walk=ok "), "{line}");
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

        let line = probe(&path);

        let expected = format!("d{}:{}:ok", depth(&link), real.as_os_str().len());
        assert!(line.contains(&expected), "{expected} in {line}");
        assert!(line.contains(" walk=ok "), "{line}");
    }

    // Unix errno and path components: a missing directory is err3 on Windows, which also has a prefix.
    #[cfg(unix)]
    #[tokio::test]
    async fn probe_failed_path_named_like_a_registered_pool_reports_our_real_path() {
        let (real, built) = registered_pool_and_missing_twin("probe-twin").await;

        let line = settled_probe(&built);
        close_pool(&real.to_string_lossy());

        assert!(line.starts_with("probe file=pool"), "{line}");
        assert!(line.contains("-otherdir stat=err2 "), "{line}");
        let shared = "=,".repeat(depth(real.parent().expect("a parent")) - 1);
        let leaf = built.parent().and_then(Path::file_name).expect("a leaf");
        let tokens = format!(" builtDir=abs:{shared}?{} ", leaf.len());
        assert!(line.contains(&tokens), "{tokens} in {line}");
        assert!(
            line.contains(" realStat=ok realWalk=ok realLinks=none "),
            "{line}"
        );
    }

    #[tokio::test]
    async fn probe_line_contains_no_part_of_the_path() {
        let (real, built) = registered_pool_and_missing_twin("privacy-marker").await;

        let line = settled_probe(&built);
        close_pool(&real.to_string_lossy());

        assert!(line.starts_with("probe file="), "{line}");
        assert!(line.contains(" builtDir=abs:"), "{line}");
        let temp = std::env::temp_dir();
        for part in [
            "privacy-marker",
            "sqlite3",
            &temp.to_string_lossy(),
            &real.parent().expect("a parent").to_string_lossy(),
        ] {
            assert!(!line.contains(part), "{part} in {line}");
        }
    }
}

use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::Result;
#[cfg(not(feature = "bundled-sapling-params"))]
use anyhow::{anyhow, Context};
#[cfg(not(feature = "bundled-sapling-params"))]
use std::{
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    time::Duration,
};

#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;

// Sapling parameter constants — must match those in zcash_proofs.
// Only needed when the parameters are loaded from disk (not bundled).
#[cfg(not(feature = "bundled-sapling-params"))]
const SAPLING_SPEND_NAME: &str = "sapling-spend.params";
#[cfg(not(feature = "bundled-sapling-params"))]
const SAPLING_OUTPUT_NAME: &str = "sapling-output.params";
#[cfg(not(feature = "bundled-sapling-params"))]
const SAPLING_SPEND_HASH: &str =
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
#[cfg(not(feature = "bundled-sapling-params"))]
const SAPLING_OUTPUT_HASH: &str =
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
#[cfg(not(feature = "bundled-sapling-params"))]
const SAPLING_SPEND_BYTES: u64 = 47_958_396;
#[cfg(not(feature = "bundled-sapling-params"))]
const SAPLING_OUTPUT_BYTES: u64 = 3_592_860;
#[cfg(not(feature = "bundled-sapling-params"))]
const DOWNLOAD_URL: &str = "https://download.z.cash/downloads";

/// Custom Sapling parameters directory, set on platforms where
/// `zcash_proofs::default_params_folder()` is not available (e.g. Android).
static SAPLING_PARAMS_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Additional read-only source for already-downloaded parameters, e.g. a
/// legacy ECC SDK install. Never written to — see `ensure_one`.
static LEGACY_PARAMS_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Set a custom directory for Sapling parameters.
///
/// Used on Android where the app's documents directory is passed from Dart
/// so that parameters are stored in a writable location.
#[allow(dead_code)]
pub(crate) fn set_sapling_params_dir(dir: PathBuf) {
    let _ = SAPLING_PARAMS_DIR.set(dir);
}

/// Register an additional directory to look for already-downloaded
/// parameters in (e.g. a legacy ECC SDK install) before downloading.
pub fn set_legacy_params_dir(dir: PathBuf) {
    let _ = LEGACY_PARAMS_DIR.set(dir);
}

/// Resolve the directory Sapling parameters are written to and read from.
///
/// Returns the custom directory if set (via `set_sapling_params_dir`),
/// otherwise falls back to `zcash_proofs::default_params_folder()`.
#[cfg(not(feature = "bundled-sapling-params"))]
fn resolve_params_dir() -> Option<PathBuf> {
    SAPLING_PARAMS_DIR
        .get()
        .cloned()
        .or_else(zcash_proofs::default_params_folder)
}

/// Status of the Sapling proving parameters on disk.
#[cfg_attr(feature = "flutter", frb)]
pub struct SaplingParamsStatus {
    pub downloaded: bool,
}

/// Check whether Sapling parameters are available.
///
/// With `bundled-sapling-params` they are compiled into the binary and always
/// considered available. Otherwise checks whether they are on disk (presence
/// only — no hash check; use `ensure_sapling_params` for a verified path).
#[cfg_attr(feature = "flutter", frb(sync))]
pub fn check_sapling_params() -> SaplingParamsStatus {
    #[cfg(feature = "bundled-sapling-params")]
    {
        return SaplingParamsStatus { downloaded: true };
    }
    #[cfg(not(feature = "bundled-sapling-params"))]
    {
        let downloaded = resolve_params_dir()
            .map(|dir| dir.join(SAPLING_SPEND_NAME).exists() && dir.join(SAPLING_OUTPUT_NAME).exists())
            .unwrap_or(false);
        SaplingParamsStatus { downloaded }
    }
}

/// Resolve local paths to verified Sapling spend/output parameters,
/// downloading (or resuming a download of) whatever is missing or corrupt.
///
/// Skips the network entirely if a valid file already exists in the
/// configured directory or in the legacy directory (see
/// `set_legacy_params_dir`). With `bundled-sapling-params` this is not
/// compiled — parameters are compiled into the binary instead.
#[cfg(not(feature = "bundled-sapling-params"))]
pub(crate) async fn ensure_sapling_params() -> Result<(PathBuf, PathBuf)> {
    // `download_sapling_params` is a second entry point, so two callers could otherwise share
    // one `.part` file: one renames it away while the other still appends through its open fd.
    static DOWNLOAD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = DOWNLOAD_LOCK.lock().await;

    let dir = resolve_params_dir().context("Could not resolve Sapling parameters directory")?;
    let legacy_dir = LEGACY_PARAMS_DIR.get().map(PathBuf::as_path);

    let spend_path = ensure_one(
        &dir,
        legacy_dir,
        SAPLING_SPEND_NAME,
        SAPLING_SPEND_BYTES,
        SAPLING_SPEND_HASH,
    )
    .await?;
    let output_path = ensure_one(
        &dir,
        legacy_dir,
        SAPLING_OUTPUT_NAME,
        SAPLING_OUTPUT_BYTES,
        SAPLING_OUTPUT_HASH,
    )
    .await?;

    Ok((spend_path, output_path))
}

/// Download Sapling parameters from the z.cash download server.
///
/// Safe to call even if they are already downloaded (no-op if valid).
/// With `bundled-sapling-params` the parameters are compiled into the binary
/// and this is a no-op.
#[cfg_attr(feature = "flutter", frb)]
pub async fn download_sapling_params() -> Result<()> {
    #[cfg(feature = "bundled-sapling-params")]
    {
        Ok(())
    }
    #[cfg(not(feature = "bundled-sapling-params"))]
    {
        ensure_sapling_params().await.map(|_| ())
    }
}

/// Resolve a single verified parameter file, preferring (in order): the
/// configured directory, the legacy directory (read-only, never written to),
/// then downloading into the configured directory.
#[cfg(not(feature = "bundled-sapling-params"))]
async fn ensure_one(
    dir: &Path,
    legacy_dir: Option<&Path>,
    name: &str,
    expected_len: u64,
    expected_hash: &str,
) -> Result<PathBuf> {
    let own_path = dir.join(name);
    if verify_file(&own_path, expected_len, expected_hash) {
        return Ok(own_path);
    }
    if let Some(legacy_path) = legacy_dir.map(|d| d.join(name)) {
        if verify_file(&legacy_path, expected_len, expected_hash) {
            return Ok(legacy_path);
        }
    }
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create params directory: {dir:?}"))?;
    download_param_file(dir, name, expected_len, expected_hash).await
}

/// Download `name` into `dir`, resuming a previous `.part` file when
/// possible, then atomically move it into place.
#[cfg(not(feature = "bundled-sapling-params"))]
async fn download_param_file(
    dir: &Path,
    name: &str,
    expected_len: u64,
    expected_hash: &str,
) -> Result<PathBuf> {
    let target = dir.join(name);
    let part = part_path(&target);
    let client = build_download_client()?;
    let url = format!("{DOWNLOAD_URL}/{name}");
    let existing_len = std::fs::metadata(&part).ok().map(|m| m.len());

    match resume_plan(existing_len, expected_len) {
        ResumePlan::Complete if verify_file(&part, expected_len, expected_hash) => {
            finalize_part(&part, &target)?;
            return Ok(target);
        }
        ResumePlan::Complete => {
            let _ = std::fs::remove_file(&part);
            fetch_and_write(&client, &url, &part, None).await?;
        }
        ResumePlan::Restart => fetch_and_write(&client, &url, &part, None).await?,
        ResumePlan::Resume(offset) => fetch_and_write(&client, &url, &part, Some(offset)).await?,
    }

    verify_downloaded_part(&part, expected_len, expected_hash, name)?;
    finalize_part(&part, &target)?;
    Ok(target)
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn build_download_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client")
}

/// Issue the GET (optionally with a `Range` header) and stream the body to
/// `part`. Only appends when `offset` is `Some` *and* the server actually
/// answered `206` — a `206` to a request without `Range` is a full body, not
/// a resume, and appending it would corrupt the file.
#[cfg(not(feature = "bundled-sapling-params"))]
async fn fetch_and_write(
    client: &reqwest::Client,
    url: &str,
    part: &Path,
    offset: Option<u64>,
) -> Result<()> {
    let mut request = client.get(url);
    if let Some(offset) = offset {
        request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
    }
    let mut response = request
        .send()
        .await
        .with_context(|| format!("Failed to request {url}"))?;

    let append = match response.status() {
        reqwest::StatusCode::PARTIAL_CONTENT if offset.is_some() => true,
        reqwest::StatusCode::OK | reqwest::StatusCode::PARTIAL_CONTENT => false,
        reqwest::StatusCode::RANGE_NOT_SATISFIABLE => {
            let _ = std::fs::remove_file(part);
            return Err(anyhow!("{url}: server rejected resume offset (416)"));
        }
        status => return Err(anyhow!("{url}: unexpected HTTP status {status}")),
    };

    let file =
        open_part_file(part, append).with_context(|| format!("Failed to open {part:?} for writing"))?;
    write_response_body(&mut response, file).await
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn open_part_file(part: &Path, append: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    options.open(part)
}

#[cfg(not(feature = "bundled-sapling-params"))]
async fn write_response_body(response: &mut reqwest::Response, file: std::fs::File) -> Result<()> {
    let mut writer = BufWriter::new(file);
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Failed reading response chunk")?
    {
        writer.write_all(&chunk).context("Failed writing chunk to disk")?;
    }
    writer.flush().context("Failed flushing part file")?;
    writer.get_ref().sync_all().context("Failed to fsync part file")?;
    Ok(())
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn verify_downloaded_part(part: &Path, expected_len: u64, expected_hash: &str, name: &str) -> Result<()> {
    if verify_file(part, expected_len, expected_hash) {
        return Ok(());
    }
    // Corrupt bytes can't be resumed on top of — drop them and let the next
    // call start over.
    let _ = std::fs::remove_file(part);
    Err(anyhow!("{name}: downloaded file failed size/hash verification"))
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn finalize_part(part: &Path, target: &Path) -> Result<()> {
    std::fs::rename(part, target)
        .with_context(|| format!("Failed to move {part:?} into place as {target:?}"))
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn part_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(".part");
    PathBuf::from(name)
}

/// Checks a file's length and streamed Blake2b hash against the expected
/// values. Never reads the whole file into memory.
#[cfg(not(feature = "bundled-sapling-params"))]
fn verify_file(path: &Path, expected_len: u64, expected_hash: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() != expected_len {
        return false;
    }
    blake2b_hex(path)
        .map(|hash| hash == expected_hash)
        .unwrap_or(false)
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn blake2b_hex(path: &Path) -> std::io::Result<String> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    let mut state = blake2b_simd::State::new();
    let mut buf = [0u8; 65536];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        state.update(&buf[..read]);
    }
    Ok(hex::encode(state.finalize().as_bytes()))
}

#[cfg(not(feature = "bundled-sapling-params"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumePlan {
    /// No usable `.part` — download from scratch.
    Restart,
    /// Partial `.part` — resume from this byte offset.
    Resume(u64),
    /// `.part` already has the expected length — verify its hash, don't
    /// re-download.
    Complete,
}

#[cfg(not(feature = "bundled-sapling-params"))]
fn resume_plan(existing_len: Option<u64>, expected_len: u64) -> ResumePlan {
    match existing_len {
        Some(len) if len == expected_len => ResumePlan::Complete,
        Some(len) if len > 0 && len < expected_len => ResumePlan::Resume(len),
        _ => ResumePlan::Restart,
    }
}

#[cfg(test)]
#[cfg(not(feature = "bundled-sapling-params"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_file(content: &[u8]) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rlz-sapling-test-{}-{n}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn verify_file_rejects_length_mismatch() {
        let path = temp_file(b"hello");
        assert!(!verify_file(&path, 999, "irrelevant"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn verify_file_rejects_hash_mismatch() {
        let content = b"hello world";
        let path = temp_file(content);
        assert!(!verify_file(&path, content.len() as u64, "0000"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn verify_file_accepts_matching_length_and_hash() {
        let content = b"hello world";
        let path = temp_file(content);
        let expected_hash = hex::encode(blake2b_simd::blake2b(content).as_bytes());
        assert!(verify_file(&path, content.len() as u64, &expected_hash));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn verify_file_rejects_missing_file() {
        let path = std::env::temp_dir().join("rlz-sapling-test-does-not-exist");
        assert!(!verify_file(&path, 10, "irrelevant"));
    }

    #[test]
    fn resume_plan_with_no_file_restarts() {
        assert_eq!(resume_plan(None, 100), ResumePlan::Restart);
    }

    #[test]
    fn resume_plan_with_empty_part_restarts() {
        assert_eq!(resume_plan(Some(0), 100), ResumePlan::Restart);
    }

    #[test]
    fn resume_plan_with_partial_part_resumes_at_offset() {
        assert_eq!(resume_plan(Some(40), 100), ResumePlan::Resume(40));
    }

    #[test]
    fn resume_plan_with_full_length_part_completes() {
        assert_eq!(resume_plan(Some(100), 100), ResumePlan::Complete);
    }

    #[test]
    fn resume_plan_with_overgrown_part_restarts() {
        assert_eq!(resume_plan(Some(150), 100), ResumePlan::Restart);
    }
}

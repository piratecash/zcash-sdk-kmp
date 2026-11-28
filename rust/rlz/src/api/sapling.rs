use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::Result;
#[cfg(not(feature = "bundled-sapling-params"))]
use anyhow::{anyhow, Context};
#[cfg(not(feature = "bundled-sapling-params"))]
use std::{
    io::{BufReader, Read, Write},
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
            fetch_and_write(&client, &url, &part, None, expected_len).await?;
        }
        ResumePlan::Restart => fetch_and_write(&client, &url, &part, None, expected_len).await?,
        ResumePlan::Resume(offset) => {
            fetch_and_write(&client, &url, &part, Some(offset), expected_len).await?
        }
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
    expected_len: u64,
) -> Result<()> {
    let mut request = client.get(url);
    if let Some(offset) = offset {
        request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
    }
    let mut response = request
        .send()
        .await
        .with_context(|| format!("Failed to request {url}"))?;

    let resumed_from = match response.status() {
        reqwest::StatusCode::PARTIAL_CONTENT if offset.is_some() => offset,
        reqwest::StatusCode::OK | reqwest::StatusCode::PARTIAL_CONTENT => None,
        reqwest::StatusCode::RANGE_NOT_SATISFIABLE => {
            let _ = std::fs::remove_file(part);
            return Err(anyhow!("{url}: server rejected resume offset (416)"));
        }
        status => return Err(anyhow!("{url}: unexpected HTTP status {status}")),
    };

    let file = open_part_file(part, resumed_from.is_some())
        .with_context(|| format!("Failed to open {part:?} for writing"))?;
    let max_len = expected_len.saturating_sub(resumed_from.unwrap_or(0));
    write_response_body(&mut response, file, part, max_len).await
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
async fn write_response_body(
    response: &mut reqwest::Response,
    file: std::fs::File,
    part: &Path,
    max_len: u64,
) -> Result<()> {
    match copy_capped(response, file, max_len).await {
        Ok(()) => Ok(()),
        Err(BodyError::Interrupted(error)) => Err(error),
        Err(BodyError::Discard(error)) => match std::fs::remove_file(part) {
            Ok(()) => Err(error),
            Err(remove_error) => {
                Err(error.context(format!("also failed to remove {part:?}: {remove_error}")))
            }
        },
    }
}

#[cfg(not(feature = "bundled-sapling-params"))]
enum BodyError {
    /// The connection broke: what is on disk is a valid prefix to resume from.
    Interrupted(anyhow::Error),
    /// An over-long body or a local disk failure: the file can be neither trusted nor resumed.
    Discard(anyhow::Error),
}

/// Never writes past `max_len`, so an endless body cannot fill the disk before verification.
/// Writes go straight to the file: a buffer's flush on drop would swallow a disk error.
#[cfg(not(feature = "bundled-sapling-params"))]
async fn copy_capped(
    response: &mut reqwest::Response,
    mut file: std::fs::File,
    max_len: u64,
) -> Result<(), BodyError> {
    let mut written = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Failed reading response chunk")
        .map_err(BodyError::Interrupted)?
    {
        written += chunk.len() as u64;
        if written > max_len {
            return Err(BodyError::Discard(anyhow!(
                "Server sent more than the expected {max_len} bytes"
            )));
        }
        file.write_all(&chunk)
            .context("Failed writing chunk to disk")
            .map_err(BodyError::Discard)?;
    }
    file.sync_all()
        .context("Failed to fsync part file")
        .map_err(BodyError::Discard)
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

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("rlz-sapling-test-{}-{n}", std::process::id()))
    }

    fn temp_file(content: &[u8]) -> PathBuf {
        let path = temp_path();
        std::fs::write(&path, content).unwrap();
        path
    }

    fn http_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response =
            format!("HTTP/1.1 {status}\r\n{headers}Connection: close\r\n\r\n").into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// Answers one request with `response` verbatim, then closes the connection.
    async fn serve_once(response: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!(
            "http://{}/params",
            listener.local_addr().expect("local addr")
        );
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            // Drain the request first: closing with unread bytes resets the connection.
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = socket.read(&mut buf).await.expect("read request");
                assert!(read > 0, "client closed before sending the request");
                request.extend_from_slice(&buf[..read]);
            }
            socket.write_all(&response).await.expect("write response");
        });
        url
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
    }

    #[tokio::test]
    async fn fetch_and_write_body_longer_than_expected_fails_and_removes_part() {
        let part = temp_path();
        let url = serve_once(http_response("200 OK", "", &[7; 101])).await;

        assert!(fetch_and_write(&test_client(), &url, &part, None, 100)
            .await
            .is_err());
        assert!(!part.exists());
    }

    #[tokio::test]
    async fn fetch_and_write_resumed_body_longer_than_remainder_fails_and_removes_part() {
        let part = temp_file(&[1; 40]);
        let url = serve_once(http_response("206 Partial Content", "", &[2; 61])).await;

        assert!(fetch_and_write(&test_client(), &url, &part, Some(40), 100)
            .await
            .is_err());
        assert!(!part.exists());
    }

    #[tokio::test]
    async fn fetch_and_write_resumed_body_with_exact_remainder_completes_part() {
        let part = temp_file(&[1; 40]);
        let url = serve_once(http_response("206 Partial Content", "", &[2; 60])).await;

        fetch_and_write(&test_client(), &url, &part, Some(40), 100)
            .await
            .expect("resume");

        assert_eq!(
            std::fs::read(&part).unwrap(),
            [[1; 40].as_slice(), &[2; 60]].concat()
        );
        std::fs::remove_file(&part).unwrap();
    }

    #[tokio::test]
    async fn fetch_and_write_full_body_for_range_request_restarts_from_zero() {
        let part = temp_file(&[1; 40]);
        let url = serve_once(http_response("200 OK", "", &[2; 100])).await;

        fetch_and_write(&test_client(), &url, &part, Some(40), 100)
            .await
            .expect("restart");

        assert_eq!(std::fs::read(&part).unwrap(), [2; 100]);
        std::fs::remove_file(&part).unwrap();
    }

    #[tokio::test]
    async fn fetch_and_write_connection_dropped_mid_body_keeps_part() {
        let part = temp_path();
        let url = serve_once(http_response("200 OK", "Content-Length: 100\r\n", &[3; 40])).await;

        assert!(fetch_and_write(&test_client(), &url, &part, None, 100)
            .await
            .is_err());

        assert_eq!(std::fs::read(&part).unwrap(), [3; 40]);
        std::fs::remove_file(&part).unwrap();
    }

    #[tokio::test]
    async fn write_response_body_disk_write_fails_removes_part() {
        let part = temp_file(b"");
        let url = serve_once(http_response("200 OK", "", &[4; 10])).await;
        let mut response = test_client().get(&url).send().await.expect("response");
        // A read-only handle makes the disk write fail on every platform.
        let read_only = std::fs::File::open(&part).unwrap();

        assert!(write_response_body(&mut response, read_only, &part, 100)
            .await
            .is_err());
        assert!(!part.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_response_body_part_cannot_be_removed_reports_both_errors() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_path();
        std::fs::create_dir(&dir).unwrap();
        let part = dir.join("params.part");
        std::fs::write(&part, [1; 40]).unwrap();
        // The open file stays writable, but a read-only directory refuses to unlink it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let url = serve_once(http_response("206 Partial Content", "", &[2; 61])).await;

        let result = fetch_and_write(&test_client(), &url, &part, Some(40), 100).await;

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let message = format!("{:#}", result.expect_err("over-long body must fail"));
        assert!(message.contains("failed to remove"), "{message}");
        assert!(message.contains("more than the expected"), "{message}");
    }

    #[test]
    fn verify_downloaded_part_hash_mismatch_removes_part() {
        let part = temp_file(b"hello world");

        assert!(verify_downloaded_part(&part, 11, "0000", "params").is_err());
        assert!(!part.exists());
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

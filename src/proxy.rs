use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response, StatusCode};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::audit::AuditLog;
use crate::config::{Config, RedactAction, Sensitivity};
use crate::faker::Faker;
use crate::redactor::{detect, Confidence};
use crate::session::SessionManager;
use crate::stats::Stats;
use regex::Regex;

/// Decompress a body based on content-encoding
fn decompress_body(data: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    match encoding {
        "zstd" => zstd::decode_all(std::io::Cursor::new(data))
            .map_err(|e| format!("zstd decode error: {}", e)),
        "gzip" => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(data));
            let mut buf = Vec::new();
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| format!("gzip decode error: {}", e))?;
            Ok(buf)
        }
        other => Err(format!("unsupported encoding: {}", other)),
    }
}

/// Compress a body back to the specified encoding
fn compress_body(data: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    match encoding {
        "zstd" => zstd::encode_all(std::io::Cursor::new(data), 3)
            .map_err(|e| format!("zstd encode error: {}", e)),
        "gzip" => {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| format!("gzip encode error: {}", e))?;
            encoder
                .finish()
                .map_err(|e| format!("gzip finish error: {}", e))
        }
        other => Err(format!("unsupported encoding: {}", other)),
    }
}

#[derive(Debug, Clone)]
pub struct CompiledCustomPattern {
    pub name: String,
    pub regex: Regex,
    pub substitute: String,
    pub pattern_str: String,
}

pub struct ProxyState {
    pub client: Client,
    pub sessions: SessionManager,
    pub config: Config,
    pub audit_log: Option<Arc<AuditLog>>,
    pub stats: Arc<Stats>,
    /// Global set of PII values already seen (by hash) — dedup across all sessions
    pub seen_pii: Mutex<HashSet<String>>,
    /// Originals the user has explicitly flagged via `mirage flag <decoy>` —
    /// detect() will still flag these but smart_redact will skip substitution.
    /// Session-scoped: cleared on daemon restart.
    pub flagged_originals: Mutex<HashSet<String>>,
    pub custom_patterns: Vec<CompiledCustomPattern>,
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: Bytes) -> BoxBody {
    Full::new(data).map_err(|never| match never {}).boxed()
}

fn error_response(status: StatusCode, msg: &str) -> Response<BoxBody> {
    let body = serde_json::json!({ "error": { "message": msg, "type": "mirage_proxy_error" } });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// Parse `?decoy=...` from a request path. Returns the URL-decoded value or None.
fn parse_decoy_param(path_and_query: &str) -> Option<String> {
    let q = path_and_query.split_once('?').map(|(_, q)| q)?;
    for pair in q.split('&') {
        if let Some(value) = pair.strip_prefix("decoy=") {
            return Some(percent_decode(value));
        }
    }
    None
}

/// Minimal percent-decoder for query values. We only need it for `mirage why`
/// where users may paste decoys containing `+` or `%` characters.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = &s[i + 1..i + 3];
                if let Ok(b) = u8::from_str_radix(h, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// `GET /why?decoy=<fake>` — explain a substitution to the user without
/// leaking the original value. Returns kind, session id, and a md5 fingerprint
/// the user can compare against an audit log entry.
fn why_response(path_and_query: &str, state: &ProxyState) -> Response<BoxBody> {
    let decoy = match parse_decoy_param(path_and_query) {
        Some(d) if !d.is_empty() => d,
        _ => {
            return error_response(StatusCode::BAD_REQUEST, "missing ?decoy=<value>");
        }
    };

    let body = match state.sessions.lookup_decoy(&decoy) {
        Some((session_id, original)) => {
            let fingerprint = format!("{:x}", md5::compute(original.as_bytes()));
            let len = original.chars().count();
            serde_json::json!({
                "decoy": decoy,
                "session": session_id,
                "original_length": len,
                "original_md5": fingerprint,
                "found": true,
                "hint": "to undo this substitution for the rest of this session, run: mirage flag <decoy>",
            })
        }
        None => serde_json::json!({
            "decoy": decoy,
            "found": false,
            "hint": "no record. either the decoy is from a previous daemon run, or the value never passed through mirage.",
        }),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// `POST /flag?decoy=<fake>` — add the corresponding original to the
/// session-scoped allowlist so smart_redact stops substituting it.
fn flag_response(path_and_query: &str, state: &ProxyState) -> Response<BoxBody> {
    let decoy = match parse_decoy_param(path_and_query) {
        Some(d) if !d.is_empty() => d,
        _ => return error_response(StatusCode::BAD_REQUEST, "missing ?decoy=<value>"),
    };

    let (session_id, original) = match state.sessions.lookup_decoy(&decoy) {
        Some(pair) => pair,
        None => {
            let body = serde_json::json!({
                "flagged": false,
                "reason": "no record for that decoy. is the daemon a different one than the one that produced it?",
            });
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(full_body(Bytes::from(body.to_string())))
                .unwrap();
        }
    };

    {
        let mut flagged = state.flagged_originals.lock().unwrap();
        flagged.insert(original.clone());
    }

    // Best-effort persistence so a daemon restart can replay flags.
    persist_flag(&original);

    let body = serde_json::json!({
        "flagged": true,
        "decoy": decoy,
        "session": session_id,
        "original_md5": format!("{:x}", md5::compute(original.as_bytes())),
        "scope": "this daemon process; persisted to ~/.mirage/flags.jsonl",
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

fn persist_flag(original: &str) {
    let dir = dirs_next::home_dir().map(|h| h.join(".mirage"));
    let Some(dir) = dir else { return };
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("flags.jsonl");
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "original_md5": format!("{:x}", md5::compute(original.as_bytes())),
            "original": original, // local-only; ~/.mirage is not synced
        });
        let _ = writeln!(f, "{}", entry);
    }
}

fn health_response(state: &ProxyState) -> Response<BoxBody> {
    use std::sync::atomic::Ordering;

    let body = serde_json::json!({
        "status": "ok",
        "service": "mirage-proxy",
        "requests": state.stats.requests.load(Ordering::Relaxed),
        "redactions": state.stats.redactions.load(Ordering::Relaxed),
        "sessions": state.stats.sessions.load(Ordering::Relaxed),
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// Fast-path: forward request without inspection (when decompression fails)
async fn forward_request(
    method: hyper::Method,
    path: &str,
    headers: &hyper::HeaderMap,
    body: Vec<u8>,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let is_chatgpt = headers.contains_key("chatgpt-account-id");
    let (target_url, _) = if let Some((upstream, remaining)) =
        crate::providers::resolve_provider(path, is_chatgpt, &state.config.custom_providers)
    {
        (
            format!("{}{}", upstream.trim_end_matches('/'), remaining),
            remaining,
        )
    } else {
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("No provider matched for path: {}. Use a provider prefix (e.g. /anthropic, /openai).", path),
        ));
    };

    debug!(
        "▶ fast-forward {} {} → {} ({} bytes, no inspection)",
        method,
        path,
        target_url,
        body.len()
    );

    let mut forward = state.client.request(method.clone(), &target_url);
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        match name_str.as_str() {
            "host" | "connection" | "transfer-encoding" | "content-length" | "accept-encoding" => {
                continue
            }
            _ => {
                if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                        forward = forward.header(n, v);
                    }
                }
            }
        }
    }
    // Force identity encoding so response rehydration can operate safely on plain text/JSON.
    forward = forward.header("accept-encoding", "identity");
    forward = forward.body(body);

    let response = match forward.send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Upstream request failed: {}", e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream error: {}", e),
            ));
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let ct = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");
    debug!(
        "← {} {} ({})",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        ct
    );

    let is_stream = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        handle_streaming_response(status, resp_headers, response, state, faker).await
    } else {
        handle_regular_response(status, resp_headers, response, state, faker).await
    }
}

/// Handle an incoming request: redact PII, forward to target, rehydrate response
pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = req.headers().clone();

    if path == "/healthz" {
        return Ok(health_response(&state));
    }
    if path.starts_with("/why") {
        return Ok(why_response(&path, &state));
    }
    if path.starts_with("/flag") {
        return Ok(flag_response(&path, &state));
    }

    debug!("{} {}", method, path);
    for (name, value) in req.headers().iter() {
        let n = name.as_str();
        let v = value.to_str().unwrap_or("<binary>");
        // Mask auth values in debug but show the header name and first/last chars
        if n == "authorization" || n == "x-api-key" || n == "openai-organization" {
            let masked = if v.len() > 12 {
                format!("{}...{}", &v[..8], &v[v.len() - 4..])
            } else {
                "***".to_string()
            };
            debug!("  → {}: {}", n, masked);
        } else {
            debug!("  → {}: {}", n, v);
        }
    }

    // Collect request body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };

    state.stats.add_request(body_bytes.len() as u64);

    let request_content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Never inspect binary request payloads (multipart, images, PDFs, etc).
    // Forward as-is to avoid corruption.
    if !body_bytes.is_empty()
        && !request_content_type.is_empty()
        && !is_textual_content_type(&request_content_type)
    {
        debug!(
            "body is non-text content-type ({}), forwarding without inspection",
            request_content_type
        );
        let (_, faker) = state.sessions.get_faker("default");
        return forward_request(method, &path, &headers, body_bytes.to_vec(), state, faker).await;
    }

    // Check if this provider is bypassed (no redaction/rehydration)
    let is_chatgpt_early = headers.contains_key("chatgpt-account-id");
    let resolved_upstream =
        crate::providers::resolve_provider(&path, is_chatgpt_early, &state.config.custom_providers)
            .map(|(upstream, _)| upstream.to_string())
            .unwrap_or_default();
    if state.config.is_bypassed(&resolved_upstream) {
        debug!("⏩ bypassing {} (matched bypass list)", resolved_upstream);
        let (_, faker) = state.sessions.get_faker("default");
        return forward_request(method, &path, &headers, body_bytes.to_vec(), state, faker).await;
    }

    // Check for compressed body (zstd, gzip, etc.) — decompress for inspection, forward original
    let content_encoding = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

    let inspect_bytes = if is_compressed {
        debug!(
            "body is compressed ({}), {} bytes — decompressing for inspection",
            content_encoding,
            body_bytes.len()
        );
        match decompress_body(&body_bytes, &content_encoding) {
            Ok(decompressed) => {
                debug!(
                    "decompressed: {} bytes → {} bytes",
                    body_bytes.len(),
                    decompressed.len()
                );
                decompressed
            }
            Err(e) => {
                warn!(
                    "failed to decompress {} body: {} — forwarding as-is without inspection",
                    content_encoding, e
                );
                // Can't inspect, just forward original
                let (_, faker) = state.sessions.get_faker("default");
                // Skip to forwarding
                return forward_request(method, &path, &headers, body_bytes.to_vec(), state, faker)
                    .await;
            }
        }
    } else {
        body_bytes.to_vec()
    };

    // Parse JSON to derive session ID, then redact with session-scoped faker
    let (redacted_body, session_faker) = if !inspect_bytes.is_empty() {
        match serde_json::from_slice::<Value>(&inspect_bytes) {
            Ok(mut json) => {
                debug!("parsed JSON body OK ({} bytes)", inspect_bytes.len());
                let session_id = SessionManager::derive_session_id(&json);
                let (is_new, faker) = state.sessions.get_faker(&session_id);
                if is_new {
                    state.stats.add_session();
                }
                if is_new {
                    eprint!("\r\x1b[2K  📎 session: {}\n", session_id);
                }
                redact_json_value(&mut json, &state, &faker);
                if is_compressed {
                    // Re-compress redacted JSON back to original encoding
                    let redacted_json =
                        serde_json::to_vec(&json).unwrap_or_else(|_| inspect_bytes.clone());
                    debug!(
                        "re-compressing redacted body ({} bytes) with {}",
                        redacted_json.len(),
                        content_encoding
                    );
                    match compress_body(&redacted_json, &content_encoding) {
                        Ok(compressed) => {
                            debug!(
                                "re-compressed: {} bytes → {} bytes",
                                redacted_json.len(),
                                compressed.len()
                            );
                            (compressed, faker)
                        }
                        Err(e) => {
                            warn!("failed to re-compress body: {} — forwarding original", e);
                            (body_bytes.to_vec(), faker)
                        }
                    }
                } else {
                    (
                        serde_json::to_vec(&json).unwrap_or_else(|_| body_bytes.to_vec()),
                        faker,
                    )
                }
            }
            Err(e) => {
                debug!(
                    "body is not valid JSON: {} — treating as text ({} bytes)",
                    e,
                    inspect_bytes.len()
                );
                let (_, faker) = state.sessions.get_faker("default");
                let text = String::from_utf8_lossy(&inspect_bytes);
                let redacted = smart_redact(&text, &state, &faker);
                if is_compressed {
                    match compress_body(redacted.as_bytes(), &content_encoding) {
                        Ok(compressed) => (compressed, faker),
                        Err(_) => (body_bytes.to_vec(), faker),
                    }
                } else {
                    (redacted.into_bytes(), faker)
                }
            }
        }
    } else {
        (body_bytes.to_vec(), state.sessions.get_faker("default").1)
    };

    // In dry-run mode, forward the original body
    let forward_body = if state.config.dry_run {
        body_bytes.to_vec()
    } else {
        redacted_body
    };

    // Resolve provider
    let is_chatgpt = headers.contains_key("chatgpt-account-id");
    let (target_url, forward_path) = if let Some((upstream, remaining)) =
        crate::providers::resolve_provider(&path, is_chatgpt, &state.config.custom_providers)
    {
        (
            format!("{}{}", upstream.trim_end_matches('/'), remaining),
            remaining,
        )
    } else {
        warn!("No provider matched for path: {}", path);
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("No provider matched for path: {}. Use a provider prefix (e.g. /anthropic, /openai).", path),
        ));
    };
    let _ = forward_path; // used for clarity, target_url has the full URL

    debug!("▶ forwarding {} {} → {}", method, path, target_url);
    debug!(
        "  forward body: {} bytes (compressed: {})",
        forward_body.len(),
        is_compressed
    );

    let mut forward = state.client.request(method.clone(), &target_url);

    let mut forwarded_headers = Vec::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        match name_str.as_str() {
            "host" | "connection" | "transfer-encoding" | "content-length" | "accept-encoding" => {
                debug!("  ⊘ skipping header: {}", name_str);
                continue;
            }
            _ => {
                if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                        forwarded_headers.push(format!(
                            "{}: {}",
                            name_str,
                            if name_str == "authorization" || name_str == "x-api-key" {
                                let val = value.to_str().unwrap_or("***");
                                if val.len() > 12 {
                                    format!("{}...{}", &val[..8], &val[val.len() - 4..])
                                } else {
                                    "***".to_string()
                                }
                            } else {
                                value.to_str().unwrap_or("<binary>").to_string()
                            }
                        ));
                        forward = forward.header(n, v);
                    }
                }
            }
        }
    }
    for h in &forwarded_headers {
        debug!("  → {}", h);
    }

    // Force identity encoding so response rehydration can operate safely on plain text/JSON.
    forward = forward.header("accept-encoding", "identity");

    forward = forward.body(forward_body);

    let response = match forward.send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Upstream request failed: {}", e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream request failed: {}", e),
            ));
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let ct = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");
    debug!(
        "← {} {} ({})",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        ct
    );

    // Log full response body on error for diagnosis
    if status.as_u16() >= 400 {
        debug!("  ← response headers:");
        for (name, value) in resp_headers.iter() {
            debug!(
                "    {}: {}",
                name.as_str(),
                value.to_str().unwrap_or("<binary>")
            );
        }
    }

    let is_stream = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        if state.config.force_no_stream {
            handle_streaming_as_regular(status, resp_headers, response, state, session_faker).await
        } else {
            handle_streaming_response(status, resp_headers, response, state, session_faker).await
        }
    } else {
        handle_regular_response(status, resp_headers, response, state, session_faker).await
    }
}

fn header_content_encoding(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn header_content_type(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_textual_content_type(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct.ends_with("+json")
        || ct == "application/xml"
        || ct.ends_with("+xml")
        || ct == "application/javascript"
        || ct == "application/x-www-form-urlencoded"
        || ct == "application/graphql"
        || ct == "application/x-ndjson"
        || ct == "application/json-seq"
        || ct == "text/event-stream"
}

fn should_skip_redaction_for_payload(text: &str) -> bool {
    let s = text.trim();

    // Non-text data URLs (image/pdf/audio/etc.) should remain byte-for-byte intact.
    // Example: data:application/pdf;base64,JVBERi0xLjcK...
    if let Some(rest) = s.strip_prefix("data:") {
        if let Some((meta, _payload)) = rest.split_once(',') {
            let has_base64 = meta.split(';').any(|p| p.eq_ignore_ascii_case("base64"));
            if has_base64 {
                let mime = meta
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                let is_text_data = mime.starts_with("text/")
                    || mime == "application/json"
                    || mime.ends_with("+json")
                    || mime == "application/xml"
                    || mime.ends_with("+xml")
                    || mime == "application/javascript";
                if !is_text_data {
                    return true;
                }
            }
        }
    }

    // Large standalone base64 blobs are usually binary payloads.
    // Avoid mutating them to prevent corruption.
    if s.len() >= 512 {
        let cleaned_len = s
            .bytes()
            .filter(|b| !matches!(*b, b'\r' | b'\n' | b'\t' | b' '))
            .count();
        if cleaned_len >= 512
            && s.bytes().all(|b| {
                matches!(b,
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
                    b'+' | b'/' | b'=' | b'\r' | b'\n' | b'\t' | b' '
                )
            })
        {
            return true;
        }
    }

    false
}

fn has_anthropic_thinking_signature(text: &str) -> bool {
    // Anthropic extended thinking blocks are signed.
    // Any mutation inside those blocks invalidates the signature.
    (text.contains("\"type\":\"thinking\"") || text.contains("\"type\": \"thinking\""))
        && (text.contains("\"signature\":\"") || text.contains("\"signature\": \""))
}

fn passthrough_response(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "content-length" || name_str == "transfer-encoding" {
            continue;
        }
        if let Ok(n) = hyper::header::HeaderName::from_bytes(name.as_ref()) {
            if let Ok(v) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(n, v);
            }
        }
    }

    Ok(builder.body(full_body(Bytes::from(body))).unwrap())
}

async fn handle_regular_response(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    response: reqwest::Response,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let body_bytes = response.bytes().await.unwrap_or_default();

    state.stats.add_response(body_bytes.len() as u64);

    // Log error response bodies for debugging
    if status.as_u16() >= 400 {
        let body_preview = String::from_utf8_lossy(&body_bytes);
        let preview = if body_preview.len() > 2000 {
            &body_preview[..2000]
        } else {
            &body_preview
        };
        debug!("  ← error body: {}", preview);
    }

    // Rehydrate: replace fakes back to originals in the response.
    // Safety guards:
    // - Never mutate signed thinking payloads (signature would break)
    // - For compressed responses: decompress -> rehydrate -> recompress
    let response_content_type = header_content_type(&resp_headers);
    if !response_content_type.is_empty() && !is_textual_content_type(&response_content_type) {
        debug!(
            "response is non-text content-type ({}), skipping rehydration",
            response_content_type
        );
        return passthrough_response(status, resp_headers, body_bytes.to_vec());
    }

    let content_encoding = header_content_encoding(&resp_headers);
    let is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

    let rehydrated_body = if !body_bytes.is_empty() && !state.config.dry_run {
        if is_compressed {
            match decompress_body(&body_bytes, &content_encoding) {
                Ok(decoded) => {
                    let text = String::from_utf8_lossy(&decoded);
                    if has_anthropic_thinking_signature(&text) {
                        debug!("skipping rehydration for signed thinking response (compressed)");
                        body_bytes.to_vec()
                    } else {
                        let rehydrated = faker.rehydrate(&text);
                        match compress_body(rehydrated.as_bytes(), &content_encoding) {
                            Ok(encoded) => encoded,
                            Err(e) => {
                                warn!("failed to re-compress rehydrated response: {}", e);
                                body_bytes.to_vec()
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "failed to decompress response body (content-encoding={}): {}",
                        content_encoding, e
                    );
                    body_bytes.to_vec()
                }
            }
        } else {
            let text = String::from_utf8_lossy(&body_bytes);
            if has_anthropic_thinking_signature(&text) {
                debug!("skipping rehydration for signed thinking response");
                body_bytes.to_vec()
            } else {
                faker.rehydrate(&text).into_bytes()
            }
        }
    } else {
        body_bytes.to_vec()
    };

    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "content-length" || name_str == "transfer-encoding" {
            continue;
        }
        if let Ok(n) = hyper::header::HeaderName::from_bytes(name.as_ref()) {
            if let Ok(v) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(n, v);
            }
        }
    }

    Ok(builder
        .body(full_body(Bytes::from(rehydrated_body)))
        .unwrap())
}

/// Parse SSE body, extract and join all `delta.content` values,
/// rehydrate the joined content, and reconstruct SSE events.
/// Puts all rehydrated content in the first content chunk;
/// clears `delta.content` from subsequent chunks.
/// This fixes PII that gets split across SSE chunk boundaries
/// (e.g. IP addresses where "84.106.142.195" arrives as separate tokens).
/// Recursively rehydrate all string values in a JSON value.
/// Returns true if any string was modified.
/// This catches substitute values in ANY field, regardless of SSE format.
fn rehydrate_json_value(value: &mut Value, faker: &Faker) -> bool {
    match value {
        Value::String(s) => {
            let rehydrated = faker.rehydrate(s);
            if rehydrated != *s {
                *s = rehydrated;
                true
            } else {
                false
            }
        }
        Value::Array(arr) => {
            let mut changed = false;
            for item in arr.iter_mut() {
                changed = rehydrate_json_value(item, faker) || changed;
            }
            changed
        }
        Value::Object(obj) => {
            let mut changed = false;
            for val in obj.values_mut() {
                changed = rehydrate_json_value(val, faker) || changed;
            }
            changed
        }
        _ => false,
    }
}

/// Parse SSE body, rehydrate ALL string values in every event (universal),
/// and handle cross-chunk boundary PII for content/reasoning/reasoning_content.
///
/// Universal rehydration covers any JSON field — content, reasoning,
/// tool_calls, function_call, or custom provider fields — so custom patterns
/// are restored everywhere without per-field maintenance.
///
/// Cross-chunk handling joins delta.content/delta.reasoning fields across
/// events to catch PII split across chunk boundaries (e.g. IP addresses).
fn rehydrate_sse_body(text: &str, faker: &Faker) -> String {
    let text = text.replace("\r\n", "\n");
    let events: Vec<&str> = text.split("\n\n").collect();
    let mut out_events: Vec<String> = Vec::with_capacity(events.len());
    let mut full_content = String::new();
    let mut content_indices: Vec<usize> = Vec::new();
    let mut content_jsons: Vec<String> = Vec::new();
    let mut full_reasoning = String::new();
    let mut reasoning_indices: Vec<usize> = Vec::new();
    let mut reasoning_jsons: Vec<String> = Vec::new();
    let mut full_reasoning_content = String::new();
    let mut reasoning_content_indices: Vec<usize> = Vec::new();
    let mut reasoning_content_jsons: Vec<String> = Vec::new();
    // Tool calls cross-chunk tracking: per tool_call index
    let mut tc_concat: Vec<String> = Vec::new();
    let mut tc_first: Vec<usize> = Vec::new();
    let mut tc_all: Vec<Vec<usize>> = Vec::new();
    let mut tc_jsons: Vec<Vec<String>> = Vec::new();
    // Map from API tool_call index (i64) -> our Vec index
    let mut tc_lookup: std::collections::HashMap<i64, usize> = std::collections::HashMap::new();

    for event in &events {
        if event.is_empty() {
            out_events.push(String::new());
            continue;
        }
        if let Some(data_str) = event.strip_prefix("data: ") {
            if data_str.trim() == "[DONE]" {
                out_events.push(event.to_string());
                continue;
            }
            match serde_json::from_str::<Value>(data_str) {
                Ok(val) => {
                    if let Some(content) = val["choices"][0]["delta"]["content"].as_str() {
                        if !content.is_empty() {
                            full_content.push_str(content);
                            content_indices.push(out_events.len());
                            content_jsons.push(data_str.to_string());
                        }
                    }
                    if let Some(reasoning) = val["choices"][0]["delta"]["reasoning"].as_str() {
                        if !reasoning.is_empty() {
                            full_reasoning.push_str(reasoning);
                            reasoning_indices.push(out_events.len());
                            reasoning_jsons.push(data_str.to_string());
                        }
                    }
                    if let Some(rc) = val["choices"][0]["delta"]["reasoning_content"].as_str() {
                        if !rc.is_empty() {
                            full_reasoning_content.push_str(rc);
                            reasoning_content_indices.push(out_events.len());
                            reasoning_content_jsons.push(data_str.to_string());
                        }
                    }
                    // Collect tool_calls arguments per index for cross-chunk rehydration
                    if let Some(tcs) = val["choices"][0]["delta"]["tool_calls"].as_array() {
                        for tc in tcs {
                            if let Some(args) = tc["function"]["arguments"].as_str() {
                                if let Some(tc_idx) = tc["index"].as_i64() {
                                    let vec_idx = *tc_lookup.entry(tc_idx).or_insert_with(|| {
                                        tc_concat.push(String::new());
                                        tc_first.push(out_events.len());
                                        tc_all.push(Vec::new());
                                        tc_jsons.push(Vec::new());
                                        tc_concat.len() - 1
                                    });
                                    tc_concat[vec_idx].push_str(args);
                                    tc_all[vec_idx].push(out_events.len());
                                    tc_jsons[vec_idx].push(data_str.to_string());
                                }
                            }
                        }
                    }
                    out_events.push(event.to_string());
                }
                Err(_) => {
                    out_events.push(event.to_string());
                }
            }
        } else {
            out_events.push(event.to_string());
        }
    }

    // Phase 1: Cross-chunk rehydration for content/reasoning/reasoning_content.
    // Each loop reads from out_events[idx] (which may have been modified
    // by a prior field loop) so edits compose correctly when the same SSE
    // event contains multiple delta fields. base is an owned String so the
    // serialization fallback (never expected in practice, but correct) does
    // not lose modifications from earlier loops.
    if !content_indices.is_empty() {
        let rehydrated = faker.rehydrate(&full_content);
        if rehydrated != full_content {
            for (i, &idx) in content_indices.iter().enumerate() {
                let base = out_events[idx]
                    .strip_prefix("data: ")
                    .unwrap_or(&content_jsons[i])
                    .to_string();
                if let Ok(mut val) = serde_json::from_str::<Value>(&base) {
                    if i == 0 {
                        val["choices"][0]["delta"]["content"] = Value::String(rehydrated.clone());
                    } else if let Some(delta) = val["choices"][0]["delta"].as_object_mut() {
                        delta.remove("content");
                    }
                    if let Ok(new_json) = serde_json::to_string(&val) {
                        out_events[idx] = format!("data: {}", new_json);
                    }
                }
            }
        }
    }

    if !reasoning_indices.is_empty() {
        let rehydrated = faker.rehydrate(&full_reasoning);
        if rehydrated != full_reasoning {
            for (i, &idx) in reasoning_indices.iter().enumerate() {
                let base = out_events[idx]
                    .strip_prefix("data: ")
                    .unwrap_or(&reasoning_jsons[i])
                    .to_string();
                if let Ok(mut val) = serde_json::from_str::<Value>(&base) {
                    if i == 0 {
                        val["choices"][0]["delta"]["reasoning"] = Value::String(rehydrated.clone());
                    } else if let Some(delta) = val["choices"][0]["delta"].as_object_mut() {
                        delta.remove("reasoning");
                    }
                    if let Ok(new_json) = serde_json::to_string(&val) {
                        out_events[idx] = format!("data: {}", new_json);
                    }
                }
            }
        }
    }

    if !reasoning_content_indices.is_empty() {
        let rehydrated = faker.rehydrate(&full_reasoning_content);
        if rehydrated != full_reasoning_content {
            for (i, &idx) in reasoning_content_indices.iter().enumerate() {
                let base = out_events[idx]
                    .strip_prefix("data: ")
                    .unwrap_or(&reasoning_content_jsons[i])
                    .to_string();
                if let Ok(mut val) = serde_json::from_str::<Value>(&base) {
                    if i == 0 {
                        val["choices"][0]["delta"]["reasoning_content"] =
                            Value::String(rehydrated.clone());
                    } else if let Some(delta) = val["choices"][0]["delta"].as_object_mut() {
                        delta.remove("reasoning_content");
                    }
                    if let Ok(new_json) = serde_json::to_string(&val) {
                        out_events[idx] = format!("data: {}", new_json);
                    }
                }
            }
        }
    }

    // Phase 1b: Cross-chunk rehydration for tool_calls arguments.
    // Tool calls are streamed as incremental function.argument chunks per index.
    // Without joining, a substitute split across events (e.g. "jo"/"hn") leaks.
    if !tc_concat.is_empty() {
        for vec_idx in 0..tc_concat.len() {
            let full_args = tc_concat[vec_idx].clone();
            let rehydrated = faker.rehydrate(&full_args);
            if rehydrated != full_args {
                let first_ev = tc_first[vec_idx];
                // Update first event with rehydrated arguments
                let first_json = &tc_jsons[vec_idx][0];
                if let Ok(mut val) = serde_json::from_str::<Value>(first_json) {
                    val["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] =
                        Value::String(rehydrated.clone());
                    if let Ok(new_json) = serde_json::to_string(&val) {
                        out_events[first_ev] = format!("data: {}", new_json);
                    }
                }
                // Clear arguments from subsequent events for this tool call index.
                // Find the API tool_call index for this vec_idx from tc_lookup.
                let api_idx = tc_lookup
                    .iter()
                    .find(|(_, &v)| v == vec_idx)
                    .map(|(&k, _)| k);
                for &ev_idx in &tc_all[vec_idx] {
                    if ev_idx == first_ev {
                        continue;
                    }
                    let ev_str = &out_events[ev_idx];
                    if let Some(base) = ev_str.strip_prefix("data: ") {
                        if let Ok(mut val) = serde_json::from_str::<Value>(base) {
                            if let Some(tcs) =
                                val["choices"][0]["delta"]["tool_calls"].as_array_mut()
                            {
                                for tc in tcs.iter_mut() {
                                    let matches = match api_idx {
                                        Some(i) => tc["index"].as_i64() == Some(i),
                                        None => true,
                                    };
                                    if matches {
                                        if let Some(func) = tc["function"].as_object_mut() {
                                            func.remove("arguments");
                                        }
                                    }
                                }
                            }
                            if let Ok(new_json) = serde_json::to_string(&val) {
                                out_events[ev_idx] = format!("data: {}", new_json);
                            }
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Universal rehydration — rehydrate ALL string values in every event.
    // This catches custom pattern substitutes in any field (tool_calls,
    // function_call, custom provider fields, etc.) without per-field tracking.
    // Only re-serializes events that actually changed (preserves key ordering otherwise).
    for event in &mut out_events {
        if let Some(data_str) = event.strip_prefix("data: ") {
            if let Ok(mut val) = serde_json::from_str::<Value>(data_str) {
                if rehydrate_json_value(&mut val, faker) {
                    if let Ok(new_json) = serde_json::to_string(&val) {
                        *event = format!("data: {}", new_json);
                    }
                }
            }
        }
    }

    out_events.join("\n\n")
}

/// When force_no_stream is enabled but the upstream returns SSE anyway,
/// buffer all raw bytes into one chunk, then rehydrate in a single pass.
/// This eliminates chunk-boundary rehydration issues at the cost of
/// delivering the full response only after the upstream finishes.
async fn handle_streaming_as_regular(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    response: reqwest::Response,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let content_encoding = header_content_encoding(&resp_headers);
    let is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

    let mut raw = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                state.stats.add_response(bytes.len() as u64);
                raw.extend_from_slice(&bytes);
            }
            Err(e) => {
                warn!("Stream chunk error in buffered fallback: {}", e);
                break;
            }
        }
    }

    let body = if raw.is_empty() || state.config.dry_run {
        raw
    } else if is_compressed {
        match decompress_body(&raw, &content_encoding) {
            Ok(decoded) => {
                let text = String::from_utf8_lossy(&decoded);
                if has_anthropic_thinking_signature(&text) {
                    debug!("skipping rehydration for signed thinking response (compressed)");
                    raw
                } else {
                    let rehydrated = rehydrate_sse_body(&text, &faker);
                    match compress_body(rehydrated.as_bytes(), &content_encoding) {
                        Ok(encoded) => encoded,
                        Err(e) => {
                            warn!("failed to re-compress rehydrated response: {}", e);
                            raw
                        }
                    }
                }
            }
            Err(e) => {
                warn!("failed to decompress streaming response: {}", e);
                raw
            }
        }
    } else {
        let text = String::from_utf8_lossy(&raw);
        if has_anthropic_thinking_signature(&text) {
            debug!("skipping rehydration for signed thinking response");
            raw
        } else {
            rehydrate_sse_body(&text, &faker).into_bytes()
        }
    };

    passthrough_response(status, resp_headers, body)
}

async fn handle_streaming_response(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    response: reqwest::Response,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);

    let content_encoding = header_content_encoding(&resp_headers);
    let stream_is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

        let stats_clone = state.stats.clone();
    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        // Buffer to handle fake values split across chunk boundaries.
        // Uses SSE event boundaries (\n\n) to preserve tool_calls argument
        // deltas so they can be joined within the same rehydrate_sse_body call.
        // Cross-chunk tool_calls joining is only available in buffered mode
        // (--no-stream / force_no_stream) via the handle_streaming_as_regular path.
        const BOUNDARY_BUF_SIZE: usize = 128;
        let mut leftover = String::new();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    stats_clone.add_response(bytes.len() as u64);

                    let bypass_rehydrate = state.config.dry_run || stream_is_compressed;
                    let out = if bypass_rehydrate {
                        if leftover.is_empty() {
                            bytes.to_vec()
                        } else {
                            let mut s = std::mem::take(&mut leftover);
                            s.push_str(&String::from_utf8_lossy(&bytes));
                            s.into_bytes()
                        }
                    } else {
                        let text = String::from_utf8_lossy(&bytes);

                        // Prepend any leftover from previous chunk
                        let combined = if leftover.is_empty() {
                            text.to_string()
                        } else {
                            let mut s = std::mem::take(&mut leftover);
                            s.push_str(&text);
                            s
                        };

                        // Do not touch signed thinking payloads (Anthropic validates signatures)
                        if has_anthropic_thinking_signature(&combined) {
                            debug!("detected signed thinking chunk in SSE stream — passing through unchanged");
                            combined.into_bytes()
                        } else {
                            // Split at an SSE event boundary (\n\n) so tool_calls
                            // argument deltas are kept together. Falls back to line
                            // boundary (\n) when no double-newline is found.
                            let (to_process, new_leftover) = if combined.len() > BOUNDARY_BUF_SIZE {
                                let split_at = combined.len() - BOUNDARY_BUF_SIZE;
                                let safe_split = combined[..split_at]
                                    .rfind("\n\n")
                                    .map(|pos| pos + 2)
                                    .or_else(|| {
                                        combined[split_at..]
                                            .find('\n')
                                            .map(|pos| split_at + pos + 1)
                                    })
                                    .unwrap_or(split_at);
                                (&combined[..safe_split], &combined[safe_split..])
                            } else {
                                leftover = combined;
                                continue;
                            };

                            leftover = new_leftover.to_string();
                            // Use SSE-aware rehydration so tool_calls arguments in
                            // the same chunk are joined and rehydrated correctly.
                            rehydrate_sse_body(to_process, &faker).into_bytes()
                        }
                    };

                    let frame = Frame::data(Bytes::from(out));
                    if tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Stream chunk error: {}", e);
                    break;
                }
            }
        }

        if !leftover.is_empty() {
            let flushed = if state.config.dry_run || stream_is_compressed {
                leftover.into_bytes()
            } else if has_anthropic_thinking_signature(&leftover) {
                leftover.into_bytes()
            } else {
                rehydrate_sse_body(&leftover, &faker).into_bytes()
            };
            let frame = Frame::data(Bytes::from(flushed));
            let _ = tx.send(Ok(frame)).await;
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = StreamBody::new(stream);
    let boxed: BoxBody = BodyExt::boxed(body);

    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "content-length" || name_str == "transfer-encoding" {
            continue;
        }
        if let Ok(n) = hyper::header::HeaderName::from_bytes(name.as_ref()) {
            if let Ok(v) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(n, v);
            }
        }
    }

    Ok(builder.body(boxed).unwrap())
}

/// Smart redaction: uses config to decide action per PII kind.
/// Only counts and logs *new* detections — values already seen in this session are silently handled.
fn smart_redact(text: &str, state: &ProxyState, faker: &Faker) -> String {
    if should_skip_redaction_for_payload(text) {
        return text.to_string();
    }

    let entities = detect(text);
    let mut result = text.to_string();
    let mut new_redaction_count: u64 = 0;

    for entity in &entities {
        let label = entity.kind.label();
        let mut action = state.config.should_redact(label);

        // Confidence gate (v0.8.1): Low-confidence patterns (IPs, generic
        // high-entropy strings) demote to Warn at low/medium sensitivity.
        // High and Paranoid sensitivity keep aggressive substitution.
        if entity.confidence == Confidence::Low
            && matches!(
                state.config.sensitivity,
                Sensitivity::Low | Sensitivity::Medium
            )
            && matches!(action, RedactAction::Redact | RedactAction::Mask)
        {
            action = RedactAction::Warn;
        }

        // User-flagged originals: skip substitution but still log a one-line
        // notice so the user knows the flag is in effect.
        let is_flagged = {
            let flagged = state.flagged_originals.lock().unwrap();
            flagged.contains(&entity.original)
        };
        if is_flagged {
            eprint!("\r\x1b[2K  ⏭️  {} (user-flagged, passing through)\n", label);
            continue;
        }

        // Global dedup: check if we've ever seen this exact value
        let is_new = {
            let mut seen = state.seen_pii.lock().unwrap();
            seen.insert(entity.original.clone()) // returns true if newly inserted
        };

        // Only audit-log and count genuinely new detections
        if is_new {
            if let Some(ref audit) = state.audit_log {
                audit.log(
                    label,
                    &action,
                    &entity.original,
                    text,
                    entity.confidence.score(),
                );
            }
        }

        match action {
            RedactAction::Redact | RedactAction::Mask => {
                let fake = faker.fake(&entity.original, &entity.kind);
                result = result.replace(&entity.original, &fake);
                if is_new {
                    // Print above status bar: clear line, print, newline
                    let preview = truncate_preview(&entity.original, 40);
                    let detail = if let Some(ref name) = entity.pattern_name {
                        format!("{} ({})", label, name)
                    } else {
                        label.to_string()
                    };
                    let char_count = entity.original.len();
                    eprint!(
                        "\r\x1b[2K  🛡️  {} [{} chars] → {}\n",
                        detail, char_count, preview
                    );
                    new_redaction_count += 1;
                }
            }
            RedactAction::Warn => {
                if is_new {
                    let preview = truncate_preview(&entity.original, 40);
                    let detail = if let Some(ref name) = entity.pattern_name {
                        format!("{} ({})", label, name)
                    } else {
                        label.to_string()
                    };
                    let char_count = entity.original.len();
                    eprint!(
                        "\r\x1b[2K  ⚠️  {} (warn) [{} chars] → {}\n",
                        detail, char_count, preview
                    );
                }
            }
            RedactAction::Ignore => {}
        }
    }

    // Apply custom user-defined patterns (after built-in detection)
    for cp in &state.custom_patterns {
        let current = result.clone();
        for m in cp.regex.find_iter(&current) {
            let original = m.as_str();
            faker.add_custom_mapping(original, &cp.substitute, Some(&cp.pattern_str));
            result = result.replace(original, &cp.substitute);
            // Log custom pattern match
            let preview = truncate_preview(original, 40);
            let char_count = original.len();
            eprint!(
                "\r\x1b[2K  🛡️  {} (custom) [{} chars] → {}\n",
                cp.name, char_count, preview
            );
        }
    }

    if new_redaction_count > 0 {
        state.stats.add_redactions(new_redaction_count);
    }

    result
}

/// Truncate a string for display, masking the middle
fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        // Mask middle: show first 4 and last 4 chars
        if s.len() > 10 {
            let start = &s[..4];
            let end = &s[s.len() - 4..];
            format!("{}•••{}", start, end)
        } else {
            format!("{}•••", &s[..s.len().min(3)])
        }
    } else {
        let start = &s[..4];
        format!("{}••• [{} chars]", start, s.len())
    }
}

/// Recursively redact PII in JSON values
/// JSON keys that should NEVER be redacted.
/// Auth, config, IDs, metadata — anything that isn't user content.
const SKIP_REDACT_KEYS: &[&str] = &[
    // Auth
    "api_key",
    "apikey",
    "api-key",
    "api_secret",
    "authorization",
    "auth",
    "token",
    "bearer",
    "x-api-key",
    "x_api_key",
    "secret_key",
    "secret",
    "credentials",
    "access_token",
    "refresh_token",
    "session_token",
    "session_key",
    "session_id",
    // Model/provider config
    "model",
    "stream",
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "stop",
    "seed",
    "anthropic-version",
    "anthropic_version",
    "openai-organization",
    "openai_organization",
    // IDs and references (can look like high-entropy secrets)
    "id",
    "object",
    "type",
    "role",
    "name",
    "previous_response_id",
    "response_id",
    "message_id",
    "conversation_id",
    "thread_id",
    "run_id",
    "assistant_id",
    "file_id",
    "batch_id",
    "tool_call_id",
    "tool_use_id",
    // Cryptographic / signed envelopes (must remain byte-exact)
    "signature",
    "encrypted_content",
    "encrypted_input",
    "ciphertext",
    "proof",
    "attestation",
    "nonce",
    "iv",
    "tag",
    "mac",
    // Request structure
    "tool_choice",
    "response_format",
    "format",
    "encoding_format",
    "modalities",
    "truncation",
    "store",
    "metadata",
    "service_tier",
    "user",
    // mirage internal
    "mirage_session",
];

/// Keys whose VALUES are user content and SHOULD be redacted.
/// Everything else in the object is skipped — we only recurse into these.
const CONTENT_KEYS: &[&str] = &[
    "content",
    "text",
    "messages",
    "system",
    "input",
    "instructions",
    "description",
    "prompt",
    "tools",
    "tool_results",
    "tool_result",
];

fn should_skip_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    // If it's a known content key, always recurse into it
    if CONTENT_KEYS.iter().any(|&k| lower == k) {
        return false;
    }
    // If it's a known skip key, skip it
    if SKIP_REDACT_KEYS.iter().any(|&k| lower == k) {
        return true;
    }
    // For unknown keys: skip if the key name suggests it's an ID or config
    lower.ends_with("_id")
        || lower.ends_with("_key")
        || lower.ends_with("_token")
        || lower.ends_with("_secret")
        || lower.ends_with("_url")
        || lower.ends_with("_uri")
        || lower.starts_with("x-")
        || lower.starts_with("x_")
}

fn redact_json_value(value: &mut Value, state: &ProxyState, faker: &Faker) {
    match value {
        Value::String(s) => {
            *s = smart_redact(s, state, faker);
        }
        Value::Array(arr) => {
            for item in arr {
                redact_json_value(item, state, faker);
            }
        }
        Value::Object(obj) => {
            // Anthropic signed thinking blocks must never be modified.
            // Shape example:
            // {"type":"thinking","thinking":"...","signature":"base64..."}
            let is_signed_thinking = obj
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t == "thinking")
                .unwrap_or(false)
                && obj.get("signature").is_some();

            if is_signed_thinking {
                return;
            }

            for (key, v) in obj.iter_mut() {
                if should_skip_key(key) {
                    continue; // Never redact auth/config fields
                }
                redact_json_value(v, state, faker);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_textual_content_type, rehydrate_sse_body, should_skip_redaction_for_payload, Faker,
    };
    use crate::redactor::PiiKind;

    #[test]
    fn non_text_data_url_is_skipped() {
        let pdf_data_url = "data:application/pdf;base64,JVBERi0xLjcK";
        assert!(should_skip_redaction_for_payload(pdf_data_url));
    }

    #[test]
    fn text_data_url_is_not_skipped() {
        let text_data_url = "data:text/plain;base64,SGVsbG8=";
        assert!(!should_skip_redaction_for_payload(text_data_url));
    }

    #[test]
    fn large_base64_blob_is_skipped() {
        let blob = "A".repeat(700);
        assert!(should_skip_redaction_for_payload(&blob));
    }

    #[test]
    fn content_type_text_detection_works() {
        assert!(is_textual_content_type("application/json; charset=utf-8"));
        assert!(is_textual_content_type("text/plain"));
        assert!(!is_textual_content_type("application/pdf"));
        assert!(!is_textual_content_type("image/png"));
    }

    #[test]
    fn force_no_stream_json_unchanged() {
        // Regression guard: rehydration is a no-op on text with no fakes
        let faker = Faker::new(None, None);
        let clean = r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#;
        assert_eq!(faker.rehydrate(clean), clean);
    }

    #[test]
    fn full_body_rehydration_resolves_boundary_splits() {
        // Regression guard: rehydration restores original PII from fakes
        let faker = Faker::new(None, None);
        let email = "user@example.com";
        let fake = faker.fake(email, &PiiKind::Email);
        let body = format!("data: {{\"text\": \"{}\"}}\n\ndata: [DONE]\n\n", fake);
        let rehydrated = faker.rehydrate(&body);
        assert_eq!(
            rehydrated,
            format!("data: {{\"text\": \"{}\"}}\n\ndata: [DONE]\n\n", email)
        );
    }

    #[test]
    fn rehydrate_sse_body_reassembles_split_ip() {
        // Simulate SSE response where a fake IP is split across delta.content fields.
        // fake_ip(1) produces 47.53.71.98, which collides with the original 47.53.71.98.
        // Use a different original so the first call gets counter=1 → fake = "47.53.71.98".
        let faker = Faker::new(None, None);
        let original_ip = "10.0.0.1";
        let fake_ip_str = faker.fake(original_ip, &PiiKind::IpAddress);
        assert_eq!(fake_ip_str, "47.53.71.98");

        // SSE body: IP split across 4 content chunks, interspersed with role + finish
        let sse_body = format!(
            "data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"My IP is \"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"47\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\".53\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\".71\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\".98\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
             data: [DONE]\n\n"
        );

        let result = rehydrate_sse_body(&sse_body, &faker);

        // The fake IP "47.53.71.98" should be replaced with original IP "10.0.0.1"
        // in the first content chunk, and subsequent content chunks should have
        // their delta.content fields removed.
        assert!(
            result.contains("10.0.0.1"),
            "rehydrated body should contain the original IP\nGot: {}",
            result
        );
        assert!(
            !result.contains("47.53.71.98"),
            "rehydrated body should NOT contain the fake IP\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_preserves_unchanged() {
        // When no PII is in the response, rehydrate_sse_body is a no-op
        let faker = Faker::new(None, None);
        let body = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                    data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n\
                    data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
                    data: [DONE]\n\n";
        assert_eq!(rehydrate_sse_body(body, &faker), body);
    }

    #[test]
    fn rehydrate_sse_body_with_reasoning_field() {
        let faker = Faker::new(None, None);
        let original_ip = "10.0.0.1";
        let fake_ip_str = faker.fake(original_ip, &PiiKind::IpAddress);
        assert_eq!(fake_ip_str, "47.53.71.98");

        // SSE body: IP split across reasoning chunks
        let sse_body = format!(
            "data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\"My IP is \"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\"47\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\".53\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\".71\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\".98\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
             data: [DONE]\n\n"
        );

        let result = rehydrate_sse_body(&sse_body, &faker);
        assert!(
            result.contains("10.0.0.1"),
            "rehydrated body should contain original IP in reasoning\nGot: {}",
            result
        );
        assert!(
            !result.contains("47.53.71.98"),
            "rehydrated body should NOT contain fake IP in reasoning\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_with_reasoning_content_field() {
        let faker = Faker::new(None, None);
        let original_ip = "10.0.0.1";
        let fake_ip_str = faker.fake(original_ip, &PiiKind::IpAddress);
        assert_eq!(fake_ip_str, "47.53.71.98");

        // SSE body: IP split across reasoning_content chunks
        let sse_body = format!(
            "data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\"My IP is \"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\"47\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\".53\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\".71\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\".98\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
             data: [DONE]\n\n"
        );

        let result = rehydrate_sse_body(&sse_body, &faker);
        assert!(
            result.contains("10.0.0.1"),
            "rehydrated body should contain original IP in reasoning_content\nGot: {}",
            result
        );
        assert!(
            !result.contains("47.53.71.98"),
            "rehydrated body should NOT contain fake IP in reasoning_content\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_with_content_and_reasoning() {
        let faker = Faker::new(None, None);
        let original_ip = "10.0.0.1";
        let fake_ip_str = faker.fake(original_ip, &PiiKind::IpAddress);
        assert_eq!(fake_ip_str, "47.53.71.98");

        let original_email = "user@example.com";
        let fake_email_str = faker.fake(original_email, &PiiKind::Email);
        assert_ne!(fake_email_str, original_email);

        // SSE body: IP in reasoning, email in content
        let sse_body = format!(
            "data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\"My IP is \"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\"47\",\"content\":\"Contact \"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\".53\",\"content\":\"{fake_email_str}\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\".71\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\".98\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
             data: [DONE]\n\n"
        );

        let result = rehydrate_sse_body(&sse_body, &faker);
        assert!(
            result.contains("10.0.0.1"),
            "rehydrated body should contain original IP in reasoning\nGot: {}",
            result
        );
        assert!(
            result.contains("user@example.com"),
            "rehydrated body should contain original email in content\nGot: {}",
            result
        );
        assert!(
            !result.contains("47.53.71.98"),
            "rehydrated body should NOT contain fake IP\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_with_reasoning_and_reasoning_content_together() {
        let faker = Faker::new(None, None);
        let original_ip = "10.0.0.1";
        let fake_ip_str = faker.fake(original_ip, &PiiKind::IpAddress);
        assert_eq!(fake_ip_str, "47.53.71.98");

        // Single event has BOTH reasoning and reasoning_content fields
        // with the complete fake IP appearing in each field.
        let sse_body = format!(
            "data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning\":\"thinking about 47.53.71.98\",\"reasoning_content\":\"47.53.71.98\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
             data: [DONE]\n\n"
        );

        let result = rehydrate_sse_body(&sse_body, &faker);
        assert!(
            result.contains("10.0.0.1"),
            "rehydrated body should contain original IP\nGot: {}",
            result
        );
        assert!(
            !result.contains("47.53.71.98"),
            "rehydrated body should NOT contain fake IP\nGot: {}",
            result
        );
        // Both fields in the first event should be rehydrated
        assert!(
            result.contains("thinking about 10.0.0.1"),
            "reasoning field should be rehydrated\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_tool_calls_single_event() {
        let faker = Faker::new(None, None);
        faker.add_custom_mapping("Nathan", "john", None);

        // Tool calls arguments in a single SSE event (no splitting)
        let sse_body = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                        data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"list_files\",\"arguments\":\"{\\\"path\\\":\\\"/home/john/Nixos-dev-ai\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
                        data: [DONE]\n\n";

        let result = rehydrate_sse_body(&sse_body, &faker);
        assert!(
            result.contains("/home/Nathan/Nixos-dev-ai"),
            "single-event tool_calls arguments should be rehydrated\nGot: {}",
            result
        );
        assert!(
            !result.contains("john"),
            "'john' should be rehydrated away in single event\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_tool_calls_split_across_events() {
        let faker = Faker::new(None, None);
        faker.add_custom_mapping("Nathan", "john", None);

        // Tool calls arguments split across multiple SSE events (common in streaming)
        // "john" appears split: "jo" in event 1, "hn" in event 2
        let sse_body = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                        data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"list_files\",\"arguments\":\"{\\\"path\\\":\\\"/home/jo\"}}]},\"finish_reason\":null}]}\n\n\
                        data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"hn/Nixos-dev-ai\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
                        data: [DONE]\n\n";

        let result = rehydrate_sse_body(&sse_body, &faker);
        // Cross-chunk join rehydrates the concatenated arguments and puts them
        // in the first event. Subsequent events have their arguments field removed.
        assert!(
            result.contains("/home/Nathan/Nixos-dev-ai"),
            "cross-event tool_calls arguments should be rehydrated\nGot: {}",
            result
        );
        assert!(
            !result.contains("jo"),
            "split 'jo' should be rehydrated\nGot: {}",
            result
        );
        assert!(
            !result.contains("hn"),
            "split 'hn' should be rehydrated\nGot: {}",
            result
        );
    }

    #[test]
    fn rehydrate_sse_body_tool_calls_split_with_regex_boundaries() {
        let faker = Faker::new(None, None);
        // Same scenario but with a pattern string — exercises the regex-bounded path
        faker.add_custom_mapping("Nathan", "john", Some(r"\bnathan\b"));

        // "john" split across events as in the None-pattern test
        let sse_body = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                        data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"list_files\",\"arguments\":\"{\\\"path\\\":\\\"/home/jo\"}}]},\"finish_reason\":null}]}\n\n\
                        data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"hn/Nixos-dev-ai\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
                        data: [DONE]\n\n";

        let result = rehydrate_sse_body(&sse_body, &faker);
        assert!(
            result.contains("/home/Nathan/Nixos-dev-ai"),
            "regex-bounded cross-event rehydration should work\nGot: {}",
            result
        );

        // "john" in midword should NOT rehydrate (would trigger without regex boundaries)
        let sse_body2 = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"foo\",\"arguments\":\"{\\\"name\\\":\\\"johnathan\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
                         data: [DONE]\n\n";
        let result2 = rehydrate_sse_body(&sse_body2, &faker);
        assert!(
            !result2.contains("nathanathan"),
            "midword 'johnathan' must not rehydrate with regex boundaries\nGot: {}",
            result2
        );
    }

    /// Cross-chunk tool_calls limitation: when tool_calls arguments are split
    /// across separate `rehydrate_sse_body` calls (as happens in the streaming
    /// path), the substitute cannot be joined and rehydrated. Only the buffered
    /// path (which passes the full SSE body at once) handles this correctly.
    #[test]
    fn rehydrate_sse_body_cross_chunk_tool_calls_limitation() {
        let faker = Faker::new(None, None);
        faker.add_custom_mapping("Nathan", "john", Some(r"\bnathan\b"));

        // Chunk 1: first event (role) + second event (partial tool_calls args)
        let chunk1 = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                      data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"list_files\",\"arguments\":\"{\\\"path\\\":\\\"/home/jo\"}}]},\"finish_reason\":null}]}\n\n";
        let result1 = rehydrate_sse_body(chunk1, &faker);
        // Partial "jo" should NOT rehydrate (no "john" to match)
        assert!(
            !result1.contains("Nathan"),
            "cross-chunk partial 'jo' must not rehydrate alone\nGot: {}",
            result1
        );

        // Chunk 2: continuation of tool_calls arguments + [DONE]
        let chunk2 = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"hn/Nixos-dev-ai\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
                      data: [DONE]\n\n";
        let result2 = rehydrate_sse_body(chunk2, &faker);
        // Continuation "hn" should also NOT rehydrate
        assert!(
            !result2.contains("Nathan"),
            "cross-chunk continuation 'hn' must not rehydrate alone\nGot: {}",
            result2
        );

        // Full body (both chunks combined) — should rehydrate correctly
        let full = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                    data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"list_files\",\"arguments\":\"{\\\"path\\\":\\\"/home/jo\"}}]},\"finish_reason\":null}]}\n\n\
                    data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"hn/Nixos-dev-ai\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
                    data: [DONE]\n\n";
        let result_full = rehydrate_sse_body(full, &faker);
        assert!(
            result_full.contains("/home/Nathan/Nixos-dev-ai"),
            "buffered full body must rehydrate cross-chunk tool_calls\nGot: {}",
            result_full
        );
    }

    /// Standard PII (IP address) inside tool_calls arguments.
    /// Phase 1b joins arguments and calls faker.rehydrate() on the result,
    /// then Phase 2 rehydrates all string values as a catch-all.
    #[test]
    fn rehydrate_sse_body_standard_pii_in_tool_calls() {
        let mut maps = crate::faker::FakerMaps::new();
        maps.reverse
            .insert("84.106.142.195".to_string(), "192.168.1.1".to_string());
        maps.forward
            .insert("192.168.1.1".to_string(), "84.106.142.195".to_string());
        let faker = crate::faker::Faker::from_maps(maps, None);

        // Tool calls with arguments containing the fake IP
        let sse_body = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n\
                        data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"connect\",\"arguments\":\"{\\\"host\\\":\\\"84.106.142.195\\\",\\\"port\\\":22}\"}}]},\"finish_reason\":null}]}\n\n\
                        data: [DONE]\n\n";

        let result = rehydrate_sse_body(sse_body, &faker);
        assert!(
            result.contains("192.168.1.1"),
            "standard IP in tool_calls arguments should rehydrate\nGot: {}",
            result
        );
        assert!(
            !result.contains("84.106.142.195"),
            "fake IP should be replaced\nGot: {}",
            result
        );
    }

    /// Standard PII inside a custom provider field (non-OpenAI JSON field).
    /// Phase 2 universal rehydration catches ANY string value, not just
    /// known OpenAI fields like content/tool_calls.
    #[test]
    fn rehydrate_sse_body_standard_pii_in_custom_field() {
        let mut maps = crate::faker::FakerMaps::new();
        maps.reverse
            .insert("84.106.142.195".to_string(), "192.168.1.1".to_string());
        maps.forward
            .insert("192.168.1.1".to_string(), "84.106.142.195".to_string());
        let faker = crate::faker::Faker::from_maps(maps, None);

        // Custom provider response with a non-standard field containing the fake IP
        let sse_body = "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null,\"x_custom_metadata\":\"connected from 84.106.142.195\"}]}\n\n\
                        data: [DONE]\n\n";

        let result = rehydrate_sse_body(sse_body, &faker);
        assert!(
            result.contains("connected from 192.168.1.1"),
            "standard IP in custom field should rehydrate\nGot: {}",
            result
        );
        assert!(
            !result.contains("84.106.142.195"),
            "fake IP should be replaced in custom field\nGot: {}",
            result
        );
    }
}

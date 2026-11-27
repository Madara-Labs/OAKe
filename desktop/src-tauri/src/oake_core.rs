use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, TimeZone, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const SHA256_OID_BYTES: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

const OTS_MAGIC: [u8; 31] = [
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];
const OTS_VERSION: u8 = 0x01;
const OP_ATTESTATION: u8 = 0x00;
const OP_SHA1: u8 = 0x02;
const OP_RIPEMD160: u8 = 0x03;
const OP_SHA256: u8 = 0x08;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_FORK: u8 = 0xff;
const TAG_PENDING_ATTESTATION: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const TAG_BITCOIN_ATTESTATION: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x1b, 0x45];
const TAG_BITCOIN_ATTESTATION_ALT: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const OAKE_TRAILER_MARKER: &[u8] = b"\x00OAKE_ANCHOR_META\x00";
const MAX_OTS_OPERAND_LENGTH: usize = 4096;
const MAX_OTS_TREE_DEPTH: usize = 256;

const OTS_MIN_SUBMIT_INTERVAL_MS: u64 = 60_000;
const OTS_CIRCUIT_BREAKER_MS: u64 = 600_000;
const HTTP_TIMEOUT_SECS: u64 = 8;

const USER_AGENT_TSA: &str = "OAKe-Desktop/0.1 (standalone-rfc3161-client)";
const USER_AGENT_OTS_SUBMIT: &str =
    "OAKe-Desktop/0.1 (batched-merkle-aggregator; max-1req-per-min)";

struct TsaAuthorityDesc {
    tsa: &'static str,
    url: &'static str,
    jurisdiction: &'static str,
}

const PRIMARY_TSA_EU: TsaAuthorityDesc = TsaAuthorityDesc {
    tsa: "certum-eu",
    url: "http://time.certum.pl",
    jurisdiction: "EU / Poland (Asseco Certum eIDAS QTSA)",
};

const SECONDARY_TSA_US: TsaAuthorityDesc = TsaAuthorityDesc {
    tsa: "digicert-us",
    url: "http://timestamp.digicert.com",
    jurisdiction: "US / WebTrust (DigiCert Assured ID TSA)",
};

const SECONDARY_TSA_FAILOVER_UK: TsaAuthorityDesc = TsaAuthorityDesc {
    tsa: "sectigo-uk",
    url: "http://timestamp.sectigo.com",
    jurisdiction: "UK / WebTrust (Sectigo Qualified TSA)",
};

const OTS_CALENDARS: &[(&str, &str)] = &[
    (
        "https://alice.btc.calendar.opentimestamps.org",
        "alice.btc.calendar.opentimestamps.org",
    ),
    (
        "https://finney.calendar.eternitywall.com",
        "finney.calendar.eternitywall.com",
    ),
    (
        "https://bob.btc.calendar.opentimestamps.org",
        "bob.btc.calendar.opentimestamps.org",
    ),
];

static ULID_STATE: Mutex<(u64, [u8; 10])> = Mutex::new((0, [0u8; 10]));

// ============================================================================
// Public DTOs (JSON contracts for Tauri UI)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub pubkey: String,
    pub short_fingerprint: String,
    pub key_path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    pub path: String,
    pub name: String,
    pub exists: bool,
    pub added_at: String,
    pub total_files: usize,
    pub anchored_count: usize,
    pub modified_count: usize,
    pub untracked_count: usize,
    pub commit_count: usize,
    pub chain_valid: bool,
    pub last_anchored_ts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceFileEntry {
    pub relative_path: String,
    pub name: String,
    pub artifact_kind: String,
    pub canonicalization: String,
    pub artifact_hash: String,
    pub byte_size: u64,
    pub modified_ts: String,
    pub status: String, // "untracked" | "modified" | "anchored"
    pub latest_entry_id: Option<String>,
    pub latest_anchored_ts: Option<String>,
    pub ots_status: Option<String>,
    pub tsa_count: usize,
    pub published_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceCommit {
    pub sequence: u64,
    pub entry_id: String,
    pub artifact_hash: String,
    pub canonicalization: String,
    pub ots_status: String,
    pub tsa_count: usize,
    pub published_to: Option<String>,
    pub bundle_path: String,
    pub captured_ts: String,
    pub prev_entry_hash: String,
    pub entry_hash: String,
    pub path_hint: Option<String>,
    pub file_label: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceCounts {
    pub total: usize,
    pub untracked: usize,
    pub modified: usize,
    pub anchored: usize,
    pub commits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceScanResult {
    pub workspace_path: String,
    pub workspace_name: String,
    pub files: Vec<WorkspaceFileEntry>,
    pub commits: Vec<ProvenanceCommit>,
    pub chain_valid: bool,
    pub counts: WorkspaceCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchoredEntryResult {
    pub relative_path: String,
    pub entry_id: String,
    pub sequence: u64,
    pub artifact_hash: String,
    pub canonicalization: String,
    pub ots_status: String,
    pub tsa_count: usize,
    pub tsas: Vec<String>,
    pub bundle_path: String,
    pub captured_ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorBatchResult {
    pub workspace_path: String,
    pub batch_id: String,
    pub merkle_root: String,
    pub ots_mode: String, // "pending" | "provisional" | "offline"
    pub ots_calendar: String,
    pub ots_rate_limited: bool,
    pub ots_retry_after_secs: Option<u64>,
    pub anchored_count: usize,
    pub warnings: Vec<String>,
    pub entries: Vec<AnchoredEntryResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsrCheckSummary {
    pub filename: String,
    pub tsa: Option<String>,
    pub der_valid: bool,
    pub digest_matches: bool,
    pub gen_time: Option<String>,
    pub serial_number: Option<String>,
    pub openssl_verified: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleVerifyResult {
    /// True only when `verdict` is "verified".
    pub valid: bool,
    /// "verified" | "incomplete" | "failed"
    pub verdict: String,
    pub bundle_path: String,
    pub entry_id: String,
    pub artifact_hash: String,
    pub canonicalization: String,
    pub user_pubkey: String,
    pub client_ts: String,
    pub received_ts: String,
    pub signature_signed: bool,
    pub signature_valid: bool,
    pub file_checked: bool,
    pub file_matches: Option<bool>,
    pub ots_header_valid: bool,
    pub ots_digest_matches: bool,
    pub ots_status: String,
    pub ots_steps: usize,
    pub ots_btc_block: Option<u64>,
    pub ots_calendar: Option<String>,
    pub tsa_tokens: Vec<TsrCheckSummary>,
    pub verify_md_present: bool,
    pub conclusion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushItemResult {
    pub entry_id: String,
    pub bundle_path: String,
    pub witnessed: bool,
    pub deduplicated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushSummary {
    pub workspace_path: String,
    pub endpoint: String,
    pub total_bundles: usize,
    pub pushed_count: usize,
    pub deduplicated_count: usize,
    pub already_published_count: usize,
    pub failed_count: usize,
    pub results: Vec<PushItemResult>,
}

// ============================================================================
// Internal Protocol & Storage Structs
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentityFile {
    pubkey: String,
    #[serde(rename = "privateKeyPem")]
    private_key_pem: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredWorkspaceRecord {
    path: String,
    added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalIndexRow {
    sequence: u64,
    prev_entry_hash: String,
    entry_hash: String,
    entry_id: String,
    artifact_hash: String,
    canonicalization: String,
    ots_status: String,
    tsa_count: usize,
    published_to: Option<String>,
    bundle_path: String,
    captured_ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rfc3161TokenRecord {
    tsa: String,
    token_ref: String,
    gen_time: String,
    serial_number: String,
    cert_not_after: String,
    restamped_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtsRecord {
    status: String,
    proof_ref: String,
    calendar: String,
    batch_id: String,
    btc_block: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    btc_block_time: Option<String>,
    btc_merkle_root: Option<String>,
    upgraded_ts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntryMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainRecord {
    sequence: u64,
    prev_entry_hash: String,
    entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    entry_id: String,
    user_pubkey: String,
    artifact_hash: String,
    canonicalization: String,
    signature: String,
    client_ts: String,
    received_ts: String,
    rfc3161_tokens: Vec<Rfc3161TokenRecord>,
    ots: OtsRecord,
    capture_source: String,
    metadata: EntryMetadata,
    chain: ChainRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct HostBackoffState {
    backoff_until_ms: u64,
    last_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OtsRateGuardState {
    last_submit_ms: Option<u64>,
    #[serde(default)]
    last_poll_by_commitment: HashMap<String, u64>,
    #[serde(default)]
    host_backoffs: HashMap<String, HostBackoffState>,
    #[serde(default)]
    total_http_posts: u64,
    #[serde(default)]
    total_http_gets: u64,
    #[serde(default)]
    blocked_submit_floods: u64,
    #[serde(default)]
    blocked_poll_floods: u64,
    last_calendar_used: Option<String>,
}

// ============================================================================
// Paths, Time, Base64, ULID & Canonical JSON
// ============================================================================

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn format_iso_millis(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn now_iso() -> String {
    format_iso_millis(Utc::now())
}

fn get_oake_home() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("OAKE_HOME") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join(".config").join("oake"));
    }
    if let Some(cfg) = dirs::config_dir() {
        return Ok(cfg.join("oake"));
    }
    Err("Could not determine home directory for ~/.config/oake".to_string())
}

/// Resolve a path typed by a person: trims it and expands a leading `~`.
fn expand_user_path(input: &str, home: Option<&Path>) -> PathBuf {
    let trimmed = input.trim();
    if let Some(home) = home {
        if trimmed == "~" {
            return home.to_path_buf();
        }
        if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
            return home.join(rest);
        }
    }
    PathBuf::from(trimmed)
}

fn clean_path_string(p: &Path) -> String {
    let raw = p.to_string_lossy().to_string();
    #[cfg(windows)]
    {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            return stripped.to_string();
        }
    }
    raw
}

fn normalize_rel_path(rel: &Path) -> String {
    rel.components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn resolve_safe_workspace_file(workspace_root: &Path, relative_path: &str) -> Result<PathBuf, String> {
    let normalized = relative_path.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(format!("Invalid relative file path: {}", relative_path));
    }
    let rel = Path::new(trimmed);
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return Err(format!("Unsafe relative file path: {}", relative_path)),
        }
    }
    let abs = workspace_root.join(rel);
    if !abs.is_file() {
        return Err(format!("File does not exist: {}", abs.display()));
    }
    Ok(abs)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha256_bytes(data)))
}

fn encode_40bits_base32(bytes: &[u8], offset: usize) -> String {
    let val: u64 = ((bytes[offset] as u64) << 32)
        | ((bytes[offset + 1] as u64) << 24)
        | ((bytes[offset + 2] as u64) << 16)
        | ((bytes[offset + 3] as u64) << 8)
        | (bytes[offset + 4] as u64);
    let mut out = String::with_capacity(8);
    for shift in (0..=35).rev().step_by(5) {
        let idx = ((val >> shift) & 0x1f) as usize;
        out.push(CROCKFORD_ALPHABET[idx] as char);
    }
    out
}

fn generate_ulid_at(ts_ms: u64) -> String {
    let mut guard = ULID_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let (ref mut last_ts, ref mut last_rand) = *guard;

    let ts = if ts_ms <= *last_ts && *last_ts > 0 {
        let mut carry: u16 = 1;
        for i in (0..10).rev() {
            let next = last_rand[i] as u16 + carry;
            last_rand[i] = (next & 0xff) as u8;
            carry = next >> 8;
            if carry == 0 {
                break;
            }
        }
        if carry > 0 {
            *last_ts += 1;
            *last_rand = [0u8; 10];
        }
        *last_ts
    } else {
        *last_ts = ts_ms;
        OsRng.fill_bytes(last_rand);
        ts_ms
    };

    let mut time_chars = ['0'; 10];
    let mut t = ts;
    for i in (0..10).rev() {
        time_chars[i] = CROCKFORD_ALPHABET[(t % 32) as usize] as char;
        t /= 32;
    }

    let mut ulid = String::with_capacity(26);
    for c in time_chars {
        ulid.push(c);
    }
    ulid.push_str(&encode_40bits_base32(last_rand, 0));
    ulid.push_str(&encode_40bits_base32(last_rand, 5));
    ulid
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if cleaned.len() % 4 != 0 || cleaned.is_empty() {
        return Err("Invalid base64 length in PEM key".to_string());
    }

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        let a = val(chunk[0]).ok_or_else(|| "Invalid base64 character".to_string())?;
        let b = val(chunk[1]).ok_or_else(|| "Invalid base64 character".to_string())?;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        let c = if pad2 {
            0
        } else {
            val(chunk[2]).ok_or_else(|| "Invalid base64 character".to_string())?
        };
        let d = if pad3 {
            0
        } else {
            val(chunk[3]).ok_or_else(|| "Invalid base64 character".to_string())?
        };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((triple >> 16) & 0xff) as u8);
        if !pad2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if !pad3 {
            out.push((triple & 0xff) as u8);
        }
    }
    Ok(out)
}

fn serialize_canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(serialize_canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for k in keys {
                if let Some(v) = map.get(k) {
                    let key_json =
                        serde_json::to_string(k).unwrap_or_else(|_| "\"\"".to_string());
                    parts.push(format!("{}:{}", key_json, serialize_canonical_json(v)));
                }
            }
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn compute_entry_chain_hash(entry_core: &Value) -> String {
    let canonical = serialize_canonical_json(entry_core);
    sha256_prefixed(canonical.as_bytes())
}

// ============================================================================
// Identity (Ed25519 PKCS#8 PEM Compatible with OAKe CLI)
// ============================================================================

fn encode_pkcs8_pem(seed: &[u8; 32]) -> String {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&PKCS8_ED25519_PREFIX);
    der.extend_from_slice(seed);
    let b64 = base64_encode(&der);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64
    )
}

fn decode_pkcs8_pem_seed(pem: &str) -> Result<[u8; 32], String> {
    let body: String = pem
        .lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with("-----BEGIN") && !t.starts_with("-----END")
        })
        .collect::<Vec<_>>()
        .join("");

    let der = base64_decode(&body)?;
    if der.len() == 48 && der[..16] == PKCS8_ED25519_PREFIX {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&der[16..48]);
        return Ok(seed);
    }

    // Fallback: locate inner OCTET STRING `04 20 <32 bytes>` in PKCS#8 Ed25519 DER
    if der.len() >= 34 {
        let has_oid = der.windows(5).any(|w| w == [0x06, 0x03, 0x2b, 0x65, 0x70]);
        if has_oid && der[der.len() - 34] == 0x04 && der[der.len() - 33] == 0x20 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&der[der.len() - 32..]);
            return Ok(seed);
        }
    }

    Err("Unsupported or malformed Ed25519 PKCS#8 PEM key".to_string())
}

fn load_or_create_identity_internal() -> Result<(StoredIdentityFile, SigningKey, PathBuf), String> {
    let oake_home = get_oake_home()?;
    fs::create_dir_all(&oake_home)
        .map_err(|e| format!("Failed to create {}: {}", oake_home.display(), e))?;

    let key_path = oake_home.join("id_ed25519.json");
    let config_path = oake_home.join("config.yaml");

    let stored = if key_path.exists() {
        let raw = fs::read_to_string(&key_path)
            .map_err(|e| format!("Failed to read {}: {}", key_path.display(), e))?;
        serde_json::from_str::<StoredIdentityFile>(&raw)
            .map_err(|e| format!("Failed to parse {}: {}", key_path.display(), e))?
    } else {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = format!(
            "ed25519:{}",
            hex::encode(signing_key.verifying_key().to_bytes())
        );
        let created = StoredIdentityFile {
            pubkey,
            private_key_pem: encode_pkcs8_pem(&seed),
            created_at: now_iso(),
        };
        let serialized = format!(
            "{}\n",
            serde_json::to_string_pretty(&created).map_err(|e| e.to_string())?
        );
        fs::write(&key_path, serialized)
            .map_err(|e| format!("Failed to write {}: {}", key_path.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        created
    };

    if !config_path.exists() {
        let sample_config = format!(
            "# ~/.config/oake/config.yaml — OAKe Provenance Micro-Utility\nidentity:\n  keyfile: {}\nservice:\n  endpoint: http://localhost:3000\ncapture:\n  git_hook: true\n  snapshot_interval: 24h\n  ignore: [ \"*.log\", \"*.aux\", \"*.pdf\", \".git/**\", \"**/node_modules/**\", \"**/target/**\" ]\nprivacy:\n  hash_paths: true\n",
            key_path.display()
        );
        let _ = fs::write(&config_path, sample_config);
    }

    let seed = decode_pkcs8_pem_seed(&stored.private_key_pem)?;
    let signing_key = SigningKey::from_bytes(&seed);

    Ok((stored, signing_key, key_path))
}

pub fn get_identity() -> Result<IdentityInfo, String> {
    let (stored, _, key_path) = load_or_create_identity_internal()?;
    let hex_part = stored
        .pubkey
        .strip_prefix("ed25519:")
        .unwrap_or(&stored.pubkey);
    let short_fingerprint: String = hex_part.chars().take(16).collect();
    Ok(IdentityInfo {
        pubkey: stored.pubkey,
        short_fingerprint,
        key_path: clean_path_string(&key_path),
        created_at: stored.created_at,
    })
}

fn sign_artifact_payload(
    signing_key: &SigningKey,
    artifact_hash: &str,
    canon: &str,
    client_ts: &str,
) -> String {
    let payload = format!("{}|{}|{}", artifact_hash, canon, client_ts);
    let sig: Signature = signing_key.sign(payload.as_bytes());
    format!("ed25519:{}", hex::encode(sig.to_bytes()))
}

fn verify_ed25519_signature(
    user_pubkey: &str,
    signature: &str,
    artifact_hash: &str,
    canon: &str,
    client_ts: &str,
) -> (bool, bool) {
    if user_pubkey == "anonymous" {
        return (false, signature == "none");
    }
    let Some(pub_hex) = user_pubkey.strip_prefix("ed25519:") else {
        return (true, false);
    };
    let Some(sig_hex) = signature.strip_prefix("ed25519:") else {
        return (true, false);
    };
    let Ok(pub_vec) = hex::decode(pub_hex) else {
        return (true, false);
    };
    let Ok(sig_vec) = hex::decode(sig_hex) else {
        return (true, false);
    };
    let Ok(pub_arr): Result<[u8; 32], _> = pub_vec.try_into() else {
        return (true, false);
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_vec.try_into() else {
        return (true, false);
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_arr) else {
        return (true, false);
    };
    let sig = Signature::from_bytes(&sig_arr);
    let payload = format!("{}|{}|{}", artifact_hash, canon, client_ts);
    (true, verifying_key.verify(payload.as_bytes(), &sig).is_ok())
}

// ============================================================================
// Canonicalization & File Classification
// ============================================================================

fn validate_canon_method(method: &str) -> Result<(), String> {
    match method {
        "raw-bytes/v1" | "text-normalized/v1" | "ipynb-cells/v1" => Ok(()),
        _ => Err(format!(
            "Unsupported canonicalization method \"{}\". Allowed: raw-bytes/v1, text-normalized/v1, ipynb-cells/v1",
            method
        )),
    }
}

fn infer_default_canon(path: &Path, override_canon: Option<&str>) -> Result<String, String> {
    if let Some(explicit) = override_canon {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            validate_canon_method(trimmed)?;
            return Ok(trimmed.to_string());
        }
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "ipynb" {
        Ok("ipynb-cells/v1".to_string())
    } else {
        Ok("raw-bytes/v1".to_string())
    }
}

fn infer_artifact_kind(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "tex" | "bib" => "latex",
        "ipynb" => "notebook",
        "py" | "ts" | "tsx" | "js" | "mjs" | "rs" | "go" | "c" | "cpp" | "h" | "hpp" => "code",
        "md" | "txt" | "rst" => "text",
        "csv" | "json" | "parquet" | "tsv" => "dataset",
        _ => "file",
    }
}

fn canonicalize_and_hash(file_path: &Path, canon_method: &str) -> Result<(String, u64), String> {
    validate_canon_method(canon_method)?;
    let raw_bytes = fs::read(file_path)
        .map_err(|e| format!("Failed to read {}: {}", file_path.display(), e))?;
    let byte_size = raw_bytes.len() as u64;

    match canon_method {
        "raw-bytes/v1" => Ok((sha256_prefixed(&raw_bytes), byte_size)),
        "text-normalized/v1" => {
            let raw_text = String::from_utf8_lossy(&raw_bytes);
            let normalized_cr = raw_text.replace("\r\n", "\n").replace('\r', "\n");
            let normalized = normalized_cr
                .split('\n')
                .map(|line| line.trim_end_matches(&[' ', '\t'][..]))
                .collect::<Vec<_>>()
                .join("\n");
            Ok((sha256_prefixed(normalized.as_bytes()), byte_size))
        }
        "ipynb-cells/v1" => {
            let raw_text = String::from_utf8_lossy(&raw_bytes);
            let parsed: Value = serde_json::from_str(&raw_text).map_err(|e| {
                format!("Invalid .ipynb JSON in {}: {}", file_path.display(), e)
            })?;
            let cells = parsed
                .get("cells")
                .and_then(|v| v.as_array())
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let mut combined = Vec::with_capacity(cells.len() * 32);
            for cell in cells {
                let cell_type = cell
                    .get("cell_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let source_text = match cell.get("source") {
                    Some(Value::Array(arr)) => arr
                        .iter()
                        .map(|part| match part {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(""),
                    Some(Value::String(s)) => s.clone(),
                    _ => String::new(),
                };
                let cell_input = format!("{}\n{}", cell_type, source_text);
                combined.extend_from_slice(&sha256_bytes(cell_input.as_bytes()));
            }
            Ok((sha256_prefixed(&combined), byte_size))
        }
        _ => Err(format!("Unsupported canonicalization method: {}", canon_method)),
    }
}

fn should_skip_dir(name: &str) -> bool {
    matches!(name, ".git" | "node_modules" | ".oake" | "target")
}

fn should_skip_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "log" | "aux" | "pdf")
}

fn collect_workspace_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    if !root.is_dir() {
        return Err(format!("Workspace path is not a directory: {}", root.display()));
    }
    let mut collected = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)
            .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?
            .filter_map(|res| res.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if file_type.is_dir() {
                if should_skip_dir(&name) {
                    continue;
                }
                walk(&path, out)?;
            } else if file_type.is_file() {
                if should_skip_file(&path) {
                    continue;
                }
                out.push(path);
            }
        }
        Ok(())
    }
    walk(root, &mut collected)?;
    Ok(collected)
}

// ============================================================================
// Local .oake/index.jsonl & Bundle Reading/Writing
// ============================================================================

fn read_local_index(index_path: &Path) -> Result<Vec<LocalIndexRow>, String> {
    if !index_path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(index_path)
        .map_err(|e| format!("Failed to read {}: {}", index_path.display(), e))?;
    let mut rows = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row: LocalIndexRow = serde_json::from_str(trimmed).map_err(|e| {
            format!(
                "Invalid JSON in {} line {}: {}",
                index_path.display(),
                idx + 1,
                e
            )
        })?;
        rows.push(row);
    }
    Ok(rows)
}

fn write_local_index(index_path: &Path, rows: &[LocalIndexRow]) -> Result<(), String> {
    if let Some(parent) = index_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    let mut content = String::new();
    for row in rows {
        content.push_str(&serde_json::to_string(row).map_err(|e| e.to_string())?);
        content.push('\n');
    }
    fs::write(index_path, content)
        .map_err(|e| format!("Failed to write {}: {}", index_path.display(), e))
}

fn append_local_index_row(index_path: &Path, row: &LocalIndexRow) -> Result<(), String> {
    if let Some(parent) = index_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(index_path)
        .map_err(|e| format!("Failed to open {}: {}", index_path.display(), e))?;
    let line = format!(
        "{}\n",
        serde_json::to_string(row).map_err(|e| e.to_string())?
    );
    file.write_all(line.as_bytes())
        .map_err(|e| format!("Failed to append {}: {}", index_path.display(), e))
}

fn verify_index_chain(rows: &[LocalIndexRow]) -> bool {
    let mut expected_prev = GENESIS_PREV_HASH;
    for row in rows {
        if row.prev_entry_hash != expected_prev {
            return false;
        }
        expected_prev = &row.entry_hash;
    }
    true
}

fn read_entry_from_bundle_file(bundle_path: &Path) -> Option<LedgerEntry> {
    let bytes = fs::read(bundle_path).ok()?;
    let mut archive = ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut entry_file = archive.by_name("entry.json").ok()?;
    let mut buf = String::new();
    entry_file.read_to_string(&mut buf).ok()?;
    serde_json::from_str::<LedgerEntry>(&buf).ok()
}

fn generate_verify_markdown(entry: &LedgerEntry) -> String {
    let btc_block_display = entry
        .ots
        .btc_block
        .map(|b| b.to_string())
        .unwrap_or_else(|| "pending".to_string());
    let btc_root_display = entry
        .ots
        .btc_merkle_root
        .as_deref()
        .unwrap_or("pending");

    let tsa_list = if entry.rfc3161_tokens.is_empty() {
        "- _(none recorded — offline capture or TSA unreachable)_".to_string()
    } else {
        entry
            .rfc3161_tokens
            .iter()
            .map(|t| {
                let rel = t.token_ref.replace("blob://tsr/", "rfc3161/");
                let fmt = t.format.as_deref().unwrap_or("rfc3161-cms-der");
                format!(
                    "- `{}` — TSA: `{}`, format: `{}`, serial: `{}`, gen_time: `{}`",
                    rel, t.tsa, fmt, t.serial_number, t.gen_time
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let digest_hex = entry
        .artifact_hash
        .strip_prefix("sha256:")
        .unwrap_or(&entry.artifact_hash);

    format!(
        "# OAKe Independent Proof Verification Guide\n\n\
This bundle (`application/oake-bundle+zip`) is 100% self-contained. You do **not** need Madara Labs or any OAKe server to verify it.\n\n\
## Artifact Summary\n\n\
| Field | Value |\n\
| --- | --- |\n\
| `entry_id` | `{}` |\n\
| `artifact_hash` | `{}` |\n\
| `canonicalization` | `{}` |\n\
| `user_pubkey` | `{}` |\n\
| `client_ts` | `{}` |\n\
| `received_ts` | `{}` |\n\
| `ots.status` | `{}` |\n\
| `ots.calendar` | `{}` |\n\
| `ots.btc_block` | `{}` |\n\
| `ots.btc_merkle_root` | `{}` |\n\n\
## Step 1: Verify Ed25519 Signature\n\n\
Signed payload:\n\
```text\n\
{}|{}|{}\n\
```\n\n\
## Step 2: Verify `rfc3161/*.tsr` via OpenSSL System Root CAs\n\n\
{}\n\n\
```bash\n\
openssl ts -verify -digest {} -in rfc3161/<token>.tsr -CAfile /etc/ssl/cert.pem\n\
```\n\n\
## Step 3: Verify `proof.ots` Against Bitcoin\n\n\
```bash\n\
ots verify proof.ots\n\
```\n",
        entry.entry_id,
        entry.artifact_hash,
        entry.canonicalization,
        entry.user_pubkey,
        entry.client_ts,
        entry.received_ts,
        entry.ots.status,
        entry.ots.calendar,
        btc_block_display,
        btc_root_display,
        entry.artifact_hash,
        entry.canonicalization,
        entry.client_ts,
        tsa_list,
        digest_hex
    )
}

fn build_bundle_zip_bytes(
    entry: &LedgerEntry,
    tsr_blobs: &[(String, Vec<u8>)],
    ots_blob: &[u8],
) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        let entry_json = format!(
            "{}\n",
            serde_json::to_string_pretty(entry).map_err(|e| e.to_string())?
        );
        zip.start_file("entry.json", options)
            .map_err(|e| format!("ZIP write error: {}", e))?;
        zip.write_all(entry_json.as_bytes())
            .map_err(|e| format!("ZIP write error: {}", e))?;

        for (filename, data) in tsr_blobs {
            let clean = filename
                .trim_start_matches("rfc3161/")
                .trim_start_matches('/');
            zip.start_file(format!("rfc3161/{}", clean), options)
                .map_err(|e| format!("ZIP write error: {}", e))?;
            zip.write_all(data)
                .map_err(|e| format!("ZIP write error: {}", e))?;
        }

        zip.start_file("proof.ots", options)
            .map_err(|e| format!("ZIP write error: {}", e))?;
        zip.write_all(ots_blob)
            .map_err(|e| format!("ZIP write error: {}", e))?;

        let verify_md = generate_verify_markdown(entry);
        zip.start_file("VERIFY.md", options)
            .map_err(|e| format!("ZIP write error: {}", e))?;
        zip.write_all(verify_md.as_bytes())
            .map_err(|e| format!("ZIP write error: {}", e))?;

        zip.finish()
            .map_err(|e| format!("ZIP finalize error: {}", e))?;
    }
    Ok(cursor.into_inner())
}

// ============================================================================
// ASN.1 DER & Direct RFC 3161 External TSA Client
// ============================================================================

fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut rem = len;
    while rem > 0 {
        bytes.push((rem & 0xff) as u8);
        rem >>= 8;
    }
    bytes.reverse();
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
    out
}

fn encode_der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len_bytes = encode_der_length(value.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + value.len());
    out.push(tag);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(value);
    out
}

fn encode_der_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return encode_der_tlv(0x02, &[0x00]);
    }
    let be = value.to_be_bytes();
    let first_non_zero = be.iter().position(|&b| b != 0).unwrap_or(7);
    let slice = &be[first_non_zero..];
    if (slice[0] & 0x80) != 0 {
        let mut padded = Vec::with_capacity(slice.len() + 1);
        padded.push(0x00);
        padded.extend_from_slice(slice);
        encode_der_tlv(0x02, &padded)
    } else {
        encode_der_tlv(0x02, slice)
    }
}

fn build_rfc3161_timestamp_req(digest32: &[u8; 32]) -> Vec<u8> {
    let mut rand_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rand_bytes);
    let nonce = u64::from_be_bytes(rand_bytes) & ((1u64 << 63) - 1);

    let version_der = encode_der_tlv(0x02, &[0x01]);
    let oid_der = encode_der_tlv(0x06, &SHA256_OID_BYTES);
    let null_der = encode_der_tlv(0x05, &[]);
    let mut alg_inner = Vec::with_capacity(oid_der.len() + null_der.len());
    alg_inner.extend_from_slice(&oid_der);
    alg_inner.extend_from_slice(&null_der);
    let hash_alg_der = encode_der_tlv(0x30, &alg_inner);

    let hashed_msg_der = encode_der_tlv(0x04, digest32);
    let mut imprint_inner = Vec::with_capacity(hash_alg_der.len() + hashed_msg_der.len());
    imprint_inner.extend_from_slice(&hash_alg_der);
    imprint_inner.extend_from_slice(&hashed_msg_der);
    let message_imprint_der = encode_der_tlv(0x30, &imprint_inner);

    let nonce_der = encode_der_u64(nonce);
    let cert_req_der = encode_der_tlv(0x01, &[0xff]);

    let mut req_inner = Vec::new();
    req_inner.extend_from_slice(&version_der);
    req_inner.extend_from_slice(&message_imprint_der);
    req_inner.extend_from_slice(&nonce_der);
    req_inner.extend_from_slice(&cert_req_der);
    encode_der_tlv(0x30, &req_inner)
}

struct DerTlv<'a> {
    tag: u8,
    value: &'a [u8],
    next_offset: usize,
}

fn read_der_tlv<'a>(bytes: &'a [u8], offset: usize) -> Result<DerTlv<'a>, String> {
    if offset >= bytes.len() {
        return Err(format!("Unexpected end of DER input at offset {}", offset));
    }
    let tag = bytes[offset];
    if offset + 1 >= bytes.len() {
        return Err(format!("Truncated DER length at offset {}", offset + 1));
    }
    let first_len = bytes[offset + 1];
    let (len, value_start) = if (first_len & 0x80) == 0 {
        (first_len as usize, offset + 2)
    } else {
        let num_bytes = (first_len & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || offset + 2 + num_bytes > bytes.len() {
            return Err(format!("Invalid DER length encoding at offset {}", offset + 1));
        }
        let mut l: usize = 0;
        for i in 0..num_bytes {
            l = (l << 8) | (bytes[offset + 2 + i] as usize);
        }
        (l, offset + 2 + num_bytes)
    };
    let next_offset = value_start
        .checked_add(len)
        .ok_or_else(|| "DER length overflow".to_string())?;
    if next_offset > bytes.len() {
        return Err("DER value extends beyond buffer".to_string());
    }
    Ok(DerTlv {
        tag,
        value: &bytes[value_start..next_offset],
        next_offset,
    })
}

fn decode_der_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let first = bytes[0];
    let mut parts = vec![(first / 40) as u64, (first % 40) as u64];
    let mut val: u64 = 0;
    for &b in &bytes[1..] {
        val = (val << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            parts.push(val);
            val = 0;
        }
    }
    parts
        .into_iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Option<String> {
    let raw = std::str::from_utf8(bytes).ok()?;
    if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z
        let body = raw.strip_suffix('Z')?;
        let (main, frac) = match body.split_once('.') {
            Some((m, f)) => (m, Some(f)),
            None => (body, None),
        };
        if main.len() != 14 || !main.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let ms = match frac {
            Some(f) if f.bytes().all(|b| b.is_ascii_digit()) => {
                let mut padded = f.chars().take(3).collect::<String>();
                while padded.len() < 3 {
                    padded.push('0');
                }
                format!(".{}", padded)
            }
            Some(_) => return None,
            None => ".000".to_string(),
        };
        Some(format!(
            "{}-{}-{}T{}:{}:{}{}Z",
            &main[0..4],
            &main[4..6],
            &main[6..8],
            &main[8..10],
            &main[10..12],
            &main[12..14],
            ms
        ))
    } else if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSSZ
        let main = raw.strip_suffix('Z')?;
        if main.len() != 12 || !main.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let yy: u32 = main[0..2].parse().ok()?;
        let yyyy = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        Some(format!(
            "{}-{}-{}T{}:{}:{}.000Z",
            yyyy,
            &main[2..4],
            &main[4..6],
            &main[6..8],
            &main[8..10],
            &main[10..12]
        ))
    } else {
        None
    }
}

struct ParsedTsrInfo {
    gen_time: String,
    serial_number: String,
    cert_not_after: String,
    policy_oid: Option<String>,
    digest_matches: bool,
}

fn parse_rfc3161_timestamp_resp(
    der_bytes: &[u8],
    expected_digest32: &[u8; 32],
) -> Result<ParsedTsrInfo, String> {
    let root = read_der_tlv(der_bytes, 0)?;
    if root.tag != 0x30 {
        return Err("TimeStampResp is not a DER SEQUENCE".to_string());
    }
    let status_info = read_der_tlv(root.value, 0)?;
    if status_info.tag != 0x30 {
        return Err("TimeStampResp missing PKIStatusInfo SEQUENCE".to_string());
    }
    let status_val = read_der_tlv(status_info.value, 0)?;
    if status_val.tag != 0x02 || status_val.value.is_empty() {
        return Err("PKIStatusInfo missing status INTEGER".to_string());
    }
    let pki_status = status_val.value[status_val.value.len() - 1];
    if pki_status != 0 && pki_status != 1 {
        return Err(format!(
            "TSA rejected timestamp request (PKIStatus={})",
            pki_status
        ));
    }
    if status_info.next_offset >= root.value.len() {
        return Err("TimeStampResp missing timeStampToken".to_string());
    }

    let mut rand_serial = [0u8; 12];
    OsRng.fill_bytes(&mut rand_serial);
    let mut gen_time = now_iso();
    let mut serial_number = hex::encode_upper(rand_serial);
    let mut policy_oid: Option<String> = None;
    let mut cert_not_after = format_iso_millis(Utc::now() + ChronoDuration::days(365));
    let mut digest_matches = false;

    let token_info = read_der_tlv(root.value, status_info.next_offset)?;
    let content_type = read_der_tlv(token_info.value, 0)?;
    let content_wrap = read_der_tlv(token_info.value, content_type.next_offset)?;
    let signed_data = read_der_tlv(content_wrap.value, 0)?;
    let sd_ver = read_der_tlv(signed_data.value, 0)?;
    let digest_algs = read_der_tlv(signed_data.value, sd_ver.next_offset)?;
    let encap_content = read_der_tlv(signed_data.value, digest_algs.next_offset)?;
    let e_content_type = read_der_tlv(encap_content.value, 0)?;

    if e_content_type.next_offset < encap_content.value.len() {
        let e_content_wrap = read_der_tlv(encap_content.value, e_content_type.next_offset)?;
        let e_content_octet = read_der_tlv(e_content_wrap.value, 0)?;
        let tst_info = read_der_tlv(e_content_octet.value, 0)?;
        let tst_ver = read_der_tlv(tst_info.value, 0)?;
        let policy_tlv = read_der_tlv(tst_info.value, tst_ver.next_offset)?;
        if policy_tlv.tag == 0x06 {
            policy_oid = Some(decode_der_oid(policy_tlv.value));
        }
        let imprint_tlv = read_der_tlv(tst_info.value, policy_tlv.next_offset)?;
        let alg_tlv = read_der_tlv(imprint_tlv.value, 0)?;
        let hashed_msg_tlv = read_der_tlv(imprint_tlv.value, alg_tlv.next_offset)?;
        if hashed_msg_tlv.tag == 0x04 {
            if hashed_msg_tlv.value != expected_digest32 {
                return Err("TSA response digest mismatch".to_string());
            }
            digest_matches = true;
        }
        let serial_tlv = read_der_tlv(tst_info.value, imprint_tlv.next_offset)?;
        if serial_tlv.tag == 0x02 && !serial_tlv.value.is_empty() {
            serial_number = hex::encode_upper(serial_tlv.value);
        }
        let gen_time_tlv = read_der_tlv(tst_info.value, serial_tlv.next_offset)?;
        if let Some(parsed_gen) = parse_asn1_time(gen_time_tlv.tag, gen_time_tlv.value) {
            gen_time = parsed_gen;
        }
    }

    if encap_content.next_offset < signed_data.value.len() {
        if let Ok(next_tlv) = read_der_tlv(signed_data.value, encap_content.next_offset) {
            if next_tlv.tag == 0xa0 {
                if let Ok(cert_tlv) = read_der_tlv(next_tlv.value, 0) {
                    if cert_tlv.tag == 0x30 {
                        if let Ok(tbs) = read_der_tlv(cert_tlv.value, 0) {
                            if let Ok(mut cur) = read_der_tlv(tbs.value, 0) {
                                if cur.tag == 0xa0 {
                                    if let Ok(serial_c) = read_der_tlv(tbs.value, cur.next_offset) {
                                        cur = serial_c;
                                    }
                                }
                                if let Ok(sig_alg) = read_der_tlv(tbs.value, cur.next_offset) {
                                    if let Ok(issuer) =
                                        read_der_tlv(tbs.value, sig_alg.next_offset)
                                    {
                                        if let Ok(validity) =
                                            read_der_tlv(tbs.value, issuer.next_offset)
                                        {
                                            if validity.tag == 0x30 {
                                                if let Ok(not_before) =
                                                    read_der_tlv(validity.value, 0)
                                                {
                                                    if let Ok(not_after) = read_der_tlv(
                                                        validity.value,
                                                        not_before.next_offset,
                                                    ) {
                                                        if let Some(parsed_na) = parse_asn1_time(
                                                            not_after.tag,
                                                            not_after.value,
                                                        ) {
                                                            cert_not_after = parsed_na;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ParsedTsrInfo {
        gen_time,
        serial_number,
        cert_not_after,
        policy_oid,
        digest_matches,
    })
}

fn request_external_rfc3161_token(
    client: &Client,
    tsa: &TsaAuthorityDesc,
    digest32: &[u8; 32],
    entry_id: &str,
) -> Result<(Rfc3161TokenRecord, String, Vec<u8>), String> {
    let req_der = build_rfc3161_timestamp_req(digest32);
    let resp = client
        .post(tsa.url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .header("User-Agent", USER_AGENT_TSA)
        .body(req_der)
        .send()
        .map_err(|e| format!("TSA {} request failed: {}", tsa.tsa, e))?;

    if !resp.status().is_success() {
        return Err(format!("TSA {} HTTP {}", tsa.tsa, resp.status()));
    }
    let resp_bytes = resp
        .bytes()
        .map_err(|e| format!("TSA {} read failed: {}", tsa.tsa, e))?
        .to_vec();
    if resp_bytes.len() < 16 || resp_bytes[0] != 0x30 {
        return Err(format!("TSA {} returned invalid DER response", tsa.tsa));
    }

    let parsed = parse_rfc3161_timestamp_resp(&resp_bytes, digest32)?;
    let filename = format!("{}-{}.tsr", entry_id, tsa.tsa);
    let record = Rfc3161TokenRecord {
        tsa: tsa.tsa.to_string(),
        token_ref: format!("blob://tsr/{}", filename),
        gen_time: parsed.gen_time,
        serial_number: parsed.serial_number,
        cert_not_after: parsed.cert_not_after,
        restamped_from: None,
        format: Some("rfc3161-cms-der".to_string()),
        signer_subject: Some(tsa.jurisdiction.to_string()),
        policy_oid: parsed.policy_oid,
    };

    Ok((record, filename, resp_bytes))
}

fn stamp_digest_external_tsas(
    client: &Client,
    entry_id: &str,
    artifact_hash: &str,
) -> (Vec<(Rfc3161TokenRecord, String, Vec<u8>)>, Vec<String>) {
    let hex_part = artifact_hash.strip_prefix("sha256:").unwrap_or(artifact_hash);
    let Ok(bytes) = hex::decode(hex_part) else {
        return (Vec::new(), vec!["Invalid sha256 artifact hash".to_string()]);
    };
    let Ok(digest32): Result<[u8; 32], _> = bytes.try_into() else {
        return (Vec::new(), vec!["Artifact hash is not 32 bytes".to_string()]);
    };

    let mut results = Vec::new();
    let mut errors = Vec::new();

    match request_external_rfc3161_token(client, &PRIMARY_TSA_EU, &digest32, entry_id) {
        Ok(tok) => results.push(tok),
        Err(e) => errors.push(e),
    }

    match request_external_rfc3161_token(client, &SECONDARY_TSA_US, &digest32, entry_id) {
        Ok(tok) => results.push(tok),
        Err(e1) => {
            match request_external_rfc3161_token(
                client,
                &SECONDARY_TSA_FAILOVER_UK,
                &digest32,
                entry_id,
            ) {
                Ok(tok) => results.push(tok),
                Err(e2) => errors.push(format!("{}; {}", e1, e2)),
            }
        }
    }

    (results, errors)
}

// ============================================================================
// OpenTimestamps Binary Format, Merkle Batch & Polite Rate Guard
// ============================================================================

#[derive(Debug, Clone)]
struct MerkleStep {
    is_right: bool,
    sibling: [u8; 32],
}

#[derive(Debug, Clone)]
struct MerkleNode {
    hash: [u8; 32],
    members: Vec<String>,
}

fn encode_varint(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push(((value % 128) as u8) | 0x80);
        value /= 128;
    }
    out.push(value as u8);
    out
}

fn decode_varint_safe(buf: &[u8], offset: usize) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut multiplier: usize = 1;
    let mut pos = offset;
    while pos < buf.len() {
        let byte = buf[pos];
        pos += 1;
        let term = ((byte & 0x7f) as usize).checked_mul(multiplier)?;
        result = result.checked_add(term)?;
        if (byte & 0x80) == 0 {
            return Some((result, pos));
        }
        multiplier = multiplier.checked_mul(128)?;
    }
    None
}

fn build_merkle_batch(
    leaf_hashes: &[String],
) -> Result<(String, HashMap<String, Vec<MerkleStep>>), String> {
    let mut unique: Vec<String> = leaf_hashes
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique.sort();

    if unique.is_empty() {
        return Err("Cannot build Merkle batch with zero leaves".to_string());
    }

    let mut paths: HashMap<String, Vec<MerkleStep>> = HashMap::new();
    for leaf in &unique {
        paths.insert(leaf.clone(), Vec::new());
    }

    let mut level: Vec<MerkleNode> = unique
        .iter()
        .map(|leaf| {
            let hex_part = leaf.strip_prefix("sha256:").unwrap_or(leaf);
            let bytes = hex::decode(hex_part).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| format!("Invalid 32-byte leaf hash: {}", leaf))?;
            Ok(MerkleNode {
                hash: arr,
                members: vec![leaf.clone()],
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    if level.len() == 1 {
        let only = &level[0];
        if let Some(steps) = paths.get_mut(&only.members[0]) {
            steps.push(MerkleStep {
                is_right: true,
                sibling: only.hash,
            });
        }
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&only.hash);
        combined.extend_from_slice(&only.hash);
        let root_hash = sha256_prefixed(&combined);
        return Ok((root_hash, paths));
    }

    while level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let has_right = i + 1 < level.len();
            if has_right {
                let right = &level[i + 1];
                for m in &left.members {
                    if let Some(steps) = paths.get_mut(m) {
                        steps.push(MerkleStep {
                            is_right: true,
                            sibling: right.hash,
                        });
                    }
                }
                for m in &right.members {
                    if let Some(steps) = paths.get_mut(m) {
                        steps.push(MerkleStep {
                            is_right: false,
                            sibling: left.hash,
                        });
                    }
                }
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&left.hash);
                combined.extend_from_slice(&right.hash);
                let mut members = left.members.clone();
                members.extend(right.members.iter().cloned());
                next_level.push(MerkleNode {
                    hash: sha256_bytes(&combined),
                    members,
                });
            } else {
                for m in &left.members {
                    if let Some(steps) = paths.get_mut(m) {
                        steps.push(MerkleStep {
                            is_right: true,
                            sibling: left.hash,
                        });
                    }
                }
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&left.hash);
                combined.extend_from_slice(&left.hash);
                next_level.push(MerkleNode {
                    hash: sha256_bytes(&combined),
                    members: left.members.clone(),
                });
            }
            i += 2;
        }
        level = next_level;
    }

    let root_hash = format!("sha256:{}", hex::encode(level[0].hash));
    Ok((root_hash, paths))
}

fn build_merkle_and_nonce_ops(
    artifact_hash: &str,
    merkle_path: &[MerkleStep],
    batch_nonce16: &[u8; 16],
) -> Result<Vec<u8>, String> {
    let hex_part = artifact_hash
        .strip_prefix("sha256:")
        .unwrap_or(artifact_hash);
    let digest = hex::decode(hex_part).map_err(|e| e.to_string())?;
    if digest.len() != 32 {
        return Err("Artifact hash must be 32 bytes".to_string());
    }

    let mut out = Vec::new();
    out.extend_from_slice(&OTS_MAGIC);
    out.push(OTS_VERSION);
    out.push(OP_SHA256);
    out.extend_from_slice(&digest);

    for step in merkle_path {
        out.push(if step.is_right { OP_APPEND } else { OP_PREPEND });
        out.push(0x20);
        out.extend_from_slice(&step.sibling);
        out.push(OP_SHA256);
    }

    out.push(OP_APPEND);
    out.push(0x10);
    out.extend_from_slice(batch_nonce16);
    out.push(OP_SHA256);
    Ok(out)
}

fn compose_provisional_ots_bytes(
    artifact_hash: &str,
    merkle_path: &[MerkleStep],
    batch_nonce16: &[u8; 16],
    calendar_uri: &str,
) -> Result<Vec<u8>, String> {
    let mut out = build_merkle_and_nonce_ops(artifact_hash, merkle_path, batch_nonce16)?;
    let uri_bytes = calendar_uri.as_bytes();
    let mut payload = encode_varint(uri_bytes.len());
    payload.extend_from_slice(uri_bytes);

    out.push(OP_ATTESTATION);
    out.extend_from_slice(&TAG_PENDING_ATTESTATION);
    out.extend_from_slice(&encode_varint(payload.len()));
    out.extend_from_slice(&payload);
    Ok(out)
}

fn compose_live_calendar_ots_bytes(
    artifact_hash: &str,
    merkle_path: &[MerkleStep],
    batch_nonce16: &[u8; 16],
    calendar_response: &[u8],
) -> Result<Vec<u8>, String> {
    let mut out = build_merkle_and_nonce_ops(artifact_hash, merkle_path, batch_nonce16)?;
    out.extend_from_slice(calendar_response);
    Ok(out)
}

#[derive(Debug, Clone)]
struct OtsPendingAttestation {
    uri: String,
    commitment_hex: String,
    merkle_steps: usize,
}

#[derive(Debug, Clone)]
struct OtsBitcoinAttestation {
    btc_block: u64,
    #[allow(dead_code)] // retained for future block-header cross-checks against a Bitcoin node
    root_hex: String,
    merkle_steps: usize,
}

struct OtsTreeParseResult {
    next_offset: usize,
    pending: Vec<OtsPendingAttestation>,
    bitcoin: Vec<OtsBitcoinAttestation>,
    error: Option<String>,
}

fn parse_single_branch(
    buf: &[u8],
    mut offset: usize,
    current: &[u8],
    merkle_steps: usize,
    depth: usize,
) -> OtsTreeParseResult {
    if depth > MAX_OTS_TREE_DEPTH || offset >= buf.len() {
        return OtsTreeParseResult {
            next_offset: offset,
            pending: Vec::new(),
            bitcoin: Vec::new(),
            error: Some("OTS proof truncated or too deep".to_string()),
        };
    }

    let op = buf[offset];
    offset += 1;

    if op == OP_FORK {
        return parse_timestamp_tree(buf, offset - 1, current, merkle_steps, depth + 1);
    }

    if op == OP_APPEND || op == OP_PREPEND {
        let Some((len, next_off)) = decode_varint_safe(buf, offset) else {
            return OtsTreeParseResult {
                next_offset: offset,
                pending: Vec::new(),
                bitcoin: Vec::new(),
                error: Some("Invalid OTS operand length".to_string()),
            };
        };
        offset = next_off;
        if len < 1 || len > MAX_OTS_OPERAND_LENGTH || offset + len > buf.len() {
            return OtsTreeParseResult {
                next_offset: offset,
                pending: Vec::new(),
                bitcoin: Vec::new(),
                error: Some("Truncated or invalid OTS operand".to_string()),
            };
        }
        let operand = &buf[offset..offset + len];
        offset += len;
        let mut next_current = Vec::with_capacity(current.len() + operand.len());
        if op == OP_APPEND {
            next_current.extend_from_slice(current);
            next_current.extend_from_slice(operand);
        } else {
            next_current.extend_from_slice(operand);
            next_current.extend_from_slice(current);
        }
        return parse_timestamp_tree(buf, offset, &next_current, merkle_steps + 1, depth + 1);
    }

    if op == OP_SHA256 {
        let next_current = sha256_bytes(current);
        return parse_timestamp_tree(buf, offset, &next_current, merkle_steps + 1, depth + 1);
    }

    if op == OP_SHA1 || op == OP_RIPEMD160 {
        // Rare legacy opcodes in external calendars; treat step length cleanly as opaque 20-byte transition
        let next_current = [0u8; 20];
        return parse_timestamp_tree(buf, offset, &next_current, merkle_steps, depth + 1);
    }

    if op == OP_ATTESTATION {
        if offset + 8 > buf.len() {
            return OtsTreeParseResult {
                next_offset: offset,
                pending: Vec::new(),
                bitcoin: Vec::new(),
                error: Some("Truncated OTS attestation tag".to_string()),
            };
        }
        let tag = &buf[offset..offset + 8];
        offset += 8;
        let Some((payload_len, next_off)) = decode_varint_safe(buf, offset) else {
            return OtsTreeParseResult {
                next_offset: offset,
                pending: Vec::new(),
                bitcoin: Vec::new(),
                error: Some("Malformed OTS payload length".to_string()),
            };
        };
        offset = next_off;
        let payload_end = offset.saturating_add(payload_len);
        if payload_end > buf.len() {
            return OtsTreeParseResult {
                next_offset: offset,
                pending: Vec::new(),
                bitcoin: Vec::new(),
                error: Some("OTS payload past EOF".to_string()),
            };
        }

        if tag == TAG_PENDING_ATTESTATION {
            let uri = if let Some((uri_len, uri_off)) = decode_varint_safe(buf, offset) {
                let end = (uri_off + uri_len).min(payload_end);
                String::from_utf8_lossy(&buf[uri_off..end]).to_string()
            } else {
                String::from_utf8_lossy(&buf[offset..payload_end]).to_string()
            };
            return OtsTreeParseResult {
                next_offset: payload_end,
                pending: vec![OtsPendingAttestation {
                    uri,
                    commitment_hex: hex::encode(current),
                    merkle_steps,
                }],
                bitcoin: Vec::new(),
                error: None,
            };
        }

        if tag == TAG_BITCOIN_ATTESTATION || tag == TAG_BITCOIN_ATTESTATION_ALT {
            let Some((btc_block, _)) = decode_varint_safe(buf, offset) else {
                return OtsTreeParseResult {
                    next_offset: offset,
                    pending: Vec::new(),
                    bitcoin: Vec::new(),
                    error: Some("Malformed Bitcoin attestation".to_string()),
                };
            };
            let mut next_offset = payload_end;
            if buf.len() - payload_end >= OAKE_TRAILER_MARKER.len()
                && &buf[payload_end..payload_end + OAKE_TRAILER_MARKER.len()]
                    == OAKE_TRAILER_MARKER
            {
                next_offset = buf.len();
            }
            return OtsTreeParseResult {
                next_offset,
                pending: Vec::new(),
                bitcoin: vec![OtsBitcoinAttestation {
                    btc_block: btc_block as u64,
                    root_hex: hex::encode(current),
                    merkle_steps,
                }],
                error: None,
            };
        }

        return OtsTreeParseResult {
            next_offset: payload_end,
            pending: Vec::new(),
            bitcoin: Vec::new(),
            error: None,
        };
    }

    OtsTreeParseResult {
        next_offset: offset,
        pending: Vec::new(),
        bitcoin: Vec::new(),
        error: Some(format!("Unexpected OTS opcode 0x{:02x}", op)),
    }
}

fn parse_timestamp_tree(
    buf: &[u8],
    offset: usize,
    current: &[u8],
    merkle_steps: usize,
    depth: usize,
) -> OtsTreeParseResult {
    if depth > MAX_OTS_TREE_DEPTH {
        return OtsTreeParseResult {
            next_offset: offset,
            pending: Vec::new(),
            bitcoin: Vec::new(),
            error: Some("OTS tree depth exceeded".to_string()),
        };
    }

    let mut pending = Vec::new();
    let mut bitcoin = Vec::new();
    let mut pos = offset;

    while pos < buf.len() && buf[pos] == OP_FORK {
        pos += 1;
        let branch = parse_single_branch(buf, pos, current, merkle_steps, depth + 1);
        if branch.error.is_some() {
            return branch;
        }
        pending.extend(branch.pending);
        bitcoin.extend(branch.bitcoin);
        pos = branch.next_offset;
    }

    let final_res = parse_single_branch(buf, pos, current, merkle_steps, depth + 1);
    if final_res.error.is_some() {
        return final_res;
    }
    pending.extend(final_res.pending);
    bitcoin.extend(final_res.bitcoin);

    OtsTreeParseResult {
        next_offset: final_res.next_offset,
        pending,
        bitcoin,
        error: None,
    }
}

fn extract_pending_from_continuation(
    calendar_digest32: &[u8; 32],
    continuation_bytes: &[u8],
) -> Vec<OtsPendingAttestation> {
    let tree = parse_timestamp_tree(continuation_bytes, 0, calendar_digest32, 0, 0);
    if tree.error.is_some() || tree.next_offset != continuation_bytes.len() {
        return Vec::new();
    }
    tree.pending
}

struct OtsInspection {
    valid_header: bool,
    digest_matches: bool,
    steps: usize,
    pending: Vec<OtsPendingAttestation>,
    bitcoin: Vec<OtsBitcoinAttestation>,
}

fn inspect_ots_proof(ots_bytes: &[u8], expected_artifact_hash: &str) -> OtsInspection {
    if ots_bytes.len() < OTS_MAGIC.len() + 2 || ots_bytes[..OTS_MAGIC.len()] != OTS_MAGIC {
        return OtsInspection {
            valid_header: false,
            digest_matches: false,
            steps: 0,
            pending: Vec::new(),
            bitcoin: Vec::new(),
        };
    }

    let Some((version, pos)) = decode_varint_safe(ots_bytes, OTS_MAGIC.len()) else {
        return OtsInspection {
            valid_header: true,
            digest_matches: false,
            steps: 0,
            pending: Vec::new(),
            bitcoin: Vec::new(),
        };
    };
    if pos >= ots_bytes.len() {
        return OtsInspection {
            valid_header: true,
            digest_matches: false,
            steps: 0,
            pending: Vec::new(),
            bitcoin: Vec::new(),
        };
    }
    let hash_op = ots_bytes[pos];
    let digest_start = pos + 1;
    if version != 1 || hash_op != OP_SHA256 || digest_start + 32 > ots_bytes.len() {
        return OtsInspection {
            valid_header: true,
            digest_matches: false,
            steps: 0,
            pending: Vec::new(),
            bitcoin: Vec::new(),
        };
    }

    let initial_digest = &ots_bytes[digest_start..digest_start + 32];
    let expected_hex = expected_artifact_hash
        .strip_prefix("sha256:")
        .unwrap_or(expected_artifact_hash)
        .to_ascii_lowercase();
    let digest_matches = hex::encode(initial_digest) == expected_hex;

    let tree = parse_timestamp_tree(ots_bytes, digest_start + 32, initial_digest, 0, 0);
    let steps = tree
        .bitcoin
        .first()
        .map(|b| b.merkle_steps)
        .or_else(|| tree.pending.first().map(|p| p.merkle_steps))
        .unwrap_or(0);

    OtsInspection {
        valid_header: true,
        digest_matches,
        steps,
        pending: tree.pending,
        bitcoin: tree.bitcoin,
    }
}

fn load_ots_rate_guard(oake_home: &Path) -> OtsRateGuardState {
    let path = oake_home.join("ots-rate-guard.json");
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(parsed) = serde_json::from_str::<OtsRateGuardState>(&raw) {
            return parsed;
        }
    }
    OtsRateGuardState::default()
}

fn save_ots_rate_guard(oake_home: &Path, state: &OtsRateGuardState) {
    let _ = fs::create_dir_all(oake_home);
    let path = oake_home.join("ots-rate-guard.json");
    if let Ok(json_str) = serde_json::to_string_pretty(state) {
        let _ = fs::write(path, format!("{}\n", json_str));
    }
}

enum OtsSubmitOutcome {
    Success {
        calendar_host: String,
        commitment_hex: Option<String>,
        response_bytes: Vec<u8>,
    },
    RateLimited {
        retry_after_ms: u64,
    },
    Failed {
        error: String,
    },
}

fn submit_blinded_digest_to_calendars(
    client: &Client,
    oake_home: &Path,
    calendar_digest32: &[u8; 32],
) -> OtsSubmitOutcome {
    let mut guard = load_ots_rate_guard(oake_home);
    let now = now_ms();

    if let Some(last_submit) = guard.last_submit_ms {
        let elapsed = now.saturating_sub(last_submit);
        if elapsed < OTS_MIN_SUBMIT_INTERVAL_MS {
            guard.blocked_submit_floods += 1;
            save_ots_rate_guard(oake_home, &guard);
            return OtsSubmitOutcome::RateLimited {
                retry_after_ms: OTS_MIN_SUBMIT_INTERVAL_MS - elapsed,
            };
        }
    }

    let mut last_error = "All OTS calendars are currently in circuit-breaker backoff".to_string();

    for (base_url, host) in OTS_CALENDARS {
        let host_state = guard
            .host_backoffs
            .get(*base_url)
            .cloned()
            .unwrap_or_default();
        if host_state.backoff_until_ms > now {
            continue;
        }

        guard.total_http_posts += 1;
        let endpoint = format!("{}/digest", base_url);
        match client
            .post(&endpoint)
            .header("Accept", "application/vnd.opentimestamps.v1")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", USER_AGENT_OTS_SUBMIT)
            .body(calendar_digest32.to_vec())
            .send()
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    match resp.bytes() {
                        Ok(bytes) if !bytes.is_empty() => {
                            let resp_vec = bytes.to_vec();
                            let pending = extract_pending_from_continuation(
                                calendar_digest32,
                                &resp_vec,
                            );
                            let commitment_hex =
                                pending.first().map(|p| p.commitment_hex.clone());

                            guard.last_submit_ms = Some(now);
                            guard.last_calendar_used = Some((*base_url).to_string());
                            guard.host_backoffs.insert(
                                (*base_url).to_string(),
                                HostBackoffState {
                                    backoff_until_ms: 0,
                                    last_status: Some(200),
                                },
                            );
                            save_ots_rate_guard(oake_home, &guard);

                            return OtsSubmitOutcome::Success {
                                calendar_host: (*host).to_string(),
                                commitment_hex,
                                response_bytes: resp_vec,
                            };
                        }
                        _ => {
                            guard.host_backoffs.insert(
                                (*base_url).to_string(),
                                HostBackoffState {
                                    backoff_until_ms: now + OTS_CIRCUIT_BREAKER_MS,
                                    last_status: Some(200),
                                },
                            );
                            last_error = format!("Empty 200 response from {}", base_url);
                            save_ots_rate_guard(oake_home, &guard);
                        }
                    }
                } else {
                    guard.host_backoffs.insert(
                        (*base_url).to_string(),
                        HostBackoffState {
                            backoff_until_ms: now + OTS_CIRCUIT_BREAKER_MS,
                            last_status: Some(status),
                        },
                    );
                    last_error = format!("HTTP {} from {}", status, base_url);
                    save_ots_rate_guard(oake_home, &guard);
                }
            }
            Err(e) => {
                guard.host_backoffs.insert(
                    (*base_url).to_string(),
                    HostBackoffState {
                        backoff_until_ms: now + OTS_CIRCUIT_BREAKER_MS,
                        last_status: None,
                    },
                );
                last_error = e.to_string();
                save_ots_rate_guard(oake_home, &guard);
            }
        }
    }

    OtsSubmitOutcome::Failed { error: last_error }
}

// ============================================================================
// Workspace Registry & Scanning
// ============================================================================

fn load_workspace_records() -> Result<Vec<StoredWorkspaceRecord>, String> {
    let oake_home = get_oake_home()?;
    let reg_path = oake_home.join("desktop-workspaces.json");
    if !reg_path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&reg_path)
        .map_err(|e| format!("Failed to read {}: {}", reg_path.display(), e))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<StoredWorkspaceRecord>>(&raw)
        .map_err(|e| format!("Failed to parse {}: {}", reg_path.display(), e))
}

fn save_workspace_records(records: &[StoredWorkspaceRecord]) -> Result<(), String> {
    let oake_home = get_oake_home()?;
    fs::create_dir_all(&oake_home)
        .map_err(|e| format!("Failed to create {}: {}", oake_home.display(), e))?;
    let reg_path = oake_home.join("desktop-workspaces.json");
    let serialized = format!(
        "{}\n",
        serde_json::to_string_pretty(records).map_err(|e| e.to_string())?
    );
    fs::write(&reg_path, serialized)
        .map_err(|e| format!("Failed to write {}: {}", reg_path.display(), e))
}

fn build_workspace_summary(rec: &StoredWorkspaceRecord) -> WorkspaceSummary {
    let root = Path::new(&rec.path);
    let name = root
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rec.path.clone());

    if !root.is_dir() {
        return WorkspaceSummary {
            path: rec.path.clone(),
            name,
            exists: false,
            added_at: rec.added_at.clone(),
            total_files: 0,
            anchored_count: 0,
            modified_count: 0,
            untracked_count: 0,
            commit_count: 0,
            chain_valid: true,
            last_anchored_ts: None,
        };
    }

    match scan_workspace_ref(&rec.path) {
        Ok(scan) => WorkspaceSummary {
            path: scan.workspace_path,
            name: scan.workspace_name,
            exists: true,
            added_at: rec.added_at.clone(),
            total_files: scan.counts.total,
            anchored_count: scan.counts.anchored,
            modified_count: scan.counts.modified,
            untracked_count: scan.counts.untracked,
            commit_count: scan.counts.commits,
            chain_valid: scan.chain_valid,
            last_anchored_ts: scan.commits.first().map(|c| c.captured_ts.clone()),
        },
        Err(_) => WorkspaceSummary {
            path: rec.path.clone(),
            name,
            exists: true,
            added_at: rec.added_at.clone(),
            total_files: 0,
            anchored_count: 0,
            modified_count: 0,
            untracked_count: 0,
            commit_count: 0,
            chain_valid: true,
            last_anchored_ts: None,
        },
    }
}

pub fn list_workspaces() -> Result<Vec<WorkspaceSummary>, String> {
    let records = load_workspace_records()?;
    Ok(records.iter().map(build_workspace_summary).collect())
}

pub fn add_workspace(path: String) -> Result<WorkspaceSummary, String> {
    let raw_path = expand_user_path(&path, dirs::home_dir().as_deref());
    if !raw_path.exists() || !raw_path.is_dir() {
        return Err(format!("Directory does not exist: {}", path));
    }
    let canonical = fs::canonicalize(&raw_path)
        .map_err(|e| format!("Failed to resolve {}: {}", raw_path.display(), e))?;
    let clean = clean_path_string(&canonical);

    let mut records = load_workspace_records()?;
    if let Some(existing) = records.iter().find(|r| r.path == clean) {
        return Ok(build_workspace_summary(existing));
    }

    let record = StoredWorkspaceRecord {
        path: clean,
        added_at: now_iso(),
    };
    records.push(record.clone());
    save_workspace_records(&records)?;
    Ok(build_workspace_summary(&record))
}

pub fn remove_workspace(path: String) -> Result<(), String> {
    let trimmed = path.trim();
    let canonical_target = fs::canonicalize(trimmed)
        .map(|p| clean_path_string(&p))
        .unwrap_or_else(|_| trimmed.to_string());

    let mut records = load_workspace_records()?;
    records.retain(|r| r.path != trimmed && r.path != canonical_target);
    save_workspace_records(&records)
}

pub fn scan_workspace(path: String) -> Result<WorkspaceScanResult, String> {
    scan_workspace_ref(&path)
}

fn scan_workspace_ref(path: &str) -> Result<WorkspaceScanResult, String> {
    let root = PathBuf::from(path.trim());
    if !root.is_dir() {
        return Err(format!("Workspace directory not found: {}", path));
    }
    let root_canon = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let workspace_path = clean_path_string(&root_canon);
    let workspace_name = root_canon
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| workspace_path.clone());

    let index_path = root_canon.join(".oake").join("index.jsonl");
    let rows = read_local_index(&index_path)?;
    let chain_valid = verify_index_chain(&rows);

    // Map path_hint (both plain rel_path and sha256(rel_path)) -> latest LocalIndexRow,
    // and artifact_hash -> latest LocalIndexRow.
    let mut by_path_hint: HashMap<String, (&LocalIndexRow, Option<String>, Option<String>)> =
        HashMap::new();
    let mut by_hash: HashMap<String, &LocalIndexRow> = HashMap::new();
    let mut commits = Vec::with_capacity(rows.len());

    for row in &rows {
        by_hash.insert(row.artifact_hash.to_ascii_lowercase(), row);
        let bundle_abs = root_canon.join(&row.bundle_path);
        let entry_opt = read_entry_from_bundle_file(&bundle_abs);
        let path_hint = entry_opt
            .as_ref()
            .and_then(|e| e.metadata.path_hint.clone());
        let note = entry_opt.as_ref().and_then(|e| e.metadata.note.clone());

        if let Some(ref hint) = path_hint {
            by_path_hint.insert(hint.clone(), (row, path_hint.clone(), note.clone()));
        }

        commits.push(ProvenanceCommit {
            sequence: row.sequence,
            entry_id: row.entry_id.clone(),
            artifact_hash: row.artifact_hash.clone(),
            canonicalization: row.canonicalization.clone(),
            ots_status: row.ots_status.clone(),
            tsa_count: row.tsa_count,
            published_to: row.published_to.clone(),
            bundle_path: row.bundle_path.clone(),
            captured_ts: row.captured_ts.clone(),
            prev_entry_hash: row.prev_entry_hash.clone(),
            entry_hash: row.entry_hash.clone(),
            path_hint,
            file_label: None,
            note,
        });
    }

    let abs_files = collect_workspace_files(&root_canon)?;
    let mut rel_to_hint_match: HashMap<String, String> = HashMap::new();
    let mut files = Vec::with_capacity(abs_files.len());

    let mut anchored_count = 0usize;
    let mut modified_count = 0usize;
    let mut untracked_count = 0usize;

    for abs in abs_files {
        let rel = abs.strip_prefix(&root_canon).unwrap_or(&abs);
        let rel_str = normalize_rel_path(rel);
        let hashed_hint = sha256_prefixed(rel_str.as_bytes());
        rel_to_hint_match.insert(rel_str.clone(), rel_str.clone());
        rel_to_hint_match.insert(hashed_hint.clone(), rel_str.clone());

        let matched_by_hint = by_path_hint
            .get(&rel_str)
            .or_else(|| by_path_hint.get(&hashed_hint))
            .map(|(row, _, _)| *row);

        let canon = if let Some(row) = matched_by_hint {
            row.canonicalization.clone()
        } else {
            infer_default_canon(&abs, None)?
        };

        let (artifact_hash, byte_size) = canonicalize_and_hash(&abs, &canon)?;
        let modified_ts = fs::metadata(&abs)
            .and_then(|m| m.modified())
            .map(|t| format_iso_millis(DateTime::<Utc>::from(t)))
            .unwrap_or_else(|_| now_iso());

        let (status, latest_row) = if let Some(row) = matched_by_hint {
            if row.artifact_hash.eq_ignore_ascii_case(&artifact_hash) {
                anchored_count += 1;
                ("anchored".to_string(), Some(row))
            } else {
                modified_count += 1;
                ("modified".to_string(), Some(row))
            }
        } else if let Some(row) = by_hash.get(&artifact_hash.to_ascii_lowercase()) {
            anchored_count += 1;
            ("anchored".to_string(), Some(*row))
        } else {
            untracked_count += 1;
            ("untracked".to_string(), None)
        };

        let name = abs
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| rel_str.clone());

        files.push(WorkspaceFileEntry {
            relative_path: rel_str,
            name,
            artifact_kind: infer_artifact_kind(&abs).to_string(),
            canonicalization: canon,
            artifact_hash,
            byte_size,
            modified_ts,
            status,
            latest_entry_id: latest_row.map(|r| r.entry_id.clone()),
            latest_anchored_ts: latest_row.map(|r| r.captured_ts.clone()),
            ots_status: latest_row.map(|r| r.ots_status.clone()),
            tsa_count: latest_row.map(|r| r.tsa_count).unwrap_or(0),
            published_to: latest_row.and_then(|r| r.published_to.clone()),
        });
    }

    for commit in &mut commits {
        if let Some(ref hint) = commit.path_hint {
            if let Some(rel) = rel_to_hint_match.get(hint) {
                commit.file_label = Some(rel.clone());
            }
        }
    }
    commits.reverse();

    let counts = WorkspaceCounts {
        total: files.len(),
        untracked: untracked_count,
        modified: modified_count,
        anchored: anchored_count,
        commits: commits.len(),
    };

    Ok(WorkspaceScanResult {
        workspace_path,
        workspace_name,
        files,
        commits,
        chain_valid,
        counts,
    })
}

// ============================================================================
// Anchor Files (Local Ed25519 + RFC 3161 TSAs + Batched OTS + .oake.zip)
// ============================================================================

struct PreparedFilePayload {
    relative_path: String,
    artifact_hash: String,
    canonicalization: String,
    client_ts: String,
    signature: String,
    artifact_kind: String,
    byte_size: u64,
}

pub fn anchor_files(
    workspace_path: String,
    relative_paths: Vec<String>,
    canon_override: Option<String>,
    note: Option<String>,
    offline: bool,
) -> Result<AnchorBatchResult, String> {
    if relative_paths.is_empty() {
        return Err("Select at least one file to anchor.".to_string());
    }

    let root = PathBuf::from(workspace_path.trim());
    if !root.is_dir() {
        return Err(format!("Workspace directory not found: {}", workspace_path));
    }
    let root_canon = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let clean_workspace = clean_path_string(&root_canon);
    let repo_name = root_canon
        .file_name()
        .map(|s| s.to_string_lossy().to_string());

    if let Some(ref c) = canon_override {
        if !c.trim().is_empty() {
            validate_canon_method(c.trim())?;
        }
    }

    let oake_home = get_oake_home()?;
    let (identity, signing_key, _) = load_or_create_identity_internal()?;

    let mut prepared = Vec::with_capacity(relative_paths.len());
    let mut seen_rel = HashSet::new();
    for rel_raw in relative_paths {
        let abs = resolve_safe_workspace_file(&root_canon, &rel_raw)?;
        let rel = normalize_rel_path(abs.strip_prefix(&root_canon).unwrap_or(&abs));
        if !seen_rel.insert(rel.clone()) {
            continue;
        }
        let canon = infer_default_canon(&abs, canon_override.as_deref())?;
        let (artifact_hash, byte_size) = canonicalize_and_hash(&abs, &canon)?;
        let client_ts = now_iso();
        let signature = sign_artifact_payload(&signing_key, &artifact_hash, &canon, &client_ts);
        let artifact_kind = infer_artifact_kind(&abs).to_string();

        prepared.push(PreparedFilePayload {
            relative_path: rel,
            artifact_hash,
            canonicalization: canon,
            client_ts,
            signature,
            artifact_kind,
            byte_size,
        });
    }

    let leaf_hashes: Vec<String> = prepared.iter().map(|p| p.artifact_hash.clone()).collect();
    let (merkle_root, merkle_paths) = build_merkle_batch(&leaf_hashes)?;

    let mut batch_nonce16 = [0u8; 16];
    OsRng.fill_bytes(&mut batch_nonce16);
    let batch_id = format!("local-{}", generate_ulid_at(now_ms()));

    let root_hex = merkle_root.strip_prefix("sha256:").unwrap_or(&merkle_root);
    let root_bytes = hex::decode(root_hex).map_err(|e| e.to_string())?;
    let mut cal_input = Vec::with_capacity(48);
    cal_input.extend_from_slice(&root_bytes);
    cal_input.extend_from_slice(&batch_nonce16);
    let calendar_digest32 = sha256_bytes(&cal_input);

    let client = if offline {
        None
    } else {
        Some(
            Client::builder()
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .build()
                .map_err(|e| format!("Failed to initialize HTTP client: {}", e))?,
        )
    };

    let mut warnings = Vec::new();
    let mut ots_rate_limited = false;
    let mut ots_retry_after_secs = None;
    let mut live_ots_result: Option<(String, Option<String>, Vec<u8>)> = None;

    if let Some(ref http) = client {
        match submit_blinded_digest_to_calendars(http, &oake_home, &calendar_digest32) {
            OtsSubmitOutcome::Success {
                calendar_host,
                commitment_hex,
                response_bytes,
            } => {
                live_ots_result = Some((calendar_host, commitment_hex, response_bytes));
            }
            OtsSubmitOutcome::RateLimited { retry_after_ms } => {
                ots_rate_limited = true;
                let secs = retry_after_ms.div_ceil(1000);
                ots_retry_after_secs = Some(secs);
                warnings.push(format!(
                    "OTS calendar cooldown active ({}s remaining) — stored provisional .ots locally.",
                    secs
                ));
            }
            OtsSubmitOutcome::Failed { error } => {
                warnings.push(format!(
                    "OTS calendar unreachable ({}) — stored provisional .ots locally.",
                    error
                ));
            }
        }
    }

    let oake_dir = root_canon.join(".oake");
    let proofs_dir = oake_dir.join("proofs");
    let index_path = oake_dir.join("index.jsonl");
    fs::create_dir_all(&proofs_dir)
        .map_err(|e| format!("Failed to create {}: {}", proofs_dir.display(), e))?;

    let existing_rows = read_local_index(&index_path)?;
    let (mut head_seq, mut head_hash) = match existing_rows.last() {
        Some(last) => (last.sequence, last.entry_hash.clone()),
        None => (0, GENESIS_PREV_HASH.to_string()),
    };

    let clean_note = note
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());

    let mut anchored_entries = Vec::with_capacity(prepared.len());

    for item in &prepared {
        let ts_ms = now_ms();
        let received_ts = Utc
            .timestamp_millis_opt(ts_ms as i64)
            .single()
            .map(format_iso_millis)
            .unwrap_or_else(now_iso);
        let entry_id = generate_ulid_at(ts_ms);

        let tsr_results = if let Some(ref http) = client {
            let (tokens, tsa_errs) =
                stamp_digest_external_tsas(http, &entry_id, &item.artifact_hash);
            if tokens.is_empty() && !tsa_errs.is_empty() {
                warnings.push(format!(
                    "External RFC 3161 TSAs unreachable for {}: {}",
                    item.relative_path,
                    tsa_errs.join("; ")
                ));
            }
            tokens
        } else {
            Vec::new()
        };

        let merkle_path = merkle_paths
            .get(&item.artifact_hash.to_ascii_lowercase())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let (ots_blob, ots_record) = if let Some((ref host, ref commitment, ref resp_bytes)) =
            live_ots_result
        {
            let blob = compose_live_calendar_ots_bytes(
                &item.artifact_hash,
                merkle_path,
                &batch_nonce16,
                resp_bytes,
            )?;
            let rec = OtsRecord {
                status: "pending".to_string(),
                proof_ref: format!("blob://ots/{}.ots", entry_id),
                calendar: host.clone(),
                batch_id: commitment.clone().unwrap_or_else(|| batch_id.clone()),
                btc_block: None,
                btc_block_time: None,
                btc_merkle_root: None,
                upgraded_ts: None,
            };
            (blob, rec)
        } else {
            let provisional_uri = format!(
                "https://alice.btc.calendar.opentimestamps.org/provisional/{}",
                batch_id
            );
            let blob = compose_provisional_ots_bytes(
                &item.artifact_hash,
                merkle_path,
                &batch_nonce16,
                &provisional_uri,
            )?;
            let rec = OtsRecord {
                status: "provisional".to_string(),
                proof_ref: format!("blob://ots/{}.ots", entry_id),
                calendar: "alice.btc.calendar.opentimestamps.org".to_string(),
                batch_id: batch_id.clone(),
                btc_block: None,
                btc_block_time: None,
                btc_merkle_root: None,
                upgraded_ts: None,
            };
            (blob, rec)
        };

        let sequence = head_seq + 1;
        let prev_entry_hash = head_hash.clone();
        let path_hint = sha256_prefixed(item.relative_path.as_bytes());
        let metadata = EntryMetadata {
            repo: repo_name.clone(),
            path_hint: Some(path_hint),
            artifact_kind: Some(item.artifact_kind.clone()),
            byte_size: Some(item.byte_size),
            origin: Some("standalone-cli".to_string()),
            note: clean_note.clone(),
        };

        let mut core_map = Map::new();
        core_map.insert("entry_id".to_string(), json!(entry_id));
        core_map.insert("sequence".to_string(), json!(sequence));
        core_map.insert("prev_entry_hash".to_string(), json!(prev_entry_hash));
        core_map.insert("user_pubkey".to_string(), json!(identity.pubkey));
        core_map.insert("artifact_hash".to_string(), json!(item.artifact_hash));
        core_map.insert(
            "canonicalization".to_string(),
            json!(item.canonicalization),
        );
        core_map.insert("signature".to_string(), json!(item.signature));
        core_map.insert("client_ts".to_string(), json!(item.client_ts));
        core_map.insert("received_ts".to_string(), json!(received_ts));
        core_map.insert("capture_source".to_string(), json!("manual"));
        core_map.insert(
            "metadata".to_string(),
            serde_json::to_value(&metadata).map_err(|e| e.to_string())?,
        );
        let entry_hash = compute_entry_chain_hash(&Value::Object(core_map));

        let rfc3161_records: Vec<Rfc3161TokenRecord> =
            tsr_results.iter().map(|(rec, _, _)| rec.clone()).collect();
        let tsr_blobs: Vec<(String, Vec<u8>)> = tsr_results
            .iter()
            .map(|(_, fname, bytes)| (fname.clone(), bytes.clone()))
            .collect();
        let tsa_names: Vec<String> = rfc3161_records.iter().map(|r| r.tsa.clone()).collect();

        let entry = LedgerEntry {
            entry_id: entry_id.clone(),
            user_pubkey: identity.pubkey.clone(),
            artifact_hash: item.artifact_hash.clone(),
            canonicalization: item.canonicalization.clone(),
            signature: item.signature.clone(),
            client_ts: item.client_ts.clone(),
            received_ts: received_ts.clone(),
            rfc3161_tokens: rfc3161_records,
            ots: ots_record.clone(),
            capture_source: "manual".to_string(),
            metadata,
            chain: ChainRecord {
                sequence,
                prev_entry_hash: prev_entry_hash.clone(),
                entry_hash: entry_hash.clone(),
            },
        };

        let zip_bytes = build_bundle_zip_bytes(&entry, &tsr_blobs, &ots_blob)?;
        let bundle_filename = format!("{}.oake.zip", entry_id);
        let bundle_abs = proofs_dir.join(&bundle_filename);
        fs::write(&bundle_abs, &zip_bytes)
            .map_err(|e| format!("Failed to write {}: {}", bundle_abs.display(), e))?;

        let rel_bundle_path = format!(".oake/proofs/{}", bundle_filename);
        let index_row = LocalIndexRow {
            sequence,
            prev_entry_hash,
            entry_hash: entry_hash.clone(),
            entry_id: entry_id.clone(),
            artifact_hash: item.artifact_hash.clone(),
            canonicalization: item.canonicalization.clone(),
            ots_status: ots_record.status.clone(),
            tsa_count: tsa_names.len(),
            published_to: None,
            bundle_path: rel_bundle_path.clone(),
            captured_ts: received_ts.clone(),
        };
        append_local_index_row(&index_path, &index_row)?;

        head_seq = sequence;
        head_hash = entry_hash;

        anchored_entries.push(AnchoredEntryResult {
            relative_path: item.relative_path.clone(),
            entry_id,
            sequence,
            artifact_hash: item.artifact_hash.clone(),
            canonicalization: item.canonicalization.clone(),
            ots_status: ots_record.status,
            tsa_count: tsa_names.len(),
            tsas: tsa_names,
            bundle_path: rel_bundle_path,
            captured_ts: received_ts,
        });
    }

    let (ots_mode, ots_calendar) = if let Some((host, _, _)) = live_ots_result {
        ("pending".to_string(), host)
    } else if offline {
        (
            "offline".to_string(),
            "alice.btc.calendar.opentimestamps.org".to_string(),
        )
    } else {
        (
            "provisional".to_string(),
            "alice.btc.calendar.opentimestamps.org".to_string(),
        )
    };

    Ok(AnchorBatchResult {
        workspace_path: clean_workspace,
        batch_id,
        merkle_root,
        ots_mode,
        ots_calendar,
        ots_rate_limited,
        ots_retry_after_secs,
        anchored_count: anchored_entries.len(),
        warnings,
        entries: anchored_entries,
    })
}

// ============================================================================
// Offline/Local Proof Bundle Verification
// ============================================================================

fn try_openssl_verify_tsr(digest_hex: &str, tsr_bytes: &[u8]) -> Option<(bool, String)> {
    let ca_candidates = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"];
    let ca_file = ca_candidates.iter().find(|p| Path::new(p).exists())?;

    let openssl_candidates = ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "openssl"];
    let mut found_bin: Option<&str> = None;
    for bin in openssl_candidates {
        if let Ok(out) = Command::new(bin).args(["ts", "-help"]).output() {
            if out.status.success() || !out.stderr.is_empty() {
                found_bin = Some(bin);
                break;
            }
        }
    }
    let bin = found_bin?;

    let tmp_dir = std::env::temp_dir().join(format!("oake-tsr-{}", generate_ulid_at(now_ms())));
    if fs::create_dir_all(&tmp_dir).is_err() {
        return None;
    }
    let tmp_tsr = tmp_dir.join("token.tsr");
    let res = if fs::write(&tmp_tsr, tsr_bytes).is_ok() {
        Command::new(bin)
            .args([
                "ts",
                "-verify",
                "-digest",
                digest_hex,
                "-in",
                &tmp_tsr.to_string_lossy(),
                "-CAfile",
                ca_file,
            ])
            .output()
            .ok()
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let ok = output.status.success() && stdout.contains("Verification: OK");
                let msg = if ok {
                    "Verification: OK".to_string()
                } else if !stderr.is_empty() {
                    stderr
                } else {
                    stdout
                };
                (ok, msg)
            })
    } else {
        None
    };
    let _ = fs::remove_dir_all(&tmp_dir);
    res
}

/// Decide what a bundle actually proves. Anything that could not be checked
/// counts as missing, never as passed.
fn assess_bundle(
    signature_signed: bool,
    signature_valid: bool,
    file_matches: Option<bool>,
    ots_ok: bool,
    token_error: bool,
    tokens: &[TsrCheckSummary],
    btc_block: Option<u64>,
) -> (&'static str, String) {
    let failure = if signature_signed && !signature_valid {
        Some("The author signature is invalid.")
    } else if file_matches == Some(false) {
        Some("The original file does not match this proof.")
    } else if !ots_ok {
        Some("proof.ots is missing, damaged, or for a different file.")
    } else if token_error || tokens.iter().any(|t| t.openssl_verified == Some(false)) {
        Some("A timestamp token failed verification.")
    } else {
        None
    };
    if let Some(reason) = failure {
        return ("failed", reason.to_string());
    }

    let checked = tokens.iter().filter(|t| t.openssl_verified == Some(true)).count();
    let mut notes = Vec::new();
    notes.push(if signature_signed {
        "Signature: valid.".to_string()
    } else {
        "Signature: none.".to_string()
    });
    notes.push(match file_matches {
        Some(_) => "File: matches.".to_string(),
        None => "File: not checked.".to_string(),
    });
    notes.push(if checked > 0 {
        format!("Timestamp: {} token(s) verified.", checked)
    } else if tokens.is_empty() {
        "Timestamp: no token in this proof.".to_string()
    } else {
        "Timestamp: token signature could not be verified on this computer.".to_string()
    });
    notes.push(match btc_block {
        Some(block) => format!(
            "Bitcoin: block {} is claimed but not checked against Bitcoin (use `ots verify`).",
            block
        ),
        None => "Bitcoin: no confirmed block.".to_string(),
    });

    let verdict = if signature_signed && checked > 0 {
        "verified"
    } else {
        "incomplete"
    };
    (verdict, notes.join("\n"))
}

pub fn verify_bundle(
    bundle_path: String,
    original_file_path: Option<String>,
) -> Result<BundleVerifyResult, String> {
    let abs_bundle = expand_user_path(&bundle_path, dirs::home_dir().as_deref());
    if !abs_bundle.is_file() {
        return Err(format!("Proof bundle not found: {}", bundle_path));
    }
    let zip_bytes = fs::read(&abs_bundle)
        .map_err(|e| format!("Failed to read {}: {}", abs_bundle.display(), e))?;
    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| format!("Invalid ZIP archive {}: {}", bundle_path, e))?;

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..archive.len() {
        let mut f = archive
            .by_index(i)
            .map_err(|e| format!("Corrupt ZIP entry: {}", e))?;
        if f.is_dir() {
            continue;
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .map_err(|e| format!("Failed to read ZIP entry {}: {}", f.name(), e))?;
        files.insert(f.name().to_string(), data);
    }

    let entry_raw = files
        .get("entry.json")
        .ok_or_else(|| "Invalid proof bundle: missing entry.json".to_string())?;
    let entry: LedgerEntry = serde_json::from_slice(entry_raw)
        .map_err(|e| format!("Invalid entry.json in bundle: {}", e))?;

    let (signature_signed, signature_valid) = verify_ed25519_signature(
        &entry.user_pubkey,
        &entry.signature,
        &entry.artifact_hash,
        &entry.canonicalization,
        &entry.client_ts,
    );

    let (file_checked, file_matches) = match original_file_path {
        Some(ref orig) if !orig.trim().is_empty() => {
            let orig_path = expand_user_path(orig, dirs::home_dir().as_deref());
            if !orig_path.is_file() {
                return Err(format!("Original file not found: {}", orig));
            }
            let (computed_hash, _) = canonicalize_and_hash(&orig_path, &entry.canonicalization)?;
            (true, Some(computed_hash.eq_ignore_ascii_case(&entry.artifact_hash)))
        }
        _ => (false, None),
    };

    let (ots_header_valid, ots_digest_matches, ots_steps, ots_btc_block, ots_calendar) =
        if let Some(ots_bytes) = files.get("proof.ots") {
            let check = inspect_ots_proof(ots_bytes, &entry.artifact_hash);
            let btc = check.bitcoin.first().map(|b| b.btc_block);
            let cal = check
                .pending
                .first()
                .map(|p| p.uri.clone())
                .or_else(|| Some(entry.ots.calendar.clone()));
            (
                check.valid_header,
                check.digest_matches,
                check.steps,
                btc,
                cal,
            )
        } else {
            (false, false, 0, None, None)
        };

    let digest_hex = entry
        .artifact_hash
        .strip_prefix("sha256:")
        .unwrap_or(&entry.artifact_hash)
        .to_ascii_lowercase();
    let expected_digest_arr: Option<[u8; 32]> = hex::decode(&digest_hex)
        .ok()
        .and_then(|v| v.try_into().ok());

    let mut tsa_tokens = Vec::new();
    let mut all_tsrs_ok = true;
    for (name, data) in &files {
        if !name.starts_with("rfc3161/") || !name.ends_with(".tsr") {
            continue;
        }
        let matching_rec = entry
            .rfc3161_tokens
            .iter()
            .find(|t| t.token_ref.replace("blob://tsr/", "rfc3161/") == *name);
        let tsa_name = matching_rec.map(|r| r.tsa.clone());

        if data.first() == Some(&0x30) {
            if let Some(ref exp32) = expected_digest_arr {
                match parse_rfc3161_timestamp_resp(data, exp32) {
                    Ok(parsed) => {
                        let openssl_res = try_openssl_verify_tsr(&digest_hex, data);
                        let (openssl_verified, detail) = match openssl_res {
                            Some((ok, msg)) => {
                                if !ok {
                                    all_tsrs_ok = false;
                                }
                                (Some(ok), msg)
                            }
                            None => (None, "DER structure & digest imprint verified".to_string()),
                        };
                        tsa_tokens.push(TsrCheckSummary {
                            filename: name.clone(),
                            tsa: tsa_name,
                            der_valid: true,
                            digest_matches: parsed.digest_matches,
                            gen_time: Some(parsed.gen_time),
                            serial_number: Some(parsed.serial_number),
                            openssl_verified,
                            detail,
                        });
                        if !parsed.digest_matches {
                            all_tsrs_ok = false;
                        }
                    }
                    Err(e) => {
                        all_tsrs_ok = false;
                        tsa_tokens.push(TsrCheckSummary {
                            filename: name.clone(),
                            tsa: tsa_name,
                            der_valid: false,
                            digest_matches: false,
                            gen_time: None,
                            serial_number: None,
                            openssl_verified: None,
                            detail: e,
                        });
                    }
                }
            }
        } else {
            tsa_tokens.push(TsrCheckSummary {
                filename: name.clone(),
                tsa: tsa_name,
                der_valid: false,
                digest_matches: false,
                gen_time: matching_rec.map(|r| r.gen_time.clone()),
                serial_number: matching_rec.map(|r| r.serial_number.clone()),
                openssl_verified: None,
                detail: "Non-DER token format".to_string(),
            });
        }
    }

    let verify_md_present = files.contains_key("VERIFY.md");
    let (verdict, conclusion) = assess_bundle(
        signature_signed,
        signature_valid,
        file_matches,
        ots_header_valid && ots_digest_matches,
        !all_tsrs_ok,
        &tsa_tokens,
        ots_btc_block,
    );

    Ok(BundleVerifyResult {
        valid: verdict == "verified",
        verdict: verdict.to_string(),
        bundle_path: clean_path_string(&abs_bundle),
        entry_id: entry.entry_id,
        artifact_hash: entry.artifact_hash,
        canonicalization: entry.canonicalization,
        user_pubkey: entry.user_pubkey,
        client_ts: entry.client_ts,
        received_ts: entry.received_ts,
        signature_signed,
        signature_valid,
        file_checked,
        file_matches,
        ots_header_valid,
        ots_digest_matches,
        ots_status: entry.ots.status,
        ots_steps,
        ots_btc_block,
        ots_calendar,
        tsa_tokens,
        verify_md_present,
        conclusion,
    })
}

// ============================================================================
// Publish (.oake.zip -> POST /v1/witness)
// ============================================================================

#[derive(Debug, Deserialize)]
struct WitnessEndpointResponse {
    #[serde(default)]
    witnessed: bool,
    #[serde(default)]
    deduplicated: bool,
    #[serde(default)]
    error: Option<String>,
}

pub fn push_workspace(workspace_path: String, endpoint: String) -> Result<PushSummary, String> {
    let root = PathBuf::from(workspace_path.trim());
    if !root.is_dir() {
        return Err(format!("Workspace directory not found: {}", workspace_path));
    }
    let root_canon = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let clean_workspace = clean_path_string(&root_canon);

    let normalized_endpoint = endpoint.trim().trim_end_matches('/').to_string();
    if !normalized_endpoint.starts_with("http://") && !normalized_endpoint.starts_with("https://")
    {
        return Err(format!(
            "Endpoint must start with http:// or https:// (got: {})",
            endpoint
        ));
    }

    let proofs_dir = root_canon.join(".oake").join("proofs");
    let index_path = root_canon.join(".oake").join("index.jsonl");
    let mut rows = read_local_index(&index_path)?;

    let mut bundle_paths = Vec::new();
    if proofs_dir.is_dir() {
        let mut names: Vec<String> = fs::read_dir(&proofs_dir)
            .map_err(|e| format!("Failed to read {}: {}", proofs_dir.display(), e))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".oake.zip") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        for name in names {
            bundle_paths.push(proofs_dir.join(name));
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let witness_url = format!("{}/v1/witness", normalized_endpoint);
    let total_bundles = bundle_paths.len();
    let mut pushed_count = 0usize;
    let mut deduplicated_count = 0usize;
    let mut already_published_count = 0usize;
    let mut failed_count = 0usize;
    let mut results = Vec::new();
    let mut index_dirty = false;

    for bundle_abs in bundle_paths {
        let entry_opt = read_entry_from_bundle_file(&bundle_abs);
        let Some(entry) = entry_opt else {
            failed_count += 1;
            results.push(PushItemResult {
                entry_id: "unknown".to_string(),
                bundle_path: clean_path_string(&bundle_abs),
                witnessed: false,
                deduplicated: false,
                error: Some("Invalid bundle: missing or unreadable entry.json".to_string()),
            });
            continue;
        };

        let existing_idx = rows.iter().position(|r| r.entry_id == entry.entry_id);
        if let Some(idx) = existing_idx {
            if rows[idx].published_to.as_deref() == Some(normalized_endpoint.as_str()) {
                already_published_count += 1;
                continue;
            }
        }

        let zip_bytes = match fs::read(&bundle_abs) {
            Ok(b) => b,
            Err(e) => {
                failed_count += 1;
                results.push(PushItemResult {
                    entry_id: entry.entry_id,
                    bundle_path: clean_path_string(&bundle_abs),
                    witnessed: false,
                    deduplicated: false,
                    error: Some(format!("Failed to read bundle: {}", e)),
                });
                continue;
            }
        };

        match client
            .post(&witness_url)
            .header("Content-Type", "application/oake-bundle+zip")
            .body(zip_bytes)
            .send()
        {
            Ok(resp) => {
                let status = resp.status();
                let parsed: Option<WitnessEndpointResponse> = resp
                    .text()
                    .ok()
                    .and_then(|body| serde_json::from_str(&body).ok());
                if status.is_success() {
                    let witnessed = parsed.as_ref().map(|p| p.witnessed).unwrap_or(true);
                    let deduplicated = parsed.as_ref().map(|p| p.deduplicated).unwrap_or(false);
                    if let Some(idx) = existing_idx {
                        rows[idx].published_to = Some(normalized_endpoint.clone());
                        index_dirty = true;
                    }
                    pushed_count += 1;
                    if deduplicated {
                        deduplicated_count += 1;
                    }
                    results.push(PushItemResult {
                        entry_id: entry.entry_id,
                        bundle_path: clean_path_string(&bundle_abs),
                        witnessed,
                        deduplicated,
                        error: None,
                    });
                } else {
                    failed_count += 1;
                    let msg = parsed
                        .and_then(|p| p.error)
                        .unwrap_or_else(|| format!("HTTP {}", status));
                    results.push(PushItemResult {
                        entry_id: entry.entry_id,
                        bundle_path: clean_path_string(&bundle_abs),
                        witnessed: false,
                        deduplicated: false,
                        error: Some(msg),
                    });
                }
            }
            Err(e) => {
                failed_count += 1;
                results.push(PushItemResult {
                    entry_id: entry.entry_id,
                    bundle_path: clean_path_string(&bundle_abs),
                    witnessed: false,
                    deduplicated: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    if index_dirty && !rows.is_empty() {
        write_local_index(&index_path, &rows)?;
    }

    Ok(PushSummary {
        workspace_path: clean_workspace,
        endpoint: normalized_endpoint,
        total_bundles,
        pushed_count,
        deduplicated_count,
        already_published_count,
        failed_count,
        results,
    })
}

#[cfg(test)]
mod verdict_tests {
    use super::*;

    fn token(openssl_verified: Option<bool>) -> TsrCheckSummary {
        TsrCheckSummary {
            filename: "rfc3161/x.tsr".to_string(),
            tsa: None,
            der_valid: true,
            digest_matches: true,
            gen_time: None,
            serial_number: None,
            openssl_verified,
            detail: String::new(),
        }
    }

    fn verdict(signed: bool, sig_ok: bool, file: Option<bool>, ots_ok: bool, tokens: &[TsrCheckSummary]) -> &'static str {
        assess_bundle(signed, sig_ok, file, ots_ok, false, tokens, None).0
    }

    #[test]
    fn verified_needs_a_signature_and_a_checked_timestamp() {
        assert_eq!(verdict(true, true, None, true, &[token(Some(true))]), "verified");
        assert_eq!(verdict(true, true, None, true, &[]), "incomplete");
        assert_eq!(verdict(true, true, None, true, &[token(None)]), "incomplete");
        assert_eq!(verdict(false, false, None, true, &[token(Some(true))]), "incomplete");
    }

    #[test]
    fn any_failed_check_fails_the_bundle() {
        let good = [token(Some(true))];
        assert_eq!(verdict(true, false, None, true, &good), "failed");
        assert_eq!(verdict(true, true, Some(false), true, &good), "failed");
        assert_eq!(verdict(true, true, None, false, &good), "failed");
        assert_eq!(verdict(true, true, None, true, &[token(Some(true)), token(Some(false))]), "failed");
        assert_eq!(assess_bundle(true, true, None, true, true, &good, None).0, "failed");
    }

    #[test]
    fn bitcoin_attestation_is_reported_as_unchecked() {
        let (v, text) = assess_bundle(true, true, None, true, false, &[], Some(900_000));
        assert_eq!(v, "incomplete");
        assert!(text.contains("not checked against Bitcoin"), "{text}");
    }

    #[test]
    fn offline_save_is_not_reported_as_verified() {
        let tmp = std::env::temp_dir().join(format!("oake-verdict-{}", generate_ulid_at(now_ms())));
        let ws = tmp.join("ws");
        fs::create_dir_all(&ws).unwrap();
        std::env::set_var("OAKE_HOME", tmp.join("home"));
        fs::write(ws.join("paper.tex"), "draft").unwrap();
        let ws_str = ws.to_string_lossy().to_string();
        let saved = anchor_files(ws_str, vec!["paper.tex".to_string()], None, None, true).unwrap();
        let bundle = ws.join(&saved.entries[0].bundle_path);
        let res = verify_bundle(bundle.to_string_lossy().to_string(), None).unwrap();
        let _ = fs::remove_dir_all(&tmp);
        assert!(!res.valid);
        assert_eq!(res.verdict, "incomplete");
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn typed_paths_may_start_with_a_tilde() {
        let home = Path::new("/home/u");
        assert_eq!(expand_user_path(" ~/research/paper ", Some(home)), home.join("research/paper"));
        assert_eq!(expand_user_path("~", Some(home)), home);
        assert_eq!(expand_user_path("/abs/~/x", Some(home)), PathBuf::from("/abs/~/x"));
        assert_eq!(expand_user_path("~other/x", Some(home)), PathBuf::from("~other/x"));
    }
}

#!/usr/bin/env node
/**
 * OAKe Desktop — Zero-Dependency Local Dev & Preview Bridge
 *
 * Serves `oake/desktop/ui/` on http://127.0.0.1:3410 (or PORT env var)
 * and exposes `/api/<cmd>` matching the Tauri v2 IPC command contract by
 * delegating directly to `cli/oake.mjs` and local `.oake/` operations.
 */

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import zlib from 'node:zlib';

const execFileAsync = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UI_DIR = path.join(__dirname, 'ui');
// The folder holding both cli/ and desktop/.
const REPO_ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.join(REPO_ROOT, 'cli', 'oake.mjs');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3410);

const SKIP_DIRS = new Set(['.git', 'node_modules', '.oake']);
const SKIP_EXTS = new Set(['.log', '.aux', '.pdf']);
const CANONICALIZATION_METHODS = ['raw-bytes/v1', 'text-normalized/v1', 'ipynb-cells/v1'];
const GENESIS_PREV_HASH =
	'sha256:0000000000000000000000000000000000000000000000000000000000000000';
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const OTS_VERSION = 0x01;
const OP_ATTESTATION = 0x00;
const OP_SHA1 = 0x02;
const OP_RIPEMD160 = 0x03;
const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const OP_FORK = 0xff;
const TAG_PENDING_ATTESTATION = Buffer.from('83dfe30d2ef90c8e', 'hex');
const TAG_BITCOIN_ATTESTATION = Buffer.from('0588960d73d71b45', 'hex');
const TAG_BITCOIN_ATTESTATION_ALT = Buffer.from('0588960d73d71901', 'hex');
const OAKE_TRAILER_MARKER = Buffer.from('\x00OAKE_ANCHOR_META\x00', 'utf8');
const OTS_MIN_SUBMIT_INTERVAL_MS = 60_000;
const OTS_CIRCUIT_BREAKER_MS = 600_000;
const HTTP_TIMEOUT_MS = 6_000;
const SHA256_OID_BYTES = Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

const PRIMARY_TSAS = [
	{ tsa: 'certum-eu', url: 'http://time.certum.pl', jurisdiction: 'EU / Poland (Asseco Certum)' }
];
const SECONDARY_TSA_PRIMARY = {
	tsa: 'digicert-us',
	url: 'http://timestamp.digicert.com',
	jurisdiction: 'US (DigiCert)'
};
const SECONDARY_TSA_FAILOVER = {
	tsa: 'sectigo-uk',
	url: 'http://timestamp.sectigo.com',
	jurisdiction: 'UK (Sectigo)'
};
const OTS_CALENDARS = [
	{ url: 'https://alice.btc.calendar.opentimestamps.org', label: 'Alice (OpenTimestamps)' },
	{ url: 'https://finney.calendar.eternitywall.com', label: 'Finney (Eternity Wall)' },
	{ url: 'https://bob.btc.calendar.opentimestamps.org', label: 'Bob (OpenTimestamps)' }
];

const MIME_TYPES = {
	'.html': 'text/html; charset=utf-8',
	'.css': 'text/css; charset=utf-8',
	'.js': 'application/javascript; charset=utf-8',
	'.mjs': 'application/javascript; charset=utf-8',
	'.json': 'application/json; charset=utf-8',
	'.svg': 'image/svg+xml',
	'.png': 'image/png',
	'.ico': 'image/x-icon'
};

let lastUlidTimestampMs = -1;
const lastUlidRandom = new Uint8Array(10);

function getOakeHome() {
	return process.env.OAKE_HOME || path.join(os.homedir(), '.config', 'oake');
}

function getWorkspacesFile() {
	return path.join(getOakeHome(), 'desktop-workspaces.json');
}

function getSettingsFile() {
	return path.join(getOakeHome(), 'desktop-settings.json');
}

function expandUserPath(inputPath) {
	if (typeof inputPath !== 'string') return '';
	const trimmed = inputPath.trim();
	if (trimmed === '~') return os.homedir();
	if (trimmed.startsWith('~/') || trimmed.startsWith('~\\')) {
		return path.join(os.homedir(), trimmed.slice(2));
	}
	return trimmed;
}

function ensureDir(dirPath) {
	fs.mkdirSync(dirPath, { recursive: true });
}

function sha256Hex(buffer) {
	return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function runCli(args, cwd = REPO_ROOT) {
	const env = { ...process.env, OAKE_HOME: getOakeHome() };
	const { stdout, stderr } = await execFileAsync(process.execPath, [CLI_PATH, ...args], {
		cwd,
		env,
		maxBuffer: 4 * 1024 * 1024
	});
	return { stdout: stdout.trim(), stderr: stderr.trim() };
}

function readJsonSafe(filePath, fallback) {
	try {
		if (!fs.existsSync(filePath)) return fallback;
		return JSON.parse(fs.readFileSync(filePath, 'utf8'));
	} catch {
		return fallback;
	}
}

function writeJsonSafe(filePath, data) {
	ensureDir(path.dirname(filePath));
	fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

function readSettings() {
	const defaults = {
		auto_snapshot_24h: false,
		default_endpoint: 'http://127.0.0.1:3000'
	};
	return { ...defaults, ...readJsonSafe(getSettingsFile(), {}) };
}

function readSavedWorkspaces() {
	const list = readJsonSafe(getWorkspacesFile(), []);
	return Array.isArray(list) ? list : [];
}

function saveWorkspaces(list) {
	writeJsonSafe(getWorkspacesFile(), list);
}

// ============================================================================
// PKZIP Reader/Writer (compatible with cli/oake.mjs & bundle.ts)
// ============================================================================

function sanitizeZipPath(name) {
	const normalized = name.replace(/\\/g, '/').replace(/^\/+/, '');
	if (!normalized || normalized.includes('\0')) {
		throw new Error(`Invalid ZIP entry name: ${JSON.stringify(name)}`);
	}
	const segments = normalized.split('/');
	if (segments.some((seg) => seg === '..' || seg === '.')) {
		throw new Error(`Unsafe ZIP path traversal: ${name}`);
	}
	return normalized;
}

// Limits for proof bundles, which may come from anyone. Real ones are a few small files.
const MAX_ZIP_ENTRIES = 64;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 24 * 1024 * 1024;

function inflateEntry(method, data, limit) {
	const tooLarge = () => new Error('Proof bundle is too large to unpack safely');
	if (limit <= 0) throw tooLarge();
	if (method === 0) {
		if (data.length > limit) throw tooLarge();
		return data;
	}
	if (method !== 8) throw new Error(`Unsupported ZIP compression method ${method}`);
	try {
		return zlib.inflateRawSync(data, { maxOutputLength: limit });
	} catch (err) {
		if (err.code === 'ERR_BUFFER_TOO_LARGE') throw tooLarge();
		throw err;
	}
}

function readZipEntries(zipBuffer) {
	let eocdOffset = -1;
	const minOffset = Math.max(0, zipBuffer.length - 65557);
	for (let i = zipBuffer.length - 22; i >= minOffset; i--) {
		if (zipBuffer.readUInt32LE(i) === 0x06054b50) {
			eocdOffset = i;
			break;
		}
	}
	if (eocdOffset === -1) {
		throw new Error('Invalid ZIP archive: EOCD not found');
	}
	const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
	const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
	if (totalEntries > MAX_ZIP_ENTRIES) {
		throw new Error('Proof bundle is too large: too many files');
	}

	const files = new Map();
	let totalBytes = 0;
	let pos = cdOffset;
	for (let i = 0; i < totalEntries; i++) {
		if (pos + 46 > zipBuffer.length || zipBuffer.readUInt32LE(pos) !== 0x02014b50) {
			throw new Error('Invalid ZIP archive: corrupt Central Directory');
		}
		const method = zipBuffer.readUInt16LE(pos + 10);
		const compressedSize = zipBuffer.readUInt32LE(pos + 20);
		const fnLen = zipBuffer.readUInt16LE(pos + 28);
		const extraLen = zipBuffer.readUInt16LE(pos + 30);
		const commentLen = zipBuffer.readUInt16LE(pos + 32);
		const localHeaderOffset = zipBuffer.readUInt32LE(pos + 42);
		const filename = sanitizeZipPath(
			zipBuffer.subarray(pos + 46, pos + 46 + fnLen).toString('utf8')
		);
		const localFnLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
		const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
		const dataStart = localHeaderOffset + 30 + localFnLen + localExtraLen;
		const compressedData = zipBuffer.subarray(dataStart, dataStart + compressedSize);
		const content = inflateEntry(method, compressedData, Math.min(MAX_ENTRY_BYTES, MAX_TOTAL_BYTES - totalBytes));
		totalBytes += content.length;
		files.set(filename, content);
		pos += 46 + fnLen + extraLen + commentLen;
	}
	return files;
}

function dateToDos(date) {
	const year = Math.max(1980, date.getUTCFullYear());
	const dosTime =
		((date.getUTCHours() & 0x1f) << 11) |
		((date.getUTCMinutes() & 0x3f) << 5) |
		(Math.floor(date.getUTCSeconds() / 2) & 0x1f);
	const dosDate =
		(((year - 1980) & 0x7f) << 9) |
		(((date.getUTCMonth() + 1) & 0x0f) << 5) |
		(date.getUTCDate() & 0x1f);
	return { dosTime, dosDate };
}

function writeZipArchive(entries) {
	const { dosTime, dosDate } = dateToDos(new Date());
	const localChunks = [];
	const centralChunks = [];
	let offset = 0;

	for (const entry of entries) {
		const cleanName = sanitizeZipPath(entry.name);
		const nameBuf = Buffer.from(cleanName, 'utf8');
		const rawBuf = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data);
		const crc = zlib.crc32(rawBuf) >>> 0;
		const deflated = zlib.deflateRawSync(rawBuf);
		const useDeflate = deflated.length < rawBuf.length;
		const method = useDeflate ? 8 : 0;
		const payload = useDeflate ? deflated : rawBuf;

		const lfh = Buffer.alloc(30);
		lfh.writeUInt32LE(0x04034b50, 0);
		lfh.writeUInt16LE(20, 4);
		lfh.writeUInt16LE(0x0800, 6);
		lfh.writeUInt16LE(method, 8);
		lfh.writeUInt16LE(dosTime, 10);
		lfh.writeUInt16LE(dosDate, 12);
		lfh.writeUInt32LE(crc, 14);
		lfh.writeUInt32LE(payload.length, 18);
		lfh.writeUInt32LE(rawBuf.length, 22);
		lfh.writeUInt16LE(nameBuf.length, 26);
		lfh.writeUInt16LE(0, 28);
		localChunks.push(lfh, nameBuf, payload);

		const cdh = Buffer.alloc(46);
		cdh.writeUInt32LE(0x02014b50, 0);
		cdh.writeUInt16LE(0x0314, 4);
		cdh.writeUInt16LE(20, 6);
		cdh.writeUInt16LE(0x0800, 8);
		cdh.writeUInt16LE(method, 10);
		cdh.writeUInt16LE(dosTime, 12);
		cdh.writeUInt16LE(dosDate, 14);
		cdh.writeUInt32LE(crc, 16);
		cdh.writeUInt32LE(payload.length, 20);
		cdh.writeUInt32LE(rawBuf.length, 24);
		cdh.writeUInt16LE(nameBuf.length, 28);
		cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38);
		cdh.writeUInt32LE(offset, 42);
		centralChunks.push(cdh, nameBuf);

		offset += lfh.length + nameBuf.length + payload.length;
	}

	const centralDir = Buffer.concat(centralChunks);
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(centralDir.length, 12);
	eocd.writeUInt32LE(offset, 16);
	return Buffer.concat([...localChunks, centralDir, eocd]);
}

// ============================================================================
// Canonicalization & Crypto Helpers
// ============================================================================

function canonicalizeAndHash(filePath, canonMethod) {
	const rawBytes = fs.readFileSync(filePath);
	if (canonMethod === 'raw-bytes/v1') {
		return { artifactHash: `sha256:${sha256Hex(rawBytes)}`, byteSize: rawBytes.byteLength };
	}
	if (canonMethod === 'text-normalized/v1') {
		const normalized = rawBytes
			.toString('utf8')
			.replace(/\r\n?/g, '\n')
			.split('\n')
			.map((line) => line.replace(/[ \t]+$/, ''))
			.join('\n');
		return {
			artifactHash: `sha256:${sha256Hex(Buffer.from(normalized, 'utf8'))}`,
			byteSize: rawBytes.byteLength
		};
	}
	if (canonMethod === 'ipynb-cells/v1') {
		const parsed = JSON.parse(rawBytes.toString('utf8'));
		const cells = Array.isArray(parsed?.cells) ? parsed.cells : [];
		const cellDigests = cells.map((cell) => {
			const cellType = typeof cell?.cell_type === 'string' ? cell.cell_type : 'unknown';
			const sourceText = Array.isArray(cell?.source)
				? cell.source.join('')
				: typeof cell?.source === 'string'
					? cell.source
					: '';
			return crypto.createHash('sha256').update(`${cellType}\n${sourceText}`, 'utf8').digest();
		});
		return {
			artifactHash: `sha256:${sha256Hex(Buffer.concat(cellDigests))}`,
			byteSize: rawBytes.byteLength
		};
	}
	throw new Error(`Unsupported canonicalization method: ${canonMethod}`);
}

function inferDefaultCanon(filePath, explicitCanon) {
	if (explicitCanon && CANONICALIZATION_METHODS.includes(explicitCanon)) {
		return explicitCanon;
	}
	return path.extname(filePath).toLowerCase() === '.ipynb' ? 'ipynb-cells/v1' : 'raw-bytes/v1';
}

function inferArtifactKind(filePath) {
	const ext = path.extname(filePath).toLowerCase();
	if (ext === '.tex' || ext === '.bib') return 'latex';
	if (ext === '.ipynb') return 'notebook';
	if (['.py', '.ts', '.tsx', '.js', '.mjs', '.rs', '.go', '.c', '.cpp'].includes(ext)) return 'code';
	if (ext === '.md' || ext === '.txt') return 'text';
	if (ext === '.csv' || ext === '.json' || ext === '.parquet') return 'dataset';
	return 'file';
}

function verifyEd25519Signature(userPubkey, signature, artifactHash, canonicalization, clientTs) {
	if (userPubkey === 'anonymous') return { signed: false, valid: true };
	if (
		typeof userPubkey !== 'string' ||
		!/^ed25519:[0-9a-f]{64}$/i.test(userPubkey) ||
		typeof signature !== 'string' ||
		!/^ed25519:[0-9a-f]{128}$/i.test(signature)
	) {
		return { signed: true, valid: false };
	}
	const rawPub = Buffer.from(userPubkey.slice('ed25519:'.length), 'hex');
	const spkiDer = Buffer.concat([SPKI_ED25519_PREFIX, rawPub]);
	const pubKeyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
	const sigBytes = Buffer.from(signature.slice('ed25519:'.length), 'hex');
	const payload = Buffer.from(`${artifactHash}|${canonicalization}|${clientTs}`, 'utf8');
	return { signed: true, valid: crypto.verify(null, payload, pubKeyObj, sigBytes) };
}

// ============================================================================
// Workspace Scanner
// ============================================================================

function collectWorkspaceFiles(rootDir) {
	const collected = [];
	function walk(dir) {
		const entries = fs.readdirSync(dir, { withFileTypes: true });
		entries.sort((a, b) => a.name.localeCompare(b.name));
		for (const entry of entries) {
			if (entry.isDirectory()) {
				if (SKIP_DIRS.has(entry.name)) continue;
				walk(path.join(dir, entry.name));
			} else if (entry.isFile()) {
				const ext = path.extname(entry.name).toLowerCase();
				if (SKIP_EXTS.has(ext)) continue;
				collected.push(path.join(dir, entry.name));
			}
		}
	}
	walk(rootDir);
	return collected;
}

function readLocalIndex(indexPath) {
	if (!fs.existsSync(indexPath)) return [];
	const raw = fs.readFileSync(indexPath, 'utf8');
	const rows = [];
	for (const line of raw.split('\n')) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			rows.push(JSON.parse(trimmed));
		} catch {
			// skip malformed line
		}
	}
	return rows;
}

function readBundleSummary(bundleAbsPath) {
	if (!fs.existsSync(bundleAbsPath)) return null;
	try {
		const entries = readZipEntries(fs.readFileSync(bundleAbsPath));
		const entryRaw = entries.get('entry.json');
		if (!entryRaw) return null;
		return JSON.parse(entryRaw.toString('utf8'));
	} catch {
		return null;
	}
}

function formatTsaLabel(tsa) {
	if (tsa === 'certum-eu') return 'Certum EU';
	if (tsa === 'digicert-us') return 'DigiCert US';
	if (tsa === 'sectigo-uk') return 'Sectigo UK';
	if (tsa === 'sovereign-ed25519') return 'Sovereign Fallback';
	return tsa;
}

function scanWorkspaceInternal(wsPath) {
	const resolved = path.resolve(expandUserPath(wsPath));
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
		throw new Error(`Workspace directory does not exist: ${wsPath}`);
	}
	const realRoot = fs.realpathSync(resolved);
	const name = path.basename(realRoot) || realRoot;
	const oakeDir = path.join(realRoot, '.oake');
	const indexPath = path.join(oakeDir, 'index.jsonl');
	const notesPath = path.join(oakeDir, 'notes.json');
	const notesMap = readJsonSafe(notesPath, {});
	const indexRows = readLocalIndex(indexPath);

	// Load entry.json summaries from .oake/proofs/*.oake.zip
	const entryDetailsById = new Map();
	for (const row of indexRows) {
		const relBundle = row.bundle_path || `.oake/proofs/${row.entry_id}.oake.zip`;
		const absBundle = path.isAbsolute(relBundle) ? relBundle : path.join(realRoot, relBundle);
		const entry = readBundleSummary(absBundle);
		if (entry) {
			entryDetailsById.set(row.entry_id, { entry, absBundle });
		}
	}

	const absFiles = collectWorkspaceFiles(realRoot);
	const hintToRelPath = new Map();
	for (const absPath of absFiles) {
		const rel = path.relative(realRoot, absPath).replace(/\\/g, '/');
		const hashed = `sha256:${sha256Hex(Buffer.from(rel, 'utf8'))}`;
		hintToRelPath.set(rel, rel);
		hintToRelPath.set(hashed, rel);
	}

	// Build latest entry per path_hint and set of anchored hashes
	const latestByPathHint = new Map();
	const latestByHash = new Map();
	for (const row of indexRows) {
		const detail = entryDetailsById.get(row.entry_id);
		const pathHint = detail?.entry?.metadata?.path_hint;
		if (pathHint) {
			const prev = latestByPathHint.get(pathHint);
			if (!prev || row.sequence > prev.sequence) {
				latestByPathHint.set(pathHint, row);
			}
		}
		if (row.artifact_hash) {
			const prevH = latestByHash.get(row.artifact_hash);
			if (!prevH || row.sequence > prevH.sequence) {
				latestByHash.set(row.artifact_hash, row);
			}
		}
	}

	const files = absFiles.map((absPath) => {
		const relPath = path.relative(realRoot, absPath).replace(/\\/g, '/');
		const hashedHint = `sha256:${sha256Hex(Buffer.from(relPath, 'utf8'))}`;
		const matchedByPlain = latestByPathHint.get(relPath);
		const matchedByHashHint = latestByPathHint.get(hashedHint);
		const matchedPathRow =
			matchedByPlain && matchedByHashHint
				? matchedByPlain.sequence >= matchedByHashHint.sequence
					? matchedByPlain
					: matchedByHashHint
				: matchedByPlain || matchedByHashHint || null;

		let canon = inferDefaultCanon(absPath, matchedPathRow?.canonicalization);
		let hashed;
		try {
			hashed = canonicalizeAndHash(absPath, canon);
		} catch {
			canon = 'raw-bytes/v1';
			hashed = canonicalizeAndHash(absPath, 'raw-bytes/v1');
		}

		let status = 'untracked';
		let lastEntryId = null;

		if (matchedPathRow) {
			lastEntryId = matchedPathRow.entry_id;
			if (hashed.artifactHash === matchedPathRow.artifact_hash) {
				status = 'anchored';
			} else {
				status = 'modified';
			}
		} else {
			const hashMatch = latestByHash.get(hashed.artifactHash);
			if (hashMatch) {
				status = 'anchored';
				lastEntryId = hashMatch.entry_id;
			}
		}

		return {
			relative_path: relPath,
			byte_size: hashed.byteSize,
			canon,
			artifact_hash: hashed.artifactHash,
			status,
			last_entry_id: lastEntryId
		};
	});

	const history = indexRows
		.slice()
		.sort((a, b) => (b.sequence || 0) - (a.sequence || 0))
		.map((row) => {
			const detail = entryDetailsById.get(row.entry_id);
			const entry = detail?.entry;
			const relBundle = row.bundle_path || `.oake/proofs/${row.entry_id}.oake.zip`;
			const absBundle = detail?.absBundle || path.join(realRoot, relBundle);
			const pathHint = entry?.metadata?.path_hint || '';
			const resolvedLabel =
				hintToRelPath.get(pathHint) ||
				(pathHint && !pathHint.startsWith('sha256:') ? pathHint : null) ||
				entry?.metadata?.repo ||
				`${row.artifact_hash.slice(0, 18)}…`;
			const tsaNames = Array.isArray(entry?.rfc3161_tokens)
				? entry.rfc3161_tokens.map((t) => formatTsaLabel(t.tsa))
				: [];
			return {
				sequence: row.sequence,
				entry_id: row.entry_id,
				artifact_hash: row.artifact_hash,
				canonicalization: row.canonicalization,
				ots_status: entry?.ots?.status || row.ots_status || 'provisional',
				tsa_count: typeof row.tsa_count === 'number' ? row.tsa_count : tsaNames.length,
				tsa_names: tsaNames,
				tsa_ids: Array.isArray(entry?.rfc3161_tokens) ? entry.rfc3161_tokens.map((t) => t.tsa) : [],
				ots_calendar: entry?.ots?.calendar || 'alice.btc.calendar.opentimestamps.org',
				btc_block: entry?.ots?.btc_block ?? null,
				client_ts: entry?.client_ts || row.captured_ts || null,
				published_to: row.published_to || null,
				bundle_path: absBundle,
				relative_bundle_path: relBundle,
				path_label: resolvedLabel,
				note: entry?.metadata?.note || notesMap[row.entry_id] || null
			};
		});

	return {
		path: realRoot,
		name,
		files,
		history
	};
}

// ============================================================================
// Multi-File Batch Capture (for >1 selected files or notes, matching cli/oake.mjs)
// ============================================================================

function encode40BitsBase32(bytes, offset) {
	const val =
		(BigInt(bytes[offset]) << 32n) |
		(BigInt(bytes[offset + 1]) << 24n) |
		(BigInt(bytes[offset + 2]) << 16n) |
		(BigInt(bytes[offset + 3]) << 8n) |
		BigInt(bytes[offset + 4]);
	let out = '';
	for (let shift = 35n; shift >= 0n; shift -= 5n) {
		out += CROCKFORD_ALPHABET[Number((val >> shift) & 0x1fn)];
	}
	return out;
}

function generateUlid(nowMs) {
	let ts = nowMs === undefined ? Date.now() : Math.floor(nowMs);
	if (ts === lastUlidTimestampMs || (nowMs === undefined && ts < lastUlidTimestampMs)) {
		ts = lastUlidTimestampMs;
		let carry = 1;
		for (let i = 9; i >= 0 && carry > 0; i--) {
			const next = lastUlidRandom[i] + carry;
			lastUlidRandom[i] = next & 0xff;
			carry = next >> 8;
		}
		if (carry > 0) {
			lastUlidTimestampMs += 1;
			ts = lastUlidTimestampMs;
			lastUlidRandom.fill(0);
		}
	} else {
		lastUlidTimestampMs = ts;
		crypto.randomFillSync(lastUlidRandom);
	}
	const timeChars = new Array(10);
	let t = ts;
	for (let i = 9; i >= 0; i--) {
		timeChars[i] = CROCKFORD_ALPHABET[t % 32];
		t = Math.floor(t / 32);
	}
	return (
		timeChars.join('') +
		encode40BitsBase32(lastUlidRandom, 0) +
		encode40BitsBase32(lastUlidRandom, 5)
	);
}

function serializeCanonicalJson(value) {
	if (value === null) return 'null';
	if (typeof value === 'object' && typeof value.toJSON === 'function') {
		return serializeCanonicalJson(value.toJSON());
	}
	const kind = typeof value;
	if (kind === 'undefined' || kind === 'function' || kind === 'symbol') return undefined;
	if (kind === 'boolean' || kind === 'number' || kind === 'string') return JSON.stringify(value);
	if (Array.isArray(value)) {
		return `[${value.map((item) => serializeCanonicalJson(item) ?? 'null').join(',')}]`;
	}
	const keys = Object.keys(value).sort();
	const parts = [];
	for (const key of keys) {
		const ser = serializeCanonicalJson(value[key]);
		if (ser !== undefined) parts.push(`${JSON.stringify(key)}:${ser}`);
	}
	return `{${parts.join(',')}}`;
}

function computeEntryChainHash(entryCore) {
	const canonical = serializeCanonicalJson(entryCore) ?? 'null';
	return `sha256:${sha256Hex(Buffer.from(canonical, 'utf8'))}`;
}

function encodeDerLength(len) {
	if (len < 0x80) return Uint8Array.from([len]);
	const bytes = [];
	let remaining = len;
	while (remaining > 0) {
		bytes.unshift(remaining & 0xff);
		remaining >>>= 8;
	}
	return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

function encodeDerTlv(tag, value) {
	const valBuf = Buffer.isBuffer(value) ? value : Buffer.from(value);
	return Buffer.concat([Buffer.from([tag]), Buffer.from(encodeDerLength(valBuf.length)), valBuf]);
}

function encodeDerInteger(value) {
	if (value === 0n) return encodeDerTlv(0x02, Buffer.from([0x00]));
	let hex = value.toString(16);
	if (hex.length % 2 !== 0) hex = `0${hex}`;
	const bytes = Buffer.from(hex, 'hex');
	const valueBytes = (bytes[0] & 0x80) !== 0 ? Buffer.concat([Buffer.from([0x00]), bytes]) : bytes;
	return encodeDerTlv(0x02, valueBytes);
}

function buildRfc3161TimeStampReq(digest32) {
	const nonce = BigInt(`0x${crypto.randomBytes(8).toString('hex')}`) & ((1n << 63n) - 1n);
	const versionDer = encodeDerTlv(0x02, Buffer.from([0x01]));
	const oidDer = encodeDerTlv(0x06, SHA256_OID_BYTES);
	const nullDer = encodeDerTlv(0x05, Buffer.alloc(0));
	const hashAlgDer = encodeDerTlv(0x30, Buffer.concat([oidDer, nullDer]));
	const hashedMessageDer = encodeDerTlv(0x04, digest32);
	const messageImprintDer = encodeDerTlv(0x30, Buffer.concat([hashAlgDer, hashedMessageDer]));
	const nonceDer = encodeDerInteger(nonce);
	const certReqDer = encodeDerTlv(0x01, Buffer.from([0xff]));
	return encodeDerTlv(0x30, Buffer.concat([versionDer, messageImprintDer, nonceDer, certReqDer]));
}

function readDerTlv(bytes, offset) {
	const tag = bytes[offset];
	const firstLenByte = bytes[offset + 1];
	let len = 0;
	let valueStart = offset + 2;
	if ((firstLenByte & 0x80) === 0) {
		len = firstLenByte;
	} else {
		const numLenBytes = firstLenByte & 0x7f;
		for (let i = 0; i < numLenBytes; i++) len = (len << 8) | bytes[offset + 2 + i];
		valueStart = offset + 2 + numLenBytes;
	}
	return { tag, value: bytes.subarray(valueStart, valueStart + len), nextOffset: valueStart + len };
}

function parseAsn1Time(tag, bytes) {
	const raw = Buffer.from(bytes).toString('ascii');
	if (tag === 0x18) {
		const m = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/);
		if (m) return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ? m[7].slice(0, 4).padEnd(4, '0') : '.000'}Z`;
	} else if (tag === 0x17) {
		const m = raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
		if (m) {
			const yy = Number(m[1]);
			return `${yy >= 50 ? 1900 + yy : 2000 + yy}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.000Z`;
		}
	}
	return null;
}

function parseRfc3161TimeStampResp(derBytes, expectedDigest32) {
	const root = readDerTlv(derBytes, 0);
	const statusInfo = readDerTlv(root.value, 0);
	const statusVal = readDerTlv(statusInfo.value, 0);
	const pkiStatus = statusVal.value[statusVal.value.length - 1];
	if (pkiStatus !== 0 && pkiStatus !== 1) throw new Error(`TSA rejected (PKIStatus=${pkiStatus})`);
	let genTime = new Date().toISOString();
	let serialNumber = crypto.randomBytes(12).toString('hex').toUpperCase();
	const certNotAfter = new Date(Date.now() + 365 * 86_400_000).toISOString();
	try {
		const tokenInfo = readDerTlv(root.value, statusInfo.nextOffset);
		const contentType = readDerTlv(tokenInfo.value, 0);
		const contentWrap = readDerTlv(tokenInfo.value, contentType.nextOffset);
		const signedData = readDerTlv(contentWrap.value, 0);
		const sdVer = readDerTlv(signedData.value, 0);
		const digestAlgs = readDerTlv(signedData.value, sdVer.nextOffset);
		const encapContent = readDerTlv(signedData.value, digestAlgs.nextOffset);
		const eContentType = readDerTlv(encapContent.value, 0);
		const eContentWrap = readDerTlv(encapContent.value, eContentType.nextOffset);
		const eContentOctet = readDerTlv(eContentWrap.value, 0);
		const tstInfo = readDerTlv(eContentOctet.value, 0);
		const tstVer = readDerTlv(tstInfo.value, 0);
		const policyTlv = readDerTlv(tstInfo.value, tstVer.nextOffset);
		const imprintTlv = readDerTlv(tstInfo.value, policyTlv.nextOffset);
		const algTlv = readDerTlv(imprintTlv.value, 0);
		const hashedMsgTlv = readDerTlv(imprintTlv.value, algTlv.nextOffset);
		if (!Buffer.from(hashedMsgTlv.value).equals(Buffer.from(expectedDigest32))) {
			throw new Error('TSA digest mismatch');
		}
		const serialTlv = readDerTlv(tstInfo.value, imprintTlv.nextOffset);
		if (serialTlv.tag === 0x02) serialNumber = Buffer.from(serialTlv.value).toString('hex').toUpperCase();
		const genTimeTlv = readDerTlv(tstInfo.value, serialTlv.nextOffset);
		genTime = parseAsn1Time(genTimeTlv.tag, genTimeTlv.value) || genTime;
	} catch (err) {
		if (err instanceof Error && err.message.includes('digest mismatch')) throw err;
	}
	return { genTime, serialNumber, certNotAfter };
}

async function fetchWithTimeout(url, init, timeoutMs = HTTP_TIMEOUT_MS) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		return await fetch(url, { ...init, signal: controller.signal });
	} finally {
		clearTimeout(timer);
	}
}

async function requestExternalRfc3161Token(tsaDesc, digest32, entryId) {
	const reqDer = buildRfc3161TimeStampReq(digest32);
	const res = await fetchWithTimeout(tsaDesc.url, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/timestamp-query',
			Accept: 'application/timestamp-reply',
			'User-Agent': 'OAKe-CLI/0.1 (standalone-rfc3161-client)'
		},
		body: reqDer
	});
	if (!res.ok) throw new Error(`TSA ${tsaDesc.tsa} HTTP ${res.status}`);
	const respBuf = Buffer.from(await res.arrayBuffer());
	if (respBuf.length < 16 || respBuf[0] !== 0x30) throw new Error(`Invalid DER from ${tsaDesc.tsa}`);
	const parsed = parseRfc3161TimeStampResp(respBuf, digest32);
	const filename = `${entryId}-${tsaDesc.tsa}.tsr`;
	return {
		filename,
		tsrBytes: respBuf,
		record: {
			tsa: tsaDesc.tsa,
			token_ref: `blob://tsr/${filename}`,
			gen_time: parsed.genTime,
			serial_number: parsed.serialNumber,
			cert_not_after: parsed.certNotAfter,
			restamped_from: null,
			format: 'rfc3161-cms-der',
			signer_subject: tsaDesc.jurisdiction
		}
	};
}

async function stampDigestExternalTsas(entryId, artifactHash) {
	const digest32 = Buffer.from(artifactHash.slice('sha256:'.length), 'hex');
	const primary = Promise.allSettled(PRIMARY_TSAS.map((t) => requestExternalRfc3161Token(t, digest32, entryId)));
	const secondary = (async () => {
		try {
			return await requestExternalRfc3161Token(SECONDARY_TSA_PRIMARY, digest32, entryId);
		} catch {
			return await requestExternalRfc3161Token(SECONDARY_TSA_FAILOVER, digest32, entryId);
		}
	})();
	const settled = [...(await primary), ...(await Promise.allSettled([secondary]))];
	return settled.filter((r) => r.status === 'fulfilled').map((r) => r.value);
}

function encodeVarint(value) {
	const out = [];
	let v = value;
	while (v >= 0x80) {
		out.push((v % 128) | 0x80);
		v = Math.floor(v / 128);
	}
	out.push(v);
	return Buffer.from(out);
}

function buildMerkleBatch(leafHashes) {
	const sortedLeaves = Array.from(new Set(leafHashes.map((h) => h.trim().toLowerCase()))).sort();
	const paths = new Map(sortedLeaves.map((l) => [l, []]));
	let level = sortedLeaves.map((leaf) => ({
		hashBuf: Buffer.from(leaf.slice('sha256:'.length), 'hex'),
		members: [leaf]
	}));
	if (level.length === 1) {
		const only = level[0];
		paths.get(only.members[0]).push({ position: 'right', siblingHex: only.hashBuf.toString('hex') });
		const rootBuf = crypto.createHash('sha256').update(Buffer.concat([only.hashBuf, only.hashBuf])).digest();
		return { rootHash: `sha256:${rootBuf.toString('hex')}`, paths };
	}
	while (level.length > 1) {
		const nextLevel = [];
		for (let i = 0; i < level.length; i += 2) {
			const left = level[i];
			const hasRight = i + 1 < level.length;
			const right = hasRight ? level[i + 1] : level[i];
			if (hasRight) {
				for (const m of left.members) paths.get(m).push({ position: 'right', siblingHex: right.hashBuf.toString('hex') });
				for (const m of right.members) paths.get(m).push({ position: 'left', siblingHex: left.hashBuf.toString('hex') });
				nextLevel.push({
					hashBuf: crypto.createHash('sha256').update(Buffer.concat([left.hashBuf, right.hashBuf])).digest(),
					members: [...left.members, ...right.members]
				});
			} else {
				for (const m of left.members) paths.get(m).push({ position: 'right', siblingHex: left.hashBuf.toString('hex') });
				nextLevel.push({
					hashBuf: crypto.createHash('sha256').update(Buffer.concat([left.hashBuf, left.hashBuf])).digest(),
					members: [...left.members]
				});
			}
		}
		level = nextLevel;
	}
	return { rootHash: `sha256:${level[0].hashBuf.toString('hex')}`, paths };
}

function buildMerkleAndNonceOps(artifactHash, merklePath, batchNonce16) {
	const digest = Buffer.from(artifactHash.slice('sha256:'.length), 'hex');
	const chunks = [OTS_MAGIC, Buffer.from([OTS_VERSION, OP_SHA256]), digest];
	for (const step of merklePath) {
		chunks.push(Buffer.from([step.position === 'right' ? OP_APPEND : OP_PREPEND, 0x20]), Buffer.from(step.siblingHex, 'hex'), Buffer.from([OP_SHA256]));
	}
	chunks.push(Buffer.from([OP_APPEND, 0x10]), Buffer.from(batchNonce16), Buffer.from([OP_SHA256]));
	return Buffer.concat(chunks);
}

function composeProvisionalOtsBytes(artifactHash, merklePath, batchNonce16, calendarUri) {
	const prefix = buildMerkleAndNonceOps(artifactHash, merklePath, batchNonce16);
	const uriBytes = Buffer.from(calendarUri, 'utf8');
	const payload = Buffer.concat([encodeVarint(uriBytes.length), uriBytes]);
	return Buffer.concat([prefix, Buffer.from([OP_ATTESTATION]), TAG_PENDING_ATTESTATION, encodeVarint(payload.length), payload]);
}

function composeLiveCalendarOtsBytes(artifactHash, merklePath, batchNonce16, calendarResponseBytes) {
	return Buffer.concat([buildMerkleAndNonceOps(artifactHash, merklePath, batchNonce16), Buffer.from(calendarResponseBytes)]);
}

function decodeVarintSafe(buf, offset) {
	let result = 0;
	let multiplier = 1;
	let pos = offset;
	while (pos < buf.length) {
		const byte = buf[pos++];
		const next = result + (byte & 0x7f) * multiplier;
		if (!Number.isSafeInteger(next)) return null;
		result = next;
		if ((byte & 0x80) === 0) return { value: result, nextOffset: pos };
		multiplier *= 128;
		if (multiplier > Number.MAX_SAFE_INTEGER) return null;
	}
	return null;
}

function parseTimestampTree(buf, offset, current, merkleSteps, depth = 0) {
	if (depth > 256) return { nextOffset: offset, pending: [], bitcoin: [], error: 'Depth exceeded' };
	const pending = [];
	const bitcoin = [];
	let pos = offset;
	const parseBranch = (startPos, cur, steps, d) => {
		if (d > 256 || startPos >= buf.length) return { nextOffset: startPos, pending: [], bitcoin: [], error: 'Truncated' };
		let p = startPos;
		const op = buf[p++];
		if (op === OP_FORK) return parseTimestampTree(buf, p - 1, cur, steps, d + 1);
		if (op === OP_APPEND || op === OP_PREPEND) {
			const lv = decodeVarintSafe(buf, p);
			if (!lv || p + lv.value > buf.length) return { nextOffset: p, pending: [], bitcoin: [], error: 'Bad operand' };
			p = lv.nextOffset;
			const operand = buf.subarray(p, p + lv.value);
			p += lv.value;
			return parseTimestampTree(buf, p, op === OP_APPEND ? Buffer.concat([cur, operand]) : Buffer.concat([operand, cur]), steps + 1, d + 1);
		}
		if (op === OP_SHA256) return parseTimestampTree(buf, p, crypto.createHash('sha256').update(cur).digest(), steps + 1, d + 1);
		if (op === OP_SHA1) return parseTimestampTree(buf, p, crypto.createHash('sha1').update(cur).digest(), steps, d + 1);
		if (op === OP_RIPEMD160) return parseTimestampTree(buf, p, crypto.createHash('ripemd160').update(cur).digest(), steps, d + 1);
		if (op === OP_ATTESTATION) {
			const tag = buf.subarray(p, p + 8);
			p += 8;
			const plv = decodeVarintSafe(buf, p);
			if (!plv) return { nextOffset: p, pending: [], bitcoin: [], error: 'Bad payload len' };
			p = plv.nextOffset;
			const payloadEnd = p + plv.value;
			if (tag.equals(TAG_PENDING_ATTESTATION)) {
				const ulv = decodeVarintSafe(buf, p);
				const uri = ulv && ulv.nextOffset + ulv.value <= payloadEnd
					? buf.subarray(ulv.nextOffset, ulv.nextOffset + ulv.value).toString('utf8')
					: buf.subarray(p, payloadEnd).toString('utf8');
				return { nextOffset: payloadEnd, pending: [{ uri, commitmentHex: cur.toString('hex') }], bitcoin: [] };
			}
			if (tag.equals(TAG_BITCOIN_ATTESTATION) || tag.equals(TAG_BITCOIN_ATTESTATION_ALT)) {
				const bv = decodeVarintSafe(buf, p);
				let nextOffset = payloadEnd;
				if (buf.length - payloadEnd >= OAKE_TRAILER_MARKER.length && buf.subarray(payloadEnd, payloadEnd + OAKE_TRAILER_MARKER.length).equals(OAKE_TRAILER_MARKER)) {
					nextOffset = buf.length;
				}
				return { nextOffset, pending: [], bitcoin: [{ btc_block: bv?.value ?? null, root: cur.toString('hex') }] };
			}
			return { nextOffset: payloadEnd, pending: [], bitcoin: [] };
		}
		return { nextOffset: p, pending: [], bitcoin: [], error: `Opcode 0x${op.toString(16)}` };
	};
	while (pos < buf.length && buf[pos] === OP_FORK) {
		pos++;
		const br = parseBranch(pos, current, merkleSteps, depth + 1);
		if (br.error) return br;
		pending.push(...br.pending);
		bitcoin.push(...br.bitcoin);
		pos = br.nextOffset;
	}
	const fin = parseBranch(pos, current, merkleSteps, depth + 1);
	if (fin.error) return fin;
	pending.push(...fin.pending);
	bitcoin.push(...fin.bitcoin);
	return { nextOffset: fin.nextOffset, pending, bitcoin };
}

async function submitBlindedDigestToCalendars(oakeHome, calendarDigest32) {
	const guardPath = path.join(oakeHome, 'ots-rate-guard.json');
	const guard = {
		lastSubmitMs: null,
		lastPollByCommitment: {},
		hostBackoffs: {},
		totalHttpPosts: 0,
		totalHttpGets: 0,
		blockedSubmitFloods: 0,
		blockedPollFloods: 0,
		lastCalendarUsed: null,
		...readJsonSafe(guardPath, {})
	};
	const now = Date.now();
	if (guard.lastSubmitMs !== null) {
		const elapsed = Math.max(0, now - guard.lastSubmitMs);
		if (elapsed < OTS_MIN_SUBMIT_INTERVAL_MS) {
			guard.blockedSubmitFloods++;
			writeJsonSafe(guardPath, guard);
			return { ok: false, rateLimited: true, retryAfterMs: OTS_MIN_SUBMIT_INTERVAL_MS - elapsed };
		}
	}
	let lastError = 'All OTS calendars in backoff';
	for (const cal of OTS_CALENDARS) {
		const baseUrl = cal.url.replace(/\/+$/, '');
		const hostState = guard.hostBackoffs[baseUrl] ?? { backoffUntilMs: 0, lastStatus: null };
		if (hostState.backoffUntilMs > now) continue;
		guard.totalHttpPosts++;
		try {
			const res = await fetchWithTimeout(`${baseUrl}/digest`, {
				method: 'POST',
				headers: {
					Accept: 'application/vnd.opentimestamps.v1',
					'Content-Type': 'application/x-www-form-urlencoded',
					'User-Agent': 'OAKe-CLI/0.1 (batched-merkle-aggregator; max-1req-per-min)'
				},
				body: Buffer.from(calendarDigest32)
			});
			hostState.lastStatus = res.status;
			if (res.status === 200) {
				const responseBytes = Buffer.from(await res.arrayBuffer());
				if (responseBytes.length > 0) {
					const tree = parseTimestampTree(responseBytes, 0, Buffer.from(calendarDigest32), 0, 0);
					guard.lastSubmitMs = now;
					guard.lastCalendarUsed = baseUrl;
					hostState.backoffUntilMs = 0;
					guard.hostBackoffs[baseUrl] = hostState;
					writeJsonSafe(guardPath, guard);
					return {
						ok: true,
						calendarHost: new URL(baseUrl).host,
						commitmentHex: tree.pending?.[0]?.commitmentHex ?? null,
						responseBytes
					};
				}
			}
			hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
			guard.hostBackoffs[baseUrl] = hostState;
			lastError = `HTTP ${res.status} from ${baseUrl}`;
			writeJsonSafe(guardPath, guard);
		} catch (err) {
			hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
			guard.hostBackoffs[baseUrl] = hostState;
			lastError = err instanceof Error ? err.message : String(err);
			writeJsonSafe(guardPath, guard);
		}
	}
	return { ok: false, rateLimited: false, error: lastError };
}

function generateVerifyMarkdown(entry) {
	const btcBlock = entry.ots?.btc_block ?? 'pending';
	const btcRoot = entry.ots?.btc_merkle_root ?? 'pending';
	return `# OAKe Independent Proof Verification Guide

This bundle (\`application/oake-bundle+zip\`) is 100% self-contained.

| Field | Value |
| --- | --- |
| \`entry_id\` | \`${entry.entry_id}\` |
| \`artifact_hash\` | \`${entry.artifact_hash}\` |
| \`canonicalization\` | \`${entry.canonicalization}\` |
| \`user_pubkey\` | \`${entry.user_pubkey}\` |
| \`client_ts\` | \`${entry.client_ts}\` |
| \`ots.status\` | \`${entry.ots?.status}\` |
| \`ots.btc_block\` | \`${btcBlock}\` |
| \`ots.btc_merkle_root\` | \`${btcRoot}\` |

\`\`\`bash
openssl ts -verify -digest ${entry.artifact_hash.replace(/^sha256:/, '')} -in rfc3161/<token>.tsr -CAfile /etc/ssl/cert.pem
ots verify proof.ots
\`\`\`
`;
}

// ============================================================================
// IPC Command Handlers
// ============================================================================

async function handleGetIdentity() {
	const oakeHome = getOakeHome();
	const keyPath = path.join(oakeHome, 'id_ed25519.json');
	if (!fs.existsSync(keyPath)) {
		await runCli(['init']);
	}
	const keyData = readJsonSafe(keyPath, {});
	const guard = readJsonSafe(path.join(oakeHome, 'ots-rate-guard.json'), {});
	const lastSubmitMs = typeof guard.lastSubmitMs === 'number' ? guard.lastSubmitMs : null;
	const cooldownRemainingMs =
		lastSubmitMs !== null ? Math.max(0, OTS_MIN_SUBMIT_INTERVAL_MS - (Date.now() - lastSubmitMs)) : 0;
	const settings = readSettings();

	return {
		pubkey: keyData.pubkey || 'anonymous',
		key_path: keyPath,
		rate_guard: {
			cooldown_remaining_ms: cooldownRemainingMs,
			last_submit_ts: lastSubmitMs !== null ? new Date(lastSubmitMs).toISOString() : null
		},
		auto_snapshot_24h: Boolean(settings.auto_snapshot_24h),
		default_endpoint: settings.default_endpoint
	};
}

async function handleListWorkspaces() {
	const saved = readSavedWorkspaces();
	const results = [];
	for (const item of saved) {
		const wsPath = item.path;
		try {
			const scan = scanWorkspaceInternal(wsPath);
			const trackedCount = scan.files.filter((f) => f.status === 'anchored').length;
			const modifiedOnlyCount = scan.files.filter((f) => f.status === 'modified').length;
			const untrackedCount = scan.files.filter((f) => f.status === 'untracked').length;
			const lastAnchoredTs = scan.history[0]?.client_ts || null;
			results.push({
				path: scan.path,
				name: scan.name,
				exists: true,
				tracked_count: trackedCount,
				anchored_count: trackedCount,
				modified_count: modifiedOnlyCount,
				untracked_count: untrackedCount,
				last_anchored_ts: lastAnchoredTs
			});
		} catch {
			results.push({
				path: wsPath,
				name: path.basename(wsPath) || wsPath,
				exists: false,
				tracked_count: 0,
				anchored_count: 0,
				modified_count: 0,
				untracked_count: 0,
				last_anchored_ts: null,
				missing: true
			});
		}
	}
	return results;
}

async function handleAddWorkspace(args) {
	const rawPath = expandUserPath(args.path);
	if (!rawPath) throw new Error('Workspace folder path is required');
	const resolved = path.resolve(rawPath);
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
		throw new Error(`Directory does not exist: ${rawPath}`);
	}
	const realPath = fs.realpathSync(resolved);
	const saved = readSavedWorkspaces();
	if (!saved.some((w) => w.path === realPath)) {
		saved.push({ path: realPath, added_at: new Date().toISOString() });
		saveWorkspaces(saved);
	}
	return scanWorkspaceInternal(realPath);
}

async function handleRemoveWorkspace(args) {
	const rawPath = expandUserPath(args.path);
	const saved = readSavedWorkspaces().filter((w) => w.path !== rawPath && path.resolve(w.path) !== path.resolve(rawPath));
	saveWorkspaces(saved);
	return { ok: true };
}

async function handleScanWorkspace(args) {
	if (!args.path) throw new Error('workspace path is required');
	return scanWorkspaceInternal(args.path);
}

async function handleAnchorFiles(args) {
	const { workspace_path, relative_paths, canon_override, note, offline } = args;
	if (!workspace_path) throw new Error('workspace_path is required');
	if (!Array.isArray(relative_paths) || relative_paths.length === 0) {
		throw new Error('Select at least one file to anchor');
	}

	const realRoot = fs.realpathSync(path.resolve(expandUserPath(workspace_path)));
	const oakeHome = getOakeHome();
	const keyPath = path.join(oakeHome, 'id_ed25519.json');
	if (!fs.existsSync(keyPath)) {
		await runCli(['init']);
	}

	const cleanNote = typeof note === 'string' && note.trim() ? note.trim() : null;

	// If single file and no note, delegate straight to `cli/oake.mjs capture`
	if (relative_paths.length === 1 && !cleanNote) {
		const rel = relative_paths[0];
		const cliArgs = ['capture', rel, '--dir', realRoot, '--source', 'cli'];
		if (canon_override && CANONICALIZATION_METHODS.includes(canon_override)) {
			cliArgs.push('--canon', canon_override);
		}
		if (offline) cliArgs.push('--offline');
		const { stdout, stderr } = await runCli(cliArgs, realRoot);
		const combined = [stdout, stderr].filter(Boolean).join('\n');
		const rateLimited = /cooldown active/i.test(combined);
		const otsMatch = combined.match(/ots=([a-z]+)/i);
		const scan = scanWorkspaceInternal(realRoot);
		const created = scan.history.slice(0, 1);
		return {
			anchored_count: 1,
			ots_status: otsMatch ? otsMatch[1] : created[0]?.ots_status || 'provisional',
			rate_limited: rateLimited,
			message: stdout || 'Anchored 1 file locally in .oake/',
			entries: created
		};
	}

	// Multi-file Merkle batch (or snapshot note metadata) using identical cli/oake.mjs protocol
	const keyData = readJsonSafe(keyPath, null);
	if (!keyData?.privateKeyPem || !keyData?.pubkey) {
		throw new Error('Ed25519 identity not found. Run oake init first.');
	}

	const oakeDir = path.join(realRoot, '.oake');
	const proofsDir = path.join(oakeDir, 'proofs');
	const indexPath = path.join(oakeDir, 'index.jsonl');
	ensureDir(proofsDir);

	const indexRows = readLocalIndex(indexPath);
	let head =
		indexRows.length === 0
			? { sequence: 0, entry_hash: GENESIS_PREV_HASH }
			: { sequence: indexRows[indexRows.length - 1].sequence, entry_hash: indexRows[indexRows.length - 1].entry_hash };

	const payloads = relative_paths.map((relPath) => {
		const absPath = path.resolve(realRoot, relPath);
		if (!absPath.startsWith(realRoot + path.sep) && absPath !== realRoot) {
			throw new Error(`Invalid relative path outside workspace: ${relPath}`);
		}
		if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
			throw new Error(`File not found: ${relPath}`);
		}
		const canon = inferDefaultCanon(absPath, canon_override);
		const { artifactHash, byteSize } = canonicalizeAndHash(absPath, canon);
		const clientTs = new Date().toISOString();
		const sigPayload = `${artifactHash}|${canon}|${clientTs}`;
		const signature = `ed25519:${crypto.sign(null, Buffer.from(sigPayload, 'utf8'), keyData.privateKeyPem).toString('hex')}`;
		const normalizedRel = path.relative(realRoot, absPath).replace(/\\/g, '/');
		const pathHint = `sha256:${sha256Hex(Buffer.from(normalizedRel, 'utf8'))}`;

		return {
			user_pubkey: keyData.pubkey,
			artifact_hash: artifactHash,
			canonicalization: canon,
			client_ts: clientTs,
			signature,
			capture_source: 'cli',
			metadata: {
				repo: path.basename(realRoot),
				path_hint: pathHint,
				artifact_kind: inferArtifactKind(absPath),
				byte_size: byteSize,
				...(cleanNote ? { note: cleanNote } : {})
			}
		};
	});

	const { rootHash, paths: merklePaths } = buildMerkleBatch(payloads.map((p) => p.artifact_hash));
	const batchNonce16 = crypto.randomBytes(16);
	const batchId = `local-${generateUlid()}`;
	const calendarDigest32 = crypto
		.createHash('sha256')
		.update(Buffer.concat([Buffer.from(rootHash.slice('sha256:'.length), 'hex'), batchNonce16]))
		.digest();

	let otsLiveResult = null;
	let rateLimited = false;
	let noticeMsg = '';
	if (!offline) {
		otsLiveResult = await submitBlindedDigestToCalendars(oakeHome, calendarDigest32);
		if (!otsLiveResult.ok && otsLiveResult.rateLimited) {
			rateLimited = true;
			noticeMsg = `OTS calendar cooldown active (${Math.ceil(otsLiveResult.retryAfterMs / 1000)}s remaining) — stored provisional .ots locally.`;
		} else if (!otsLiveResult.ok) {
			noticeMsg = `OTS calendar unreachable (${otsLiveResult.error}) — stored provisional .ots locally.`;
		}
	}

	const createdEntries = [];
	const notesPath = path.join(oakeDir, 'notes.json');
	const notesMap = readJsonSafe(notesPath, {});

	for (const payload of payloads) {
		const now = new Date();
		const receivedTs = now.toISOString();
		const entryId = generateUlid(now.getTime());

		const tsrResults = offline ? [] : await stampDigestExternalTsas(entryId, payload.artifact_hash);
		const merklePath = merklePaths.get(payload.artifact_hash.toLowerCase()) || [];

		let otsBlob;
		let otsRecord;
		if (otsLiveResult && otsLiveResult.ok) {
			otsBlob = composeLiveCalendarOtsBytes(payload.artifact_hash, merklePath, batchNonce16, otsLiveResult.responseBytes);
			otsRecord = {
				status: 'pending',
				proof_ref: `blob://ots/${entryId}.ots`,
				calendar: otsLiveResult.calendarHost,
				batch_id: otsLiveResult.commitmentHex || batchId,
				btc_block: null,
				btc_block_time: null,
				btc_merkle_root: null,
				upgraded_ts: null
			};
		} else {
			const provisionalUri = `https://alice.btc.calendar.opentimestamps.org/provisional/${batchId}`;
			otsBlob = composeProvisionalOtsBytes(payload.artifact_hash, merklePath, batchNonce16, provisionalUri);
			otsRecord = {
				status: 'provisional',
				proof_ref: `blob://ots/${entryId}.ots`,
				calendar: 'alice.btc.calendar.opentimestamps.org',
				batch_id: batchId,
				btc_block: null,
				btc_block_time: null,
				btc_merkle_root: null,
				upgraded_ts: null
			};
		}

		const sequence = head.sequence + 1;
		const prevEntryHash = head.entry_hash;
		const cleanMetadata = { ...payload.metadata, origin: 'oake-desktop' };
		const entryHash = computeEntryChainHash({
			entry_id: entryId,
			sequence,
			prev_entry_hash: prevEntryHash,
			user_pubkey: payload.user_pubkey,
			artifact_hash: payload.artifact_hash,
			canonicalization: payload.canonicalization,
			signature: payload.signature,
			client_ts: payload.client_ts,
			received_ts: receivedTs,
			capture_source: payload.capture_source,
			metadata: cleanMetadata
		});

		const entry = {
			entry_id: entryId,
			user_pubkey: payload.user_pubkey,
			artifact_hash: payload.artifact_hash,
			canonicalization: payload.canonicalization,
			signature: payload.signature,
			client_ts: payload.client_ts,
			received_ts: receivedTs,
			rfc3161_tokens: tsrResults.map((t) => t.record),
			ots: otsRecord,
			capture_source: payload.capture_source,
			metadata: cleanMetadata,
			chain: { sequence, prev_entry_hash: prevEntryHash, entry_hash: entryHash }
		};

		const zipEntries = [
			{ name: 'entry.json', data: Buffer.from(`${JSON.stringify(entry, null, 2)}\n`, 'utf8') },
			...tsrResults.map((t) => ({ name: `rfc3161/${t.filename}`, data: t.tsrBytes })),
			{ name: 'proof.ots', data: otsBlob },
			{ name: 'VERIFY.md', data: Buffer.from(generateVerifyMarkdown(entry), 'utf8') }
		];
		const bundleAbsPath = path.join(proofsDir, `${entryId}.oake.zip`);
		fs.writeFileSync(bundleAbsPath, writeZipArchive(zipEntries));

		const relBundlePath = path.relative(realRoot, bundleAbsPath).replace(/\\/g, '/');
		const row = {
			sequence,
			prev_entry_hash: prevEntryHash,
			entry_hash: entryHash,
			entry_id: entryId,
			artifact_hash: payload.artifact_hash,
			canonicalization: payload.canonicalization,
			ots_status: otsRecord.status,
			tsa_count: tsrResults.length,
			published_to: null,
			bundle_path: relBundlePath,
			captured_ts: receivedTs
		};
		fs.appendFileSync(indexPath, `${JSON.stringify(row)}\n`, 'utf8');
		if (cleanNote) notesMap[entryId] = cleanNote;
		head = { sequence, entry_hash: entryHash };
		createdEntries.push(entry);
	}

	if (cleanNote) writeJsonSafe(notesPath, notesMap);

	const otsStatus = createdEntries[0]?.ots?.status || 'provisional';
	const defaultMsg = offline
		? `Anchored ${createdEntries.length} file(s) offline into .oake/`
		: `Anchored ${createdEntries.length} file(s) locally (OTS: ${otsStatus})`;

	return {
		anchored_count: createdEntries.length,
		ots_status: otsStatus,
		rate_limited: rateLimited,
		message: noticeMsg || defaultMsg,
		entries: createdEntries
	};
}

async function handleVerifyBundle(args) {
	const rawBundle = expandUserPath(args.bundle_path);
	if (!rawBundle) throw new Error('bundle_path is required');
	let bundleAbs = path.resolve(rawBundle);
	if (args.workspace_path && !fs.existsSync(bundleAbs)) {
		bundleAbs = path.resolve(expandUserPath(args.workspace_path), rawBundle);
	}
	if (!fs.existsSync(bundleAbs) || !fs.statSync(bundleAbs).isFile()) {
		throw new Error(`Proof bundle not found: ${rawBundle}`);
	}

	const rawFile = args.original_file_path ? expandUserPath(args.original_file_path) : '';
	let fileAbs = null;
	if (rawFile) {
		fileAbs = path.resolve(rawFile);
		if (args.workspace_path && !fs.existsSync(fileAbs)) {
			fileAbs = path.resolve(expandUserPath(args.workspace_path), rawFile);
		}
		if (!fs.existsSync(fileAbs) || !fs.statSync(fileAbs).isFile()) {
			throw new Error(`Original file not found: ${rawFile}`);
		}
	}

	const zipBuffer = fs.readFileSync(bundleAbs);
	const zipEntries = readZipEntries(zipBuffer);
	const entryRaw = zipEntries.get('entry.json');
	if (!entryRaw) throw new Error('Invalid .oake.zip bundle: missing entry.json');
	const entry = JSON.parse(entryRaw.toString('utf8'));

	const sigCheck = verifyEd25519Signature(
		entry.user_pubkey,
		entry.signature,
		entry.artifact_hash,
		entry.canonicalization,
		entry.client_ts
	);

	let fileMatches = null;
	if (fileAbs) {
		const { artifactHash } = canonicalizeAndHash(fileAbs, entry.canonicalization || 'raw-bytes/v1');
		fileMatches = artifactHash === entry.artifact_hash;
	}

	const cliArgs = ['verify', bundleAbs, '--offline'];
	if (fileAbs) cliArgs.push('--file', fileAbs);

	// The verdict comes from the exit code only: printed text includes values from the proof.
	let cliOutput = '';
	let cliVerdict = 'VERIFIED';
	try {
		const res = await runCli(cliArgs);
		cliOutput = res.stdout;
	} catch (err) {
		cliVerdict = err.code === 2 ? 'INCOMPLETE' : 'FAILED';
		cliOutput = [err.stdout, err.stderr].filter(Boolean).join('\n').trim() || err.message;
	}

	const digestHex64 = (entry.artifact_hash || '').replace(/^sha256:/i, '');
	const tsrNames = Array.from(zipEntries.keys()).filter((k) => k.startsWith('rfc3161/') && k.endsWith('.tsr')).sort();
	const opensslCommands = tsrNames.map(
		(name) => `openssl ts -verify -digest ${digestHex64} -in ${name} -CAfile /etc/ssl/cert.pem`
	);
	if (opensslCommands.length === 0) {
		opensslCommands.push(`openssl ts -verify -digest ${digestHex64} -in rfc3161/<token>.tsr -CAfile /etc/ssl/cert.pem`);
	}

	const otsBytes = zipEntries.get('proof.ots');
	let otsStatus = entry.ots?.status || 'unknown';
	if (otsBytes && otsBytes.length > OTS_MAGIC.length + 34) {
		const initialDigest = otsBytes.subarray(OTS_MAGIC.length + 2, OTS_MAGIC.length + 34);
		const tree = parseTimestampTree(otsBytes, OTS_MAGIC.length + 34, Buffer.from(initialDigest), 0, 0);
		if (tree.bitcoin?.length > 0) otsStatus = 'upgraded';
	}

	const valid =
		cliVerdict !== 'FAILED' &&
		(!sigCheck.signed || sigCheck.valid) &&
		(fileMatches === null || fileMatches === true);

	const verdict = !valid ? 'failed' : cliVerdict.toLowerCase();

	return {
		valid: verdict === 'verified',
		verdict,
		entry_id: entry.entry_id,
		artifact_hash: entry.artifact_hash,
		canonicalization: entry.canonicalization,
		user_pubkey: entry.user_pubkey,
		client_ts: entry.client_ts,
		signature_valid: sigCheck.valid,
		signature_signed: sigCheck.signed,
		file_matches: fileMatches,
		ots_status: otsStatus,
		ots_calendar: entry.ots?.calendar || null,
		btc_block: entry.ots?.btc_block ?? null,
		tsa_count: Array.isArray(entry.rfc3161_tokens) ? entry.rfc3161_tokens.length : tsrNames.length,
		tokens: (entry.rfc3161_tokens || []).map((t) => ({
			tsa: t.tsa,
			label: formatTsaLabel(t.tsa),
			gen_time: t.gen_time,
			serial_number: t.serial_number,
			token_ref: t.token_ref
		})),
		commands: {
			openssl: opensslCommands,
			ots: 'ots verify proof.ots'
		},
		details: cliOutput || (valid ? 'Cryptographic bundle verification passed.' : 'Bundle verification failed.')
	};
}

async function handlePushWorkspace(args) {
	const workspacePath = expandUserPath(args.workspace_path);
	if (!workspacePath) throw new Error('workspace_path is required');
	const endpoint = (args.endpoint || readSettings().default_endpoint || 'http://127.0.0.1:3000').replace(/\/+$/, '');
	const realRoot = fs.realpathSync(path.resolve(workspacePath));

	const { stdout, stderr } = await runCli(['push', '--dir', realRoot, '--endpoint', endpoint], realRoot);
	const output = [stdout, stderr].filter(Boolean).join('\n');
	const pushedLines = output.split('\n').filter((l) => l.startsWith('Pushed '));
	let deduplicatedCount = 0;
	for (const line of pushedLines) {
		if (/deduplicated=true/i.test(line)) deduplicatedCount++;
	}

	return {
		pushed_count: pushedLines.length,
		deduplicated_count: deduplicatedCount,
		endpoint,
		message: output || `Pushed ${pushedLines.length} bundle(s) to ${endpoint}`
	};
}

async function handleUpgradeWorkspace(args) {
	const workspacePath = expandUserPath(args.workspace_path);
	if (!workspacePath) throw new Error('workspace_path is required');
	const realRoot = fs.realpathSync(path.resolve(workspacePath));
	const { stdout, stderr } = await runCli(['upgrade', '--dir', realRoot], realRoot);
	const output = [stdout, stderr].filter(Boolean).join('\n');
	const lines = output.split('\n').filter(Boolean);
	const upgradedCount = lines.filter((l) => l.startsWith('Upgraded ')).length;
	const submittedCount = lines.filter((l) => l.startsWith('Submitted ')).length;
	const rateLimited = /cooldown active/i.test(output);
	return {
		ok: true,
		upgraded_count: upgradedCount,
		submitted_count: submittedCount,
		rate_limited: rateLimited,
		message: output || 'OTS upgrade check completed.'
	};
}

async function handleSetAutoSnapshot(args) {
	const settings = readSettings();
	if (typeof args.enabled === 'boolean') settings.auto_snapshot_24h = args.enabled;
	if (typeof args.default_endpoint === 'string' && args.default_endpoint.trim()) {
		settings.default_endpoint = args.default_endpoint.trim().replace(/\/+$/, '');
	}
	writeJsonSafe(getSettingsFile(), settings);
	return settings;
}

async function handleBrowseDirectory(args) {
	const raw = args.path ? expandUserPath(args.path) : os.homedir();
	const resolved = path.resolve(raw);
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
		throw new Error(`Directory not found: ${raw}`);
	}
	const entries = fs.readdirSync(resolved, { withFileTypes: true });
	const dirs = entries
		.filter((e) => e.isDirectory() && !e.name.startsWith('.'))
		.map((e) => ({ name: e.name, path: path.join(resolved, e.name), has_oake: fs.existsSync(path.join(resolved, e.name, '.oake')) }))
		.sort((a, b) => a.name.localeCompare(b.name));
	const parent = path.dirname(resolved);
	return {
		current: resolved,
		parent: parent !== resolved ? parent : null,
		has_oake: fs.existsSync(path.join(resolved, '.oake')),
		directories: dirs
	};
}

const COMMAND_MAP = {
	get_identity: handleGetIdentity,
	list_workspaces: handleListWorkspaces,
	add_workspace: handleAddWorkspace,
	remove_workspace: handleRemoveWorkspace,
	scan_workspace: handleScanWorkspace,
	anchor_files: handleAnchorFiles,
	verify_bundle: handleVerifyBundle,
	push_workspace: handlePushWorkspace,
	upgrade_workspace: handleUpgradeWorkspace,
	set_auto_snapshot: handleSetAutoSnapshot,
	browse_directory: handleBrowseDirectory
};

// ============================================================================
// HTTP Server
// ============================================================================

async function readJsonBody(req) {
	const chunks = [];
	for await (const chunk of req) {
		chunks.push(chunk);
	}
	const raw = Buffer.concat(chunks).toString('utf8').trim();
	if (!raw) return {};
	return JSON.parse(raw);
}

function sendJson(res, status, data) {
	const body = Buffer.from(`${JSON.stringify(data)}\n`, 'utf8');
	res.writeHead(status, {
		'Content-Type': 'application/json; charset=utf-8',
		'Content-Length': body.length,
		'Cache-Control': 'no-store'
	});
	res.end(body);
}

function serveStatic(reqPath, res) {
	const cleanPath = reqPath === '/' ? '/index.html' : reqPath.split('?')[0];
	const resolved = path.resolve(UI_DIR, `.${cleanPath}`);
	if (!resolved.startsWith(UI_DIR + path.sep) && resolved !== path.join(UI_DIR, 'index.html')) {
		res.writeHead(403);
		res.end('Forbidden');
		return;
	}
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
		res.writeHead(404);
		res.end('Not found');
		return;
	}
	const ext = path.extname(resolved).toLowerCase();
	const content = fs.readFileSync(resolved);
	res.writeHead(200, {
		'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
		'Content-Length': content.length,
		'Cache-Control': 'no-store'
	});
	res.end(content);
}

// This server can read and sign local files, so it only answers its own page.
const ALLOWED_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);

function rejectReason(req, isApi) {
	// A foreign Host header means another domain was pointed at this machine.
	if (!ALLOWED_HOSTS.has(req.headers.host)) return [403, 'Host not allowed'];
	if (!isApi) return null;
	const origin = req.headers.origin;
	if (origin && origin !== `http://${req.headers.host}`) return [403, 'Origin not allowed'];
	if (req.method !== 'POST') return [405, 'Use POST'];
	// Other sites cannot send this content type without a preflight, which fails here.
	if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return [415, 'Use application/json'];
	return null;
}

const server = http.createServer(async (req, res) => {
	const rejected = rejectReason(req, (req.url || '').includes('/api/'));
	if (rejected) {
		sendJson(res, rejected[0], { error: rejected[1] });
		return;
	}
	const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);

	if (url.pathname.startsWith('/api/')) {
		const cmd = decodeURIComponent(url.pathname.slice('/api/'.length));
		const handler = COMMAND_MAP[cmd];
		if (!handler) {
			sendJson(res, 404, { error: `Unknown IPC command: ${cmd}` });
			return;
		}
		try {
			const args = await readJsonBody(req);
			const result = await handler(args);
			sendJson(res, 200, result);
		} catch (err) {
			sendJson(res, 400, { error: err instanceof Error ? err.message : String(err) });
		}
		return;
	}

	serveStatic(url.pathname, res);
});

server.listen(PORT, HOST, () => {
	console.log(`OAKe Desktop dev bridge running at http://${HOST}:${PORT}`);
	console.log(`Serving UI from ${UI_DIR}`);
	console.log(`OAKE_HOME=${getOakeHome()}`);
});

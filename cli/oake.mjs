#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

const OAKE_PROTOCOL_VERSION = 'OAKe-v0.1';
const GENESIS_PREV_HASH =
	'sha256:0000000000000000000000000000000000000000000000000000000000000000';
const CANONICALIZATION_METHODS = ['raw-bytes/v1', 'text-normalized/v1', 'ipynb-cells/v1'];
const CAPTURE_SOURCES = ['git-hook', 'jupyter', 'overleaf', 'editor', 'manual', 'cli'];
const SKIP_DIRS = new Set(['.git', 'node_modules', '.oake']);
const SKIP_EXTS = new Set(['.log', '.aux', '.pdf']);
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
const MAX_OTS_OPERAND_LENGTH = 4096;
const MAX_OTS_TREE_DEPTH = 256;

const SHA256_OID_BYTES = Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

const PRIMARY_TSAS = [
	{ tsa: 'certum-eu', url: 'http://time.certum.pl', jurisdiction: 'EU / Poland (Asseco Certum eIDAS QTSA)' }
];
const SECONDARY_TSA_PRIMARY = {
	tsa: 'digicert-us',
	url: 'http://timestamp.digicert.com',
	jurisdiction: 'US / WebTrust (DigiCert Assured ID TSA)'
};
const SECONDARY_TSA_FAILOVER = {
	tsa: 'sectigo-uk',
	url: 'http://timestamp.sectigo.com',
	jurisdiction: 'UK / WebTrust (Sectigo Qualified TSA)'
};

const OTS_CALENDARS = [
	{ url: 'https://alice.btc.calendar.opentimestamps.org', label: 'Alice (OpenTimestamps)' },
	{ url: 'https://finney.calendar.eternitywall.com', label: 'Finney (Eternity Wall)' },
	{ url: 'https://bob.btc.calendar.opentimestamps.org', label: 'Bob (OpenTimestamps)' }
];

const OTS_MIN_SUBMIT_INTERVAL_MS = 60_000;
const OTS_MIN_POLL_INTERVAL_MS = 300_000;
const OTS_CIRCUIT_BREAKER_MS = 600_000;
const HTTP_TIMEOUT_MS = 6_000;

const USER_AGENT_TSA = 'OAKe-CLI/0.1 (standalone-rfc3161-client)';
const USER_AGENT_OTS_SUBMIT = 'OAKe-CLI/0.1 (batched-merkle-aggregator; max-1req-per-min)';
const USER_AGENT_OTS_POLL = 'OAKe-CLI/0.1 (batched-merkle-aggregator; max-1req-per-5min)';

let lastUlidTimestampMs = -1;
const lastUlidRandom = new Uint8Array(10);

function getOakeHome() {
	return process.env.OAKE_HOME || path.join(os.homedir(), '.config', 'oake');
}

function getKeyFilePath(oakeHome) {
	return path.join(oakeHome, 'id_ed25519.json');
}

function getConfigFilePath(oakeHome) {
	return path.join(oakeHome, 'config.yaml');
}

function getOtsRateGuardPath(oakeHome) {
	return path.join(oakeHome, 'ots-rate-guard.json');
}

function readEndpointFromConfig(configPath) {
	if (!fs.existsSync(configPath)) return null;
	try {
		const raw = fs.readFileSync(configPath, 'utf8');
		const match = raw.match(/^\s*endpoint:\s*([^\s#]+)/m);
		return match ? match[1].replace(/^['"]|['"]$/g, '') : null;
	} catch {
		return null;
	}
}

function resolveEndpoint(flagEndpoint, oakeHome) {
	return (
		flagEndpoint ||
		process.env.OAKE_ENDPOINT ||
		readEndpointFromConfig(getConfigFilePath(oakeHome)) ||
		'http://localhost:3000'
	).replace(/\/+$/, '');
}

function ensureDir(dirPath) {
	fs.mkdirSync(dirPath, { recursive: true });
}

function findMarkerUpwards(startDir, markerName) {
	let current = path.resolve(startDir);
	while (true) {
		if (fs.existsSync(path.join(current, markerName))) {
			return current;
		}
		const parent = path.dirname(current);
		if (parent === current) {
			return null;
		}
		current = parent;
	}
}

function resolveProjectRoot(explicitDir) {
	if (explicitDir) {
		return path.resolve(explicitDir);
	}
	const cwd = process.cwd();
	return findMarkerUpwards(cwd, '.oake') || findMarkerUpwards(cwd, '.git') || cwd;
}

function getLocalRepoPaths(projectRoot) {
	const oakeDir = path.join(projectRoot, '.oake');
	const proofsDir = path.join(oakeDir, 'proofs');
	const indexPath = path.join(oakeDir, 'index.jsonl');
	return { oakeDir, proofsDir, indexPath };
}

function generateIdentity(oakeHome, force = false) {
	ensureDir(oakeHome);
	const keyPath = getKeyFilePath(oakeHome);
	const configPath = getConfigFilePath(oakeHome);

	let keyData;
	if (fs.existsSync(keyPath) && !force) {
		keyData = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
	} else {
		const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
		const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
		const rawPub = spkiDer.subarray(spkiDer.length - 32);
		const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

		keyData = {
			pubkey: `ed25519:${rawPub.toString('hex')}`,
			privateKeyPem,
			createdAt: new Date().toISOString()
		};
		fs.writeFileSync(keyPath, JSON.stringify(keyData, null, 2) + '\n', { mode: 0o600 });
		fs.chmodSync(keyPath, 0o600);
	}

	if (!fs.existsSync(configPath) || force) {
		const sampleConfig = `# ~/.config/oake/config.yaml — OAKe Provenance Micro-Utility
identity:
  keyfile: ${keyPath}
service:
  endpoint: http://localhost:3000
capture:
  git_hook: true
  snapshot_interval: 24h
  watch:
    - { path: ~/research, kind: latex, canon: raw-bytes/v1 }
    - { path: ~/notebooks, kind: notebook, canon: ipynb-cells/v1 }
  ignore: [ "*.log", "*.aux", "*.pdf", ".git/**", "**/node_modules/**" ]
privacy:
  hash_paths: true
`;
		fs.writeFileSync(configPath, sampleConfig, 'utf8');
	}

	return { keyData, keyPath, configPath };
}

function loadOrCreateIdentity(oakeHome) {
	const keyPath = getKeyFilePath(oakeHome);
	if (fs.existsSync(keyPath)) {
		return JSON.parse(fs.readFileSync(keyPath, 'utf8'));
	}
	return generateIdentity(oakeHome, false).keyData;
}

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
	if (!Number.isFinite(ts) || ts < 0 || ts > 0xffffffffffff) {
		throw new Error(`Invalid ULID timestamp: ${String(nowMs)}`);
	}

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
		const parts = value.map((item) => {
			const ser = serializeCanonicalJson(item);
			return ser === undefined ? 'null' : ser;
		});
		return `[${parts.join(',')}]`;
	}
	const keys = Object.keys(value).sort();
	const parts = [];
	for (const key of keys) {
		const ser = serializeCanonicalJson(value[key]);
		if (ser !== undefined) {
			parts.push(`${JSON.stringify(key)}:${ser}`);
		}
	}
	return `{${parts.join(',')}}`;
}

function computeEntryChainHash(entryCore) {
	const canonical = serializeCanonicalJson(entryCore) ?? 'null';
	return `sha256:${sha256Hex(Buffer.from(canonical, 'utf8'))}`;
}

function formatSigningPayload(artifactHash, canonicalization, clientTs) {
	return `${artifactHash}|${canonicalization}|${clientTs}`;
}

function signDigest(keyData, artifactHash, canonicalization, clientTs) {
	const payload = formatSigningPayload(artifactHash, canonicalization, clientTs);
	const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), keyData.privateKeyPem);
	return `ed25519:${sig.toString('hex')}`;
}

function verifyEd25519Signature(userPubkey, signature, artifactHash, canonicalization, clientTs) {
	if (userPubkey === 'anonymous') {
		return { signed: false, valid: true };
	}
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
	const payload = Buffer.from(formatSigningPayload(artifactHash, canonicalization, clientTs), 'utf8');
	const valid = crypto.verify(null, payload, pubKeyObj, sigBytes);
	return { signed: true, valid };
}

function sha256Hex(buffer) {
	return crypto.createHash('sha256').update(buffer).digest('hex');
}

function canonicalizeAndHash(filePath, canonMethod) {
	const rawBytes = fs.readFileSync(filePath);

	if (canonMethod === 'raw-bytes/v1') {
		return {
			artifactHash: `sha256:${sha256Hex(rawBytes)}`,
			byteSize: rawBytes.byteLength
		};
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
		let parsed;
		try {
			parsed = JSON.parse(rawBytes.toString('utf8'));
		} catch (err) {
			throw new Error(`Invalid .ipynb JSON in ${filePath}: ${err.message}`);
		}
		const cells = Array.isArray(parsed?.cells) ? parsed.cells : [];
		const cellDigests = cells.map((cell) => {
			const cellType = typeof cell?.cell_type === 'string' ? cell.cell_type : 'unknown';
			const sourceText = Array.isArray(cell?.source)
				? cell.source.join('')
				: typeof cell?.source === 'string'
					? cell.source
					: '';
			return crypto
				.createHash('sha256')
				.update(`${cellType}\n${sourceText}`, 'utf8')
				.digest();
		});
		const combined = Buffer.concat(cellDigests);
		return {
			artifactHash: `sha256:${sha256Hex(combined)}`,
			byteSize: rawBytes.byteLength
		};
	}

	throw new Error(
		`Unsupported canonicalization method "${canonMethod}". Allowed: ${CANONICALIZATION_METHODS.join(', ')}`
	);
}

function inferDefaultCanon(filePath, explicitCanon) {
	if (explicitCanon) {
		if (!CANONICALIZATION_METHODS.includes(explicitCanon)) {
			throw new Error(
				`Invalid --canon "${explicitCanon}". Allowed: ${CANONICALIZATION_METHODS.join(', ')}`
			);
		}
		return explicitCanon;
	}
	return path.extname(filePath).toLowerCase() === '.ipynb' ? 'ipynb-cells/v1' : 'raw-bytes/v1';
}

function inferArtifactKind(filePath) {
	const ext = path.extname(filePath).toLowerCase();
	if (ext === '.tex' || ext === '.bib') return 'latex';
	if (ext === '.ipynb') return 'notebook';
	if (['.py', '.ts', '.tsx', '.js', '.mjs', '.rs', '.go', '.c', '.cpp'].includes(ext)) {
		return 'code';
	}
	if (ext === '.md' || ext === '.txt') return 'text';
	if (ext === '.csv' || ext === '.json' || ext === '.parquet') return 'dataset';
	return 'file';
}

function collectTargetFiles(targetPath) {
	const resolved = path.resolve(targetPath);
	if (!fs.existsSync(resolved)) {
		throw new Error(`Path does not exist: ${targetPath}`);
	}
	const stat = fs.statSync(resolved);
	if (stat.isFile()) {
		return [resolved];
	}
	if (!stat.isDirectory()) {
		throw new Error(`Unsupported file type: ${targetPath}`);
	}

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
	walk(resolved);
	return collected;
}

// ============================================================================
// PKZIP Writer & Reader (pure Node.js node:zlib)
// ============================================================================

function sanitizeZipPath(name) {
	const normalized = name.replace(/\\/g, '/').replace(/^\/+/, '');
	if (!normalized || normalized.includes('\0')) {
		throw new Error(`Invalid ZIP entry name: ${JSON.stringify(name)}`);
	}
	const segments = normalized.split('/');
	if (segments.some((seg) => seg === '..' || seg === '.')) {
		throw new Error(`Unsafe ZIP path traversal in entry name: ${name}`);
	}
	return normalized;
}

function dateToDos(date) {
	const year = Math.max(1980, date.getUTCFullYear());
	const month = date.getUTCMonth() + 1;
	const day = date.getUTCDate();
	const hours = date.getUTCHours();
	const minutes = date.getUTCMinutes();
	const seconds = Math.floor(date.getUTCSeconds() / 2);
	const dosTime = ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | (seconds & 0x1f);
	const dosDate = (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f);
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
		cdh.writeUInt16LE(0, 30);
		cdh.writeUInt16LE(0, 32);
		cdh.writeUInt16LE(0, 34);
		cdh.writeUInt16LE(0, 36);
		cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38);
		cdh.writeUInt32LE(offset, 42);
		centralChunks.push(cdh, nameBuf);

		offset += lfh.length + nameBuf.length + payload.length;
	}

	const centralDir = Buffer.concat(centralChunks);
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(centralDir.length, 12);
	eocd.writeUInt32LE(offset, 16);
	eocd.writeUInt16LE(0, 20);

	return Buffer.concat([...localChunks, centralDir, eocd]);
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
		throw new Error('Invalid ZIP archive: End of Central Directory not found');
	}

	const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
	const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);

	const files = new Map();
	let pos = cdOffset;
	for (let i = 0; i < totalEntries; i++) {
		if (pos + 46 > zipBuffer.length || zipBuffer.readUInt32LE(pos) !== 0x02014b50) {
			throw new Error('Invalid ZIP archive: corrupt Central Directory entry');
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

		if (
			localHeaderOffset + 30 > zipBuffer.length ||
			zipBuffer.readUInt32LE(localHeaderOffset) !== 0x04034b50
		) {
			throw new Error(`Invalid ZIP archive: bad local header for ${filename}`);
		}
		const localFnLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
		const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
		const dataStart = localHeaderOffset + 30 + localFnLen + localExtraLen;
		const compressedData = zipBuffer.subarray(dataStart, dataStart + compressedSize);

		let content;
		if (method === 0) {
			content = compressedData;
		} else if (method === 8) {
			content = zlib.inflateRawSync(compressedData);
		} else {
			throw new Error(`Unsupported ZIP compression method ${method} for ${filename}`);
		}

		files.set(filename, content);
		pos += 46 + fnLen + extraLen + commentLen;
	}

	return files;
}

// ============================================================================
// ASN.1 DER & Direct RFC 3161 External TSA Client
// ============================================================================

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
	const lenBytes = Buffer.from(encodeDerLength(valBuf.length));
	return Buffer.concat([Buffer.from([tag]), lenBytes, valBuf]);
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
	if (offset >= bytes.length) {
		throw new Error(`Unexpected end of DER input at offset ${offset}`);
	}
	const tag = bytes[offset];
	if (offset + 1 >= bytes.length) {
		throw new Error(`Truncated DER length at offset ${offset + 1}`);
	}
	const firstLenByte = bytes[offset + 1];
	let len = 0;
	let valueStart = offset + 2;
	if ((firstLenByte & 0x80) === 0) {
		len = firstLenByte;
	} else {
		const numLenBytes = firstLenByte & 0x7f;
		if (numLenBytes === 0 || numLenBytes > 4 || offset + 2 + numLenBytes > bytes.length) {
			throw new Error(`Invalid DER length encoding at offset ${offset + 1}`);
		}
		for (let i = 0; i < numLenBytes; i++) {
			len = (len << 8) | bytes[offset + 2 + i];
		}
		valueStart = offset + 2 + numLenBytes;
	}
	const nextOffset = valueStart + len;
	if (nextOffset > bytes.length) {
		throw new Error(`DER value extends beyond buffer`);
	}
	return { tag, value: bytes.subarray(valueStart, nextOffset), nextOffset };
}

function decodeDerOid(bytes) {
	if (!bytes.length) return '';
	const first = bytes[0];
	const parts = [Math.floor(first / 40), first % 40];
	let val = 0;
	for (let i = 1; i < bytes.length; i++) {
		val = (val << 7) | (bytes[i] & 0x7f);
		if ((bytes[i] & 0x80) === 0) {
			parts.push(val);
			val = 0;
		}
	}
	return parts.join('.');
}

function parseAsn1Time(tag, bytes) {
	const raw = Buffer.from(bytes).toString('ascii');
	if (tag === 0x18) {
		// GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z
		const m = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/);
		if (m) {
			const ms = m[7] ? m[7].slice(0, 4).padEnd(4, '0') : '.000';
			return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${ms}Z`;
		}
	} else if (tag === 0x17) {
		// UTCTime: YYMMDDHHMMSSZ
		const m = raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
		if (m) {
			const yy = Number(m[1]);
			const yyyy = yy >= 50 ? 1900 + yy : 2000 + yy;
			return `${yyyy}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.000Z`;
		}
	}
	return null;
}

function parseRfc3161TimeStampResp(derBytes, expectedDigest32) {
	const root = readDerTlv(derBytes, 0);
	if (root.tag !== 0x30) {
		throw new Error('TimeStampResp is not a DER SEQUENCE');
	}
	const statusInfo = readDerTlv(root.value, 0);
	if (statusInfo.tag !== 0x30) {
		throw new Error('TimeStampResp missing PKIStatusInfo SEQUENCE');
	}
	const statusVal = readDerTlv(statusInfo.value, 0);
	if (statusVal.tag !== 0x02 || statusVal.value.length === 0) {
		throw new Error('PKIStatusInfo missing status INTEGER');
	}
	const pkiStatus = statusVal.value[statusVal.value.length - 1];
	if (pkiStatus !== 0 && pkiStatus !== 1) {
		throw new Error(`TSA rejected timestamp request (PKIStatus=${pkiStatus})`);
	}
	if (statusInfo.nextOffset >= root.value.length) {
		throw new Error('TimeStampResp missing timeStampToken');
	}

	const fallbackIso = new Date().toISOString();
	let genTime = fallbackIso;
	let serialNumber = crypto.randomBytes(12).toString('hex').toUpperCase();
	let policyOid;
	let certNotAfter = new Date(Date.now() + 365 * 86_400_000).toISOString();

	try {
		const tokenInfo = readDerTlv(root.value, statusInfo.nextOffset); // ContentInfo
		const contentType = readDerTlv(tokenInfo.value, 0);
		const contentWrap = readDerTlv(tokenInfo.value, contentType.nextOffset); // [0]
		const signedData = readDerTlv(contentWrap.value, 0); // SEQUENCE
		const sdVer = readDerTlv(signedData.value, 0);
		const digestAlgs = readDerTlv(signedData.value, sdVer.nextOffset);
		const encapContent = readDerTlv(signedData.value, digestAlgs.nextOffset);
		const eContentType = readDerTlv(encapContent.value, 0);
		if (eContentType.nextOffset < encapContent.value.length) {
			const eContentWrap = readDerTlv(encapContent.value, eContentType.nextOffset);
			const eContentOctet = readDerTlv(eContentWrap.value, 0);
			const tstInfo = readDerTlv(eContentOctet.value, 0);
			const tstVer = readDerTlv(tstInfo.value, 0);
			const policyTlv = readDerTlv(tstInfo.value, tstVer.nextOffset);
			if (policyTlv.tag === 0x06) {
				policyOid = decodeDerOid(policyTlv.value);
			}
			const imprintTlv = readDerTlv(tstInfo.value, policyTlv.nextOffset);
			const algTlv = readDerTlv(imprintTlv.value, 0);
			const hashedMsgTlv = readDerTlv(imprintTlv.value, algTlv.nextOffset);
			if (
				hashedMsgTlv.tag === 0x04 &&
				!Buffer.from(hashedMsgTlv.value).equals(Buffer.from(expectedDigest32))
			) {
				throw new Error('TSA response digest mismatch');
			}
			const serialTlv = readDerTlv(tstInfo.value, imprintTlv.nextOffset);
			if (serialTlv.tag === 0x02 && serialTlv.value.length > 0) {
				serialNumber = Buffer.from(serialTlv.value).toString('hex').toUpperCase();
			}
			const genTimeTlv = readDerTlv(tstInfo.value, serialTlv.nextOffset);
			const parsedGen = parseAsn1Time(genTimeTlv.tag, genTimeTlv.value);
			if (parsedGen) {
				genTime = parsedGen;
			}
		}

		// Scan optional [0] certificates to extract leaf/signer notAfter if present
		if (encapContent.nextOffset < signedData.value.length) {
			const nextTlv = readDerTlv(signedData.value, encapContent.nextOffset);
			if (nextTlv.tag === 0xa0) {
				const certTlv = readDerTlv(nextTlv.value, 0);
				if (certTlv.tag === 0x30) {
					const tbs = readDerTlv(certTlv.value, 0);
					let p = 0;
					let cur = readDerTlv(tbs.value, p);
					if (cur.tag === 0xa0) {
						p = cur.nextOffset;
						cur = readDerTlv(tbs.value, p); // serialNumber
					}
					const sigAlg = readDerTlv(tbs.value, cur.nextOffset);
					const issuer = readDerTlv(tbs.value, sigAlg.nextOffset);
					const validity = readDerTlv(tbs.value, issuer.nextOffset);
					if (validity.tag === 0x30) {
						const notBefore = readDerTlv(validity.value, 0);
						const notAfter = readDerTlv(validity.value, notBefore.nextOffset);
						const parsedNotAfter = parseAsn1Time(notAfter.tag, notAfter.value);
						if (parsedNotAfter) {
							certNotAfter = parsedNotAfter;
						}
					}
				}
			}
		}
	} catch (err) {
		if (err instanceof Error && err.message.includes('digest mismatch')) {
			throw err;
		}
	}

	return { genTime, serialNumber, certNotAfter, policyOid };
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
			'User-Agent': USER_AGENT_TSA
		},
		body: reqDer
	});
	if (!res.ok) {
		throw new Error(`TSA ${tsaDesc.tsa} HTTP ${res.status}`);
	}
	const respBuf = Buffer.from(await res.arrayBuffer());
	if (respBuf.length < 16 || respBuf[0] !== 0x30) {
		throw new Error(`TSA ${tsaDesc.tsa} returned invalid DER response`);
	}
	const parsed = parseRfc3161TimeStampResp(respBuf, digest32);
	const filename = `${entryId}-${tsaDesc.tsa}.tsr`;
	const record = {
		tsa: tsaDesc.tsa,
		token_ref: `blob://tsr/${filename}`,
		gen_time: parsed.genTime,
		serial_number: parsed.serialNumber,
		cert_not_after: parsed.certNotAfter,
		restamped_from: null,
		format: 'rfc3161-cms-der',
		signer_subject: tsaDesc.jurisdiction,
		...(parsed.policyOid ? { policy_oid: parsed.policyOid } : {})
	};
	return { record, filename, tsrBytes: respBuf };
}

async function stampDigestExternalTsas(entryId, artifactHash) {
	const digest32 = Buffer.from(artifactHash.slice('sha256:'.length), 'hex');
	const results = [];
	const errors = [];

	const primaryPromise = Promise.allSettled(
		PRIMARY_TSAS.map((tsaDesc) => requestExternalRfc3161Token(tsaDesc, digest32, entryId))
	);

	const secondaryPromise = (async () => {
		try {
			return await requestExternalRfc3161Token(SECONDARY_TSA_PRIMARY, digest32, entryId);
		} catch (err1) {
			try {
				return await requestExternalRfc3161Token(SECONDARY_TSA_FAILOVER, digest32, entryId);
			} catch (err2) {
				throw new Error(
					`${SECONDARY_TSA_PRIMARY.tsa}: ${err1 instanceof Error ? err1.message : String(err1)}; ` +
						`${SECONDARY_TSA_FAILOVER.tsa}: ${err2 instanceof Error ? err2.message : String(err2)}`
				);
			}
		}
	})();

	const [primarySettled, secondarySettled] = await Promise.all([
		primaryPromise,
		Promise.allSettled([secondaryPromise])
	]);

	for (const r of [...primarySettled, ...secondarySettled]) {
		if (r.status === 'fulfilled') {
			results.push(r.value);
		} else {
			errors.push(r.reason instanceof Error ? r.reason.message : String(r.reason));
		}
	}

	return { tokens: results, errors };
}

// ============================================================================
// OpenTimestamps Binary Format, Local Merkle Batch & Polite Alice Client
// ============================================================================

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

function readVarUint(buf, state) {
	let result = 0;
	let shift = 0;
	while (state.offset < buf.length) {
		const byte = buf[state.offset++];
		result |= (byte & 0x7f) << shift;
		if ((byte & 0x80) === 0) return result;
		shift += 7;
	}
	throw new Error('Unexpected EOF reading OTS varint');
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

function buildMerkleBatch(leafHashes) {
	const uniqueSet = new Set(leafHashes.map((h) => h.trim().toLowerCase()));
	const sortedLeaves = Array.from(uniqueSet).sort();
	const paths = new Map();
	for (const leaf of sortedLeaves) {
		paths.set(leaf, []);
	}

	let level = sortedLeaves.map((leaf) => ({
		hashBuf: Buffer.from(leaf.slice('sha256:'.length), 'hex'),
		members: [leaf]
	}));

	if (level.length === 1) {
		const only = level[0];
		const siblingHex = only.hashBuf.toString('hex');
		paths.get(only.members[0]).push({ position: 'right', siblingHex });
		const rootBuf = crypto
			.createHash('sha256')
			.update(Buffer.concat([only.hashBuf, only.hashBuf]))
			.digest();
		return { rootHash: `sha256:${rootBuf.toString('hex')}`, paths };
	}

	while (level.length > 1) {
		const nextLevel = [];
		for (let i = 0; i < level.length; i += 2) {
			const left = level[i];
			const hasRight = i + 1 < level.length;
			const right = hasRight ? level[i + 1] : level[i];
			const leftHex = left.hashBuf.toString('hex');
			const rightHex = right.hashBuf.toString('hex');

			if (hasRight) {
				for (const m of left.members) paths.get(m).push({ position: 'right', siblingHex: rightHex });
				for (const m of right.members) paths.get(m).push({ position: 'left', siblingHex: leftHex });
				nextLevel.push({
					hashBuf: crypto.createHash('sha256').update(Buffer.concat([left.hashBuf, right.hashBuf])).digest(),
					members: [...left.members, ...right.members]
				});
			} else {
				for (const m of left.members) paths.get(m).push({ position: 'right', siblingHex: leftHex });
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
		const op = step.position === 'right' ? OP_APPEND : OP_PREPEND;
		chunks.push(Buffer.from([op, 0x20]), Buffer.from(step.siblingHex, 'hex'), Buffer.from([OP_SHA256]));
	}
	chunks.push(Buffer.from([OP_APPEND, 0x10]), Buffer.from(batchNonce16), Buffer.from([OP_SHA256]));
	return Buffer.concat(chunks);
}

function composeProvisionalOtsBytes(artifactHash, merklePath, batchNonce16, calendarUri) {
	const prefix = buildMerkleAndNonceOps(artifactHash, merklePath, batchNonce16);
	const uriBytes = Buffer.from(calendarUri, 'utf8');
	const payload = Buffer.concat([encodeVarint(uriBytes.length), uriBytes]);
	return Buffer.concat([
		prefix,
		Buffer.from([OP_ATTESTATION]),
		TAG_PENDING_ATTESTATION,
		encodeVarint(payload.length),
		payload
	]);
}

function composeLiveCalendarOtsBytes(artifactHash, merklePath, batchNonce16, calendarResponseBytes) {
	const prefix = buildMerkleAndNonceOps(artifactHash, merklePath, batchNonce16);
	return Buffer.concat([prefix, Buffer.from(calendarResponseBytes)]);
}

function parseSingleBranch(buf, offset, current, merkleSteps, depth) {
	if (depth > MAX_OTS_TREE_DEPTH || offset >= buf.length) {
		return { nextOffset: offset, pending: [], bitcoin: [], error: 'OTS proof truncated or too deep' };
	}
	const op = buf[offset++];
	if (op === OP_FORK) {
		return parseTimestampTree(buf, offset - 1, current, merkleSteps, depth + 1);
	}
	if (op === OP_APPEND || op === OP_PREPEND) {
		const lenVar = decodeVarintSafe(buf, offset);
		if (!lenVar || lenVar.value < 1 || lenVar.value > MAX_OTS_OPERAND_LENGTH) {
			return { nextOffset: offset, pending: [], bitcoin: [], error: 'Invalid OTS operand length' };
		}
		offset = lenVar.nextOffset;
		if (offset + lenVar.value > buf.length) {
			return { nextOffset: offset, pending: [], bitcoin: [], error: 'Truncated OTS operand' };
		}
		const operand = buf.subarray(offset, offset + lenVar.value);
		offset += lenVar.value;
		const nextCurrent =
			op === OP_APPEND ? Buffer.concat([current, operand]) : Buffer.concat([operand, current]);
		return parseTimestampTree(buf, offset, nextCurrent, merkleSteps + 1, depth + 1);
	}
	if (op === OP_SHA256) {
		const nextCurrent = crypto.createHash('sha256').update(current).digest();
		return parseTimestampTree(buf, offset, nextCurrent, merkleSteps + 1, depth + 1);
	}
	if (op === OP_SHA1) {
		const nextCurrent = crypto.createHash('sha1').update(current).digest();
		return parseTimestampTree(buf, offset, nextCurrent, merkleSteps, depth + 1);
	}
	if (op === OP_RIPEMD160) {
		const nextCurrent = crypto.createHash('ripemd160').update(current).digest();
		return parseTimestampTree(buf, offset, nextCurrent, merkleSteps, depth + 1);
	}
	if (op === OP_ATTESTATION) {
		const attStartOffset = offset - 1;
		if (offset + 8 > buf.length) {
			return { nextOffset: offset, pending: [], bitcoin: [], error: 'Truncated OTS attestation tag' };
		}
		const tag = buf.subarray(offset, offset + 8);
		offset += 8;
		const payloadLenVar = decodeVarintSafe(buf, offset);
		if (!payloadLenVar) {
			return { nextOffset: offset, pending: [], bitcoin: [], error: 'Malformed OTS payload length' };
		}
		offset = payloadLenVar.nextOffset;
		const payloadEnd = offset + payloadLenVar.value;
		if (payloadEnd > buf.length) {
			return { nextOffset: offset, pending: [], bitcoin: [], error: 'OTS payload past EOF' };
		}

		if (tag.equals(TAG_PENDING_ATTESTATION)) {
			let uri = '';
			const uriLenVar = decodeVarintSafe(buf, offset);
			if (uriLenVar && uriLenVar.nextOffset + uriLenVar.value === payloadEnd) {
				uri = buf
					.subarray(uriLenVar.nextOffset, uriLenVar.nextOffset + uriLenVar.value)
					.toString('utf8');
			} else if (uriLenVar && uriLenVar.nextOffset < payloadEnd) {
				const end = Math.min(payloadEnd, uriLenVar.nextOffset + uriLenVar.value);
				uri = buf.subarray(uriLenVar.nextOffset, end).toString('utf8');
			} else {
				uri = buf.subarray(offset, payloadEnd).toString('utf8');
			}
			return {
				nextOffset: payloadEnd,
				pending: [
					{
						uri,
						commitmentHex: current.toString('hex'),
						attStartOffset,
						attEndOffset: payloadEnd,
						merkleSteps
					}
				],
				bitcoin: []
			};
		}

		if (tag.equals(TAG_BITCOIN_ATTESTATION) || tag.equals(TAG_BITCOIN_ATTESTATION_ALT)) {
			const blockVar = decodeVarintSafe(buf, offset);
			if (!blockVar) {
				return { nextOffset: offset, pending: [], bitcoin: [], error: 'Malformed Bitcoin attestation' };
			}
			let nextOffset = payloadEnd;
			if (
				buf.length - payloadEnd >= OAKE_TRAILER_MARKER.length &&
				buf.subarray(payloadEnd, payloadEnd + OAKE_TRAILER_MARKER.length).equals(OAKE_TRAILER_MARKER)
			) {
				nextOffset = buf.length;
			}
			return {
				nextOffset,
				pending: [],
				bitcoin: [
					{
						btc_block: blockVar.value,
						root: current.toString('hex'),
						merkleSteps
					}
				]
			};
		}

		return { nextOffset: payloadEnd, pending: [], bitcoin: [] };
	}

	return { nextOffset: offset, pending: [], bitcoin: [], error: `Unexpected OTS opcode 0x${op.toString(16)}` };
}

function parseTimestampTree(buf, offset, current, merkleSteps, depth = 0) {
	if (depth > MAX_OTS_TREE_DEPTH) {
		return { nextOffset: offset, pending: [], bitcoin: [], error: 'OTS tree depth exceeded' };
	}
	const pending = [];
	const bitcoin = [];
	let pos = offset;
	while (pos < buf.length && buf[pos] === OP_FORK) {
		pos++;
		const branchRes = parseSingleBranch(buf, pos, current, merkleSteps, depth + 1);
		if (branchRes.error) return branchRes;
		pending.push(...branchRes.pending);
		bitcoin.push(...branchRes.bitcoin);
		pos = branchRes.nextOffset;
	}
	const finalRes = parseSingleBranch(buf, pos, current, merkleSteps, depth + 1);
	if (finalRes.error) return finalRes;
	pending.push(...finalRes.pending);
	bitcoin.push(...finalRes.bitcoin);
	return { nextOffset: finalRes.nextOffset, pending, bitcoin };
}

function extractPendingFromContinuation(calendarDigest32, continuationBytes) {
	const buf = Buffer.from(continuationBytes);
	const tree = parseTimestampTree(buf, 0, Buffer.from(calendarDigest32), 0, 0);
	if (tree.error || tree.nextOffset !== buf.length) return [];
	return tree.pending;
}

function hasBitcoinAttestationInContinuation(continuationBytes) {
	const buf = Buffer.from(continuationBytes);
	const tree = parseTimestampTree(buf, 0, Buffer.alloc(32), 0, 0);
	if (tree.error || tree.nextOffset !== buf.length) return false;
	return tree.bitcoin.length > 0;
}

function inspectOtsProof(otsBytes, expectedArtifactHash) {
	if (!otsBytes || otsBytes.length < OTS_MAGIC.length + 2) {
		return { validHeader: false, digestMatches: false, steps: 0, attestations: [] };
	}

	const magicOk = otsBytes.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC);
	if (!magicOk) {
		return { validHeader: false, digestMatches: false, steps: 0, attestations: [] };
	}

	const state = { offset: OTS_MAGIC.length };
	let version;
	let hashOp;
	try {
		version = readVarUint(otsBytes, state);
		hashOp = otsBytes[state.offset++];
	} catch {
		return { validHeader: true, digestMatches: false, steps: 0, attestations: [] };
	}

	if (version !== 1 || hashOp !== 0x08 || state.offset + 32 > otsBytes.length) {
		return { validHeader: true, digestMatches: false, steps: 0, attestations: [] };
	}

	const initialDigest = otsBytes.subarray(state.offset, state.offset + 32);
	state.offset += 32;
	const expectedHex = expectedArtifactHash.replace(/^sha256:/i, '').toLowerCase();
	const digestMatches = initialDigest.toString('hex') === expectedHex;

	const tree = parseTimestampTree(Buffer.from(otsBytes), state.offset, Buffer.from(initialDigest), 0, 0);
	const attestations = [];
	for (const btc of tree.bitcoin) {
		attestations.push({
			type: 'bitcoin',
			btc_block: btc.btc_block,
			root: btc.root,
			steps: btc.merkleSteps
		});
	}
	for (const p of tree.pending) {
		attestations.push({
			type: 'pending',
			uri: p.uri,
			root: p.commitmentHex,
			attStartOffset: p.attStartOffset,
			attEndOffset: p.attEndOffset,
			steps: p.merkleSteps
		});
	}

	const steps = attestations[0]?.steps ?? 0;

	return {
		validHeader: true,
		digestMatches,
		steps,
		attestations
	};
}

function spliceCalendarUpgradeBytes(otsBytes, commitmentHex, upgradeTimestampBytes) {
	const buf = Buffer.from(otsBytes);
	const tree = parseTimestampTree(
		buf,
		OTS_MAGIC.length + 2 + 32,
		Buffer.from(buf.subarray(OTS_MAGIC.length + 2, OTS_MAGIC.length + 2 + 32)),
		0,
		0
	);
	const target = tree.pending.find(
		(p) => p.commitmentHex.toLowerCase() === commitmentHex.toLowerCase()
	);
	if (!target) {
		throw new Error(`No PendingAttestation matching commitment ${commitmentHex}`);
	}
	return Buffer.concat([
		buf.subarray(0, target.attStartOffset),
		Buffer.from(upgradeTimestampBytes),
		buf.subarray(target.attEndOffset)
	]);
}

function loadOtsRateGuard(oakeHome) {
	const filePath = getOtsRateGuardPath(oakeHome);
	const defaults = {
		lastSubmitMs: null,
		lastPollByCommitment: {},
		hostBackoffs: {},
		totalHttpPosts: 0,
		totalHttpGets: 0,
		blockedSubmitFloods: 0,
		blockedPollFloods: 0,
		lastCalendarUsed: null
	};
	if (!fs.existsSync(filePath)) return defaults;
	try {
		const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
		return {
			...defaults,
			...parsed,
			lastPollByCommitment: parsed?.lastPollByCommitment ?? {},
			hostBackoffs: parsed?.hostBackoffs ?? {}
		};
	} catch {
		return defaults;
	}
}

function saveOtsRateGuard(oakeHome, state) {
	ensureDir(oakeHome);
	fs.writeFileSync(getOtsRateGuardPath(oakeHome), `${JSON.stringify(state, null, 2)}\n`, 'utf8');
}

async function submitBlindedDigestToCalendars(oakeHome, calendarDigest32) {
	const guard = loadOtsRateGuard(oakeHome);
	const now = Date.now();

	if (guard.lastSubmitMs !== null) {
		const elapsed = Math.max(0, now - guard.lastSubmitMs);
		if (elapsed < OTS_MIN_SUBMIT_INTERVAL_MS) {
			guard.blockedSubmitFloods++;
			saveOtsRateGuard(oakeHome, guard);
			return {
				ok: false,
				rateLimited: true,
				retryAfterMs: OTS_MIN_SUBMIT_INTERVAL_MS - elapsed
			};
		}
	}

	let lastError = 'All OTS calendars are currently in circuit-breaker backoff';
	for (const cal of OTS_CALENDARS) {
		const baseUrl = cal.url.replace(/\/+$/, '');
		const hostState = guard.hostBackoffs[baseUrl] ?? { backoffUntilMs: 0, lastStatus: null };
		if (hostState.backoffUntilMs > now) continue;

		guard.totalHttpPosts++;
		try {
			const res = await fetchWithTimeout(`${baseUrl}/digest`, {
				redirect: 'manual',
				method: 'POST',
				headers: {
					Accept: 'application/vnd.opentimestamps.v1',
					'Content-Type': 'application/x-www-form-urlencoded',
					'User-Agent': USER_AGENT_OTS_SUBMIT
				},
				body: Buffer.from(calendarDigest32)
			});
			hostState.lastStatus = res.status;

			if (res.status === 200) {
				const responseBytes = Buffer.from(await res.arrayBuffer());
				if (responseBytes.length === 0) {
					hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
					guard.hostBackoffs[baseUrl] = hostState;
					lastError = `Empty 200 response from ${baseUrl}`;
					saveOtsRateGuard(oakeHome, guard);
					continue;
				}
				const pending = extractPendingFromContinuation(calendarDigest32, responseBytes);
				const calendarUri = pending[0]?.uri ?? baseUrl;
				const commitmentHex = pending[0]?.commitmentHex ?? null;

				guard.lastSubmitMs = now;
				guard.lastCalendarUsed = baseUrl;
				hostState.backoffUntilMs = 0;
				guard.hostBackoffs[baseUrl] = hostState;
				saveOtsRateGuard(oakeHome, guard);

				return {
					ok: true,
					calendarHost: new URL(baseUrl).host,
					calendarUrl: baseUrl,
					calendarUri,
					commitmentHex,
					responseBytes
				};
			}

			hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
			guard.hostBackoffs[baseUrl] = hostState;
			lastError = `HTTP ${res.status} from ${baseUrl}`;
			saveOtsRateGuard(oakeHome, guard);
		} catch (err) {
			hostState.lastStatus = null;
			hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
			guard.hostBackoffs[baseUrl] = hostState;
			lastError = err instanceof Error ? err.message : String(err);
			saveOtsRateGuard(oakeHome, guard);
		}
	}

	return { ok: false, rateLimited: false, error: lastError };
}

/** Addresses inside `.ots` files are untrusted: only known calendars, from our own list. */
function matchKnownCalendar(uri) {
	let parsed;
	try {
		parsed = new URL(String(uri).trim());
	} catch {
		return null;
	}
	if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) {
		return null;
	}
	return OTS_CALENDARS.find((cal) => new URL(cal.url).hostname === parsed.hostname)?.url ?? null;
}

async function pollCalendarCommitmentUpgrade(oakeHome, calendarBaseUrl, commitmentHex) {
	const guard = loadOtsRateGuard(oakeHome);
	const now = Date.now();
	const key = commitmentHex.toLowerCase();
	const lastPoll = guard.lastPollByCommitment[key];

	if (lastPoll !== undefined) {
		const elapsed = Math.max(0, now - lastPoll);
		if (elapsed < OTS_MIN_POLL_INTERVAL_MS) {
			guard.blockedPollFloods++;
			saveOtsRateGuard(oakeHome, guard);
			return { status: 'rate_limited', retryAfterMs: OTS_MIN_POLL_INTERVAL_MS - elapsed };
		}
	}

	const baseUrl = calendarBaseUrl.replace(/\/+$/, '');
	const hostState = guard.hostBackoffs[baseUrl] ?? { backoffUntilMs: 0, lastStatus: null };
	if (hostState.backoffUntilMs > now) {
		return { status: 'error', error: `Calendar ${baseUrl} in circuit-breaker backoff` };
	}

	guard.lastPollByCommitment[key] = now;
	guard.totalHttpGets++;

	try {
		const res = await fetchWithTimeout(`${baseUrl}/timestamp/${key}`, {
			redirect: 'manual',
			method: 'GET',
			headers: {
				Accept: 'application/vnd.opentimestamps.v1',
				'User-Agent': USER_AGENT_OTS_POLL
			}
		});
		hostState.lastStatus = res.status;

		if (res.status === 404) {
			guard.hostBackoffs[baseUrl] = hostState;
			saveOtsRateGuard(oakeHome, guard);
			return { status: 'pending' };
		}

		if (res.status === 200) {
			hostState.backoffUntilMs = 0;
			guard.hostBackoffs[baseUrl] = hostState;
			const upgradeBytes = Buffer.from(await res.arrayBuffer());
			saveOtsRateGuard(oakeHome, guard);
			if (hasBitcoinAttestationInContinuation(upgradeBytes)) {
				return { status: 'upgraded', upgradeBytes };
			}
			return { status: 'pending' };
		}

		hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
		guard.hostBackoffs[baseUrl] = hostState;
		saveOtsRateGuard(oakeHome, guard);
		return { status: 'error', error: `HTTP ${res.status} from ${baseUrl}` };
	} catch (err) {
		hostState.lastStatus = null;
		hostState.backoffUntilMs = now + OTS_CIRCUIT_BREAKER_MS;
		guard.hostBackoffs[baseUrl] = hostState;
		saveOtsRateGuard(oakeHome, guard);
		return { status: 'error', error: err instanceof Error ? err.message : String(err) };
	}
}

// ============================================================================
// Local .oake/ Index & Proof Bundle Helpers
// ============================================================================

function generateVerifyMarkdown(entry) {
	const btcBlockDisplay = entry.ots?.btc_block !== null && entry.ots?.btc_block !== undefined
		? String(entry.ots.btc_block)
		: 'pending';
	const btcRootDisplay = entry.ots?.btc_merkle_root ?? 'pending';
	const tsaList =
		Array.isArray(entry.rfc3161_tokens) && entry.rfc3161_tokens.length > 0
			? entry.rfc3161_tokens
					.map(
						(t) =>
							`- \`${t.token_ref.replace(/^blob:\/\/tsr\//, 'rfc3161/')}\` — TSA: \`${t.tsa}\`, format: \`${t.format || 'rfc3161-cms-der'}\`, serial: \`${t.serial_number}\`, gen_time: \`${t.gen_time}\``
					)
					.join('\n')
			: '- _(none recorded — offline capture or TSA unreachable)_';

	return `# OAKe Independent Proof Verification Guide

This bundle (\`application/oake-bundle+zip\`) is 100% self-contained. You do **not** need Madara Labs or any OAKe server to verify it.

## Artifact Summary

| Field | Value |
| --- | --- |
| \`entry_id\` | \`${entry.entry_id}\` |
| \`artifact_hash\` | \`${entry.artifact_hash}\` |
| \`canonicalization\` | \`${entry.canonicalization}\` |
| \`user_pubkey\` | \`${entry.user_pubkey}\` |
| \`client_ts\` | \`${entry.client_ts}\` |
| \`received_ts\` | \`${entry.received_ts}\` |
| \`ots.status\` | \`${entry.ots?.status}\` |
| \`ots.calendar\` | \`${entry.ots?.calendar}\` |
| \`ots.btc_block\` | \`${btcBlockDisplay}\` |
| \`ots.btc_merkle_root\` | \`${btcRootDisplay}\` |

## Step 1: Verify Ed25519 Signature

Signed payload:
\`\`\`text
${entry.artifact_hash}|${entry.canonicalization}|${entry.client_ts}
\`\`\`

## Step 2: Verify \`rfc3161/*.tsr\` via OpenSSL System Root CAs

${tsaList}

\`\`\`bash
openssl ts -verify -digest ${entry.artifact_hash.replace(/^sha256:/, '')} -in rfc3161/<token>.tsr -CAfile /etc/ssl/cert.pem
\`\`\`

## Step 3: Verify \`proof.ots\` Against Bitcoin

\`\`\`bash
ots verify proof.ots
\`\`\`
`;
}

function buildBundleZipBuffer(entry, tsrBlobs, otsBlob) {
	const zipEntries = [
		{ name: 'entry.json', data: Buffer.from(`${JSON.stringify(entry, null, 2)}\n`, 'utf8') }
	];
	for (const blob of tsrBlobs) {
		const cleanName = blob.filename.replace(/^rfc3161\//, '').replace(/^\/+/, '');
		zipEntries.push({ name: `rfc3161/${cleanName}`, data: blob.data });
	}
	zipEntries.push(
		{ name: 'proof.ots', data: otsBlob },
		{ name: 'VERIFY.md', data: Buffer.from(generateVerifyMarkdown(entry), 'utf8') }
	);
	return writeZipArchive(zipEntries);
}

function readLocalIndex(indexPath) {
	if (!fs.existsSync(indexPath)) return [];
	const raw = fs.readFileSync(indexPath, 'utf8');
	const rows = [];
	for (const line of raw.split('\n')) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		rows.push(JSON.parse(trimmed));
	}
	return rows;
}

function writeLocalIndex(indexPath, rows) {
	ensureDir(path.dirname(indexPath));
	const content = rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : '');
	fs.writeFileSync(indexPath, content, 'utf8');
}

function appendLocalIndexRow(indexPath, row) {
	ensureDir(path.dirname(indexPath));
	fs.appendFileSync(indexPath, `${JSON.stringify(row)}\n`, 'utf8');
}

function getLatestChainHead(rows) {
	if (rows.length === 0) {
		return { sequence: 0, entry_hash: GENESIS_PREV_HASH };
	}
	const last = rows[rows.length - 1];
	return { sequence: last.sequence, entry_hash: last.entry_hash };
}

function findOpenSslBinary() {
	const candidates = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', 'openssl'];
	for (const bin of candidates) {
		try {
			execFileSync(bin, ['ts', '-help'], { stdio: ['ignore', 'pipe', 'pipe'] });
			return bin;
		} catch {
			// try next candidate
		}
	}
	return null;
}

function verifyCmsTsrWithOpenSsl(opensslBin, caFile, digestHex64, tsrBuffer) {
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-tsr-'));
	const tmpTsr = path.join(tmpDir, 'token.tsr');
	try {
		fs.writeFileSync(tmpTsr, tsrBuffer);
		const out = execFileSync(
			opensslBin,
			['ts', '-verify', '-digest', digestHex64, '-in', tmpTsr, '-CAfile', caFile],
			{ encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
		);
		return { ok: out.includes('Verification: OK'), output: out.trim() };
	} catch (err) {
		const stderr = err?.stderr ? String(err.stderr).trim() : '';
		const stdout = err?.stdout ? String(err.stdout).trim() : '';
		return { ok: false, output: stderr || stdout || (err instanceof Error ? err.message : String(err)) };
	} finally {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	}
}

// ============================================================================
// Argument Parsing & Help
// ============================================================================

function parseArgs(argv) {
	const positionals = [];
	const flags = {};
	for (let i = 0; i < argv.length; i++) {
		const token = argv[i];
		if (token === '--') {
			positionals.push(...argv.slice(i + 1));
			break;
		}
		if (token.startsWith('--')) {
			const eqIdx = token.indexOf('=');
			if (eqIdx !== -1) {
				flags[token.slice(2, eqIdx)] = token.slice(eqIdx + 1);
			} else {
				const key = token.slice(2);
				const next = argv[i + 1];
				if (
					next !== undefined &&
					!next.startsWith('-') &&
					['canon', 'source', 'repo', 'commit', 'endpoint', 'dir', 'file', 'o'].includes(key)
				) {
					flags[key] = next;
					i++;
				} else {
					flags[key] = true;
				}
			}
		} else if (token === '-o') {
			flags.o = argv[++i];
		} else if (token === '-h') {
			flags.help = true;
		} else {
			positionals.push(token);
		}
	}
	return { positionals, flags };
}

function printUsage() {
	console.log(`OAKe Local-First Provenance CLI (${OAKE_PROTOCOL_VERSION})

Usage:
  oake init [--force]
  oake keygen [--force]
  oake hash <file> [--canon raw-bytes/v1|text-normalized/v1|ipynb-cells/v1]
  oake capture <file_or_dir> [--canon ...] [--source cli|git-hook|jupyter|overleaf|editor|manual]
                             [--repo <name>] [--commit <sha>] [--plain-paths] [--dir <project_dir>]
                             [--offline] [--publish] [--remote-only] [--endpoint <url>] [--dry-run]
  oake log [--dir <project_dir>]
  oake push [bundle_or_dir] [--endpoint <url>] [--dir <project_dir>]
  oake upgrade [bundle_or_dir] [--dir <project_dir>]
  oake proof <entry_id> [-o <path.oake.zip>] [--endpoint <url>]
  oake verify <bundle.zip | sha256_or_entry_id> [--file <original_artifact>] [--canon ...] [--offline] [--online] [--endpoint <url>]
  oake settle [--poll] [--simulate] [--restamp] [--force] [--endpoint <url>]
  oake status [--dir <project_dir>] [--endpoint <url>]
  oake install --git [--dir <repo_dir>]
`);
}

// ============================================================================
// Commands
// ============================================================================

async function cmdInit(flags, oakeHome) {
	const { keyData, keyPath, configPath } = generateIdentity(oakeHome, Boolean(flags.force));
	console.log(`Initialized OAKe identity:`);
	console.log(`  Public key : ${keyData.pubkey}`);
	console.log(`  Key file   : ${keyPath} (0600)`);
	console.log(`  Config file: ${configPath}`);
}

function cmdHash(positionals, flags) {
	const file = positionals[0];
	if (!file) {
		throw new Error('Usage: oake hash <file> [--canon raw-bytes/v1|text-normalized/v1|ipynb-cells/v1]');
	}
	const resolved = path.resolve(file);
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
		throw new Error(`File not found: ${file}`);
	}
	const canon = inferDefaultCanon(resolved, typeof flags.canon === 'string' ? flags.canon : undefined);
	const { artifactHash } = canonicalizeAndHash(resolved, canon);
	console.log(artifactHash);
}

async function witnessBundleToEndpoint(zipBuffer, endpoint) {
	const res = await fetchWithTimeout(
		`${endpoint}/v1/witness`,
		{
			method: 'POST',
			headers: { 'Content-Type': 'application/oake-bundle+zip' },
			body: zipBuffer
		},
		15_000
	);
	const data = await res.json().catch(() => ({}));
	if (!res.ok) {
		throw new Error(`POST /v1/witness failed (${res.status}): ${data.error || res.statusText}`);
	}
	return data;
}

async function cmdCapture(positionals, flags, oakeHome) {
	let target = positionals[0];
	if (!target && flags.commit) {
		target = '.';
	}
	if (!target) {
		throw new Error('Usage: oake capture <file_or_dir> [options]');
	}

	const captureSource = typeof flags.source === 'string' ? flags.source : 'cli';
	if (!CAPTURE_SOURCES.includes(captureSource)) {
		throw new Error(`Invalid --source "${captureSource}". Allowed: ${CAPTURE_SOURCES.join(', ')}`);
	}

	const explicitCanon = typeof flags.canon === 'string' ? flags.canon : undefined;
	if (explicitCanon && !CANONICALIZATION_METHODS.includes(explicitCanon)) {
		throw new Error(
			`Invalid --canon "${explicitCanon}". Allowed: ${CANONICALIZATION_METHODS.join(', ')}`
		);
	}

	const keyData = loadOrCreateIdentity(oakeHome);
	const files = collectTargetFiles(target);
	if (files.length === 0) {
		console.log('No eligible files found to capture.');
		return;
	}

	const endpoint = resolveEndpoint(typeof flags.endpoint === 'string' ? flags.endpoint : undefined, oakeHome);
	const plainPaths = Boolean(flags['plain-paths']);
	const repoName = typeof flags.repo === 'string' ? flags.repo : undefined;
	const dryRun = Boolean(flags['dry-run']);
	const remoteOnly = Boolean(flags['remote-only']);
	const offline = Boolean(flags.offline);
	const publish = Boolean(flags.publish);

	const cwdReal = fs.realpathSync(process.cwd());
	const payloads = files.map((absPath) => {
		const canon = inferDefaultCanon(absPath, explicitCanon);
		const { artifactHash, byteSize } = canonicalizeAndHash(absPath, canon);
		const clientTs = new Date().toISOString();
		const signature = signDigest(keyData, artifactHash, canon, clientTs);
		const absReal = fs.realpathSync(absPath);
		const relPath = path.relative(cwdReal, absReal) || path.basename(absReal);
		const pathHint = plainPaths ? relPath : `sha256:${sha256Hex(Buffer.from(relPath, 'utf8'))}`;

		const metadata = {
			...(repoName ? { repo: repoName } : {}),
			path_hint: pathHint,
			artifact_kind: inferArtifactKind(absPath),
			byte_size: byteSize
		};

		return {
			user_pubkey: keyData.pubkey,
			artifact_hash: artifactHash,
			canonicalization: canon,
			client_ts: clientTs,
			signature,
			capture_source: captureSource,
			metadata
		};
	});

	if (dryRun) {
		console.log(JSON.stringify(payloads.length === 1 ? payloads[0] : payloads, null, 2));
		return;
	}

	if (remoteOnly) {
		for (const payload of payloads) {
			const res = await fetch(`${endpoint}/v1/entries`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload)
			});
			const data = await res.json().catch(() => ({}));
			if (!res.ok) {
				throw new Error(`POST /v1/entries failed (${res.status}): ${data.error || res.statusText}`);
			}
			console.log(
				`Captured ${payload.artifact_hash} -> entry_id=${data.entry_id} ots=${data.ots?.status} batch=${data.ots?.batch_id}`
			);
		}
		return;
	}

	// Standalone Local-First Mode (.oake/ repository)
	const projectRoot = resolveProjectRoot(typeof flags.dir === 'string' ? flags.dir : undefined);
	const { proofsDir, indexPath } = getLocalRepoPaths(projectRoot);
	ensureDir(proofsDir);

	const indexRows = readLocalIndex(indexPath);
	let head = getLatestChainHead(indexRows);

	// Build ONE local Merkle batch + 16-byte blinding nonce across all files in this capture invocation
	const { rootHash, paths: merklePaths } = buildMerkleBatch(
		payloads.map((p) => p.artifact_hash)
	);
	const batchNonce16 = crypto.randomBytes(16);
	const batchId = `local-${generateUlid()}`;
	const calendarDigest32 = crypto
		.createHash('sha256')
		.update(Buffer.concat([Buffer.from(rootHash.slice('sha256:'.length), 'hex'), batchNonce16]))
		.digest();

	let otsLiveResult = null;
	if (!offline) {
		otsLiveResult = await submitBlindedDigestToCalendars(oakeHome, calendarDigest32);
		if (!otsLiveResult.ok && otsLiveResult.rateLimited) {
			console.log(
				`OTS calendar cooldown active (${Math.ceil(otsLiveResult.retryAfterMs / 1000)}s remaining) — storing provisional .ots locally.`
			);
		} else if (!otsLiveResult.ok) {
			console.warn(`Warning: OTS calendar unreachable (${otsLiveResult.error}) — storing provisional .ots locally.`);
		}
	}

	for (const payload of payloads) {
		const now = new Date();
		const receivedTs = now.toISOString();
		const entryId = generateUlid(now.getTime());

		let tsrResults = [];
		if (!offline) {
			const tsaRes = await stampDigestExternalTsas(entryId, payload.artifact_hash);
			tsrResults = tsaRes.tokens;
			if (tsaRes.errors.length > 0 && tsrResults.length === 0) {
				console.warn(`Warning: external RFC 3161 TSAs unreachable (${tsaRes.errors.join('; ')})`);
			}
		}

		const merklePath = merklePaths.get(payload.artifact_hash.toLowerCase()) || [];
		let otsBlob;
		let otsRecord;
		if (otsLiveResult && otsLiveResult.ok) {
			otsBlob = composeLiveCalendarOtsBytes(
				payload.artifact_hash,
				merklePath,
				batchNonce16,
				otsLiveResult.responseBytes
			);
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
			otsBlob = composeProvisionalOtsBytes(
				payload.artifact_hash,
				merklePath,
				batchNonce16,
				provisionalUri
			);
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
		const cleanMetadata = { ...payload.metadata, origin: 'standalone-cli' };
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
			chain: {
				sequence,
				prev_entry_hash: prevEntryHash,
				entry_hash: entryHash
			}
		};

		const zipBuffer = buildBundleZipBuffer(
			entry,
			tsrResults.map((t) => ({ filename: t.filename, data: t.tsrBytes })),
			otsBlob
		);

		const bundleFilename = `${entryId}.oake.zip`;
		const bundleAbsPath = path.join(proofsDir, bundleFilename);
		fs.writeFileSync(bundleAbsPath, zipBuffer);

		let publishedTo = null;
		if (publish) {
			await witnessBundleToEndpoint(zipBuffer, endpoint);
			publishedTo = endpoint;
		}

		const relBundlePath = path.relative(projectRoot, bundleAbsPath).replace(/\\/g, '/');
		appendLocalIndexRow(indexPath, {
			sequence,
			prev_entry_hash: prevEntryHash,
			entry_hash: entryHash,
			entry_id: entryId,
			artifact_hash: payload.artifact_hash,
			canonicalization: payload.canonicalization,
			ots_status: otsRecord.status,
			tsa_count: tsrResults.length,
			published_to: publishedTo,
			bundle_path: relBundlePath,
			captured_ts: receivedTs
		});

		head = { sequence, entry_hash: entryHash };

		console.log(
			`Captured ${payload.artifact_hash} -> entry_id=${entryId} seq=#${sequence} tsas=${tsrResults.length} ots=${otsRecord.status} bundle=${relBundlePath}${publishedTo ? ` published=${publishedTo}` : ''}`
		);
	}
}

function cmdLog(flags) {
	const projectRoot = resolveProjectRoot(typeof flags.dir === 'string' ? flags.dir : undefined);
	const { indexPath } = getLocalRepoPaths(projectRoot);
	const rows = readLocalIndex(indexPath);

	if (rows.length === 0) {
		console.log(`No local OAKe provenance entries in ${path.join(projectRoot, '.oake')}`);
		return;
	}

	console.log(`OAKe Local Provenance Log (${projectRoot}/.oake/index.jsonl):`);
	let expectedPrev = GENESIS_PREV_HASH;
	let chainOk = true;
	for (const row of rows) {
		if (row.prev_entry_hash !== expectedPrev) {
			chainOk = false;
		}
		expectedPrev = row.entry_hash;
		const tsaCount = typeof row.tsa_count === 'number' ? row.tsa_count : 0;
		const published = row.published_to || 'local-only';
		console.log(
			`  #${row.sequence}  ${row.entry_id}  ${row.artifact_hash}  ots=${row.ots_status}  tsas=${tsaCount}  published_to=${published}`
		);
	}
	console.log(`Chain integrity: ${chainOk ? 'VALID' : 'BROKEN'} (${rows.length} entries)`);
}

async function cmdPush(positionals, flags, oakeHome) {
	const targetArg = positionals[0];
	const endpoint = resolveEndpoint(typeof flags.endpoint === 'string' ? flags.endpoint : undefined, oakeHome);

	let explicitBundlePath = null;
	let explicitDir = typeof flags.dir === 'string' ? flags.dir : undefined;

	if (targetArg) {
		const resolved = path.resolve(targetArg);
		if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
			explicitBundlePath = resolved;
			const parentDir = path.dirname(resolved);
			if (!explicitDir && path.basename(parentDir) === 'proofs' && path.basename(path.dirname(parentDir)) === '.oake') {
				explicitDir = path.dirname(path.dirname(parentDir));
			}
		} else {
			explicitDir = resolved;
		}
	}

	const projectRoot = resolveProjectRoot(explicitDir);
	const { proofsDir, indexPath } = getLocalRepoPaths(projectRoot);
	const rows = readLocalIndex(indexPath);

	const bundles = [];
	if (explicitBundlePath) {
		bundles.push(explicitBundlePath);
	} else if (fs.existsSync(proofsDir)) {
		const files = fs
			.readdirSync(proofsDir)
			.filter((name) => name.endsWith('.oake.zip'))
			.sort();
		for (const name of files) {
			bundles.push(path.join(proofsDir, name));
		}
	}

	if (bundles.length === 0) {
		console.log('No local .oake.zip proof bundles found to push.');
		return;
	}

	let pushed = 0;
	for (const bundlePath of bundles) {
		const zipBuffer = fs.readFileSync(bundlePath);
		const files = readZipEntries(zipBuffer);
		const entryRaw = files.get('entry.json');
		if (!entryRaw) {
			throw new Error(`Invalid bundle (missing entry.json): ${bundlePath}`);
		}
		const entry = JSON.parse(entryRaw.toString('utf8'));
		const existingRow = rows.find((r) => r.entry_id === entry.entry_id);
		if (!explicitBundlePath && existingRow && existingRow.published_to === endpoint) {
			continue;
		}

		const result = await witnessBundleToEndpoint(zipBuffer, endpoint);
		if (existingRow) {
			existingRow.published_to = endpoint;
		}
		pushed++;
		console.log(
			`Pushed ${entry.entry_id} -> ${endpoint}/v1/witness (witnessed=${result.witnessed}, deduplicated=${result.deduplicated})`
		);
	}

	if (rows.length > 0 && pushed > 0) {
		writeLocalIndex(indexPath, rows);
	}
	if (pushed === 0) {
		console.log(`All local proof bundles are already published to ${endpoint}.`);
	}
}

async function cmdUpgrade(positionals, flags, oakeHome) {
	const targetArg = positionals[0];
	let explicitBundlePath = null;
	let explicitDir = typeof flags.dir === 'string' ? flags.dir : undefined;

	if (targetArg) {
		const resolved = path.resolve(targetArg);
		if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
			explicitBundlePath = resolved;
			const parentDir = path.dirname(resolved);
			if (!explicitDir && path.basename(parentDir) === 'proofs' && path.basename(path.dirname(parentDir)) === '.oake') {
				explicitDir = path.dirname(path.dirname(parentDir));
			}
		} else {
			explicitDir = resolved;
		}
	}

	const projectRoot = resolveProjectRoot(explicitDir);
	const { proofsDir, indexPath } = getLocalRepoPaths(projectRoot);
	const indexRows = readLocalIndex(indexPath);

	const bundlePaths = [];
	if (explicitBundlePath) {
		bundlePaths.push(explicitBundlePath);
	} else if (fs.existsSync(proofsDir)) {
		const files = fs
			.readdirSync(proofsDir)
			.filter((name) => name.endsWith('.oake.zip'))
			.sort();
		for (const name of files) {
			bundlePaths.push(path.join(proofsDir, name));
		}
	}

	if (bundlePaths.length === 0) {
		console.log('No local .oake.zip proof bundles found to upgrade.');
		return;
	}

	const loaded = bundlePaths.map((bundlePath) => {
		const zipBuffer = fs.readFileSync(bundlePath);
		const files = readZipEntries(zipBuffer);
		const entryRaw = files.get('entry.json');
		if (!entryRaw) {
			throw new Error(`Invalid bundle (missing entry.json): ${bundlePath}`);
		}
		const entry = JSON.parse(entryRaw.toString('utf8'));
		const otsBlob = files.get('proof.ots') || null;
		const tsrBlobs = [];
		for (const [name, data] of files.entries()) {
			if (name.startsWith('rfc3161/') && name.length > 'rfc3161/'.length) {
				tsrBlobs.push({ filename: name.slice('rfc3161/'.length), data });
			}
		}
		return { bundlePath, entry, otsBlob, tsrBlobs };
	});

	let indexDirty = false;

	// Phase 1: Flush provisional bundles -> pending on Alice (1 batched POST /digest max)
	const provisionalItems = loaded.filter((item) => item.entry.ots?.status === 'provisional');
	if (provisionalItems.length > 0) {
		const { rootHash, paths: merklePaths } = buildMerkleBatch(
			provisionalItems.map((i) => i.entry.artifact_hash)
		);
		const batchNonce16 = crypto.randomBytes(16);
		const calendarDigest32 = crypto
			.createHash('sha256')
			.update(Buffer.concat([Buffer.from(rootHash.slice('sha256:'.length), 'hex'), batchNonce16]))
			.digest();

		const submitRes = await submitBlindedDigestToCalendars(oakeHome, calendarDigest32);
		if (submitRes.ok) {
			for (const item of provisionalItems) {
				const merklePath = merklePaths.get(item.entry.artifact_hash.toLowerCase()) || [];
				const newOts = composeLiveCalendarOtsBytes(
					item.entry.artifact_hash,
					merklePath,
					batchNonce16,
					submitRes.responseBytes
				);
				item.otsBlob = newOts;
				item.entry.ots = {
					...item.entry.ots,
					status: 'pending',
					calendar: submitRes.calendarHost,
					batch_id: submitRes.commitmentHex || item.entry.ots.batch_id
				};
				const updatedZip = buildBundleZipBuffer(item.entry, item.tsrBlobs, newOts);
				fs.writeFileSync(item.bundlePath, updatedZip);

				const row = indexRows.find((r) => r.entry_id === item.entry.entry_id);
				if (row) {
					row.ots_status = 'pending';
					indexDirty = true;
				}
				console.log(
					`Submitted ${item.entry.entry_id} to ${submitRes.calendarHost} (ots=pending, commitment=${submitRes.commitmentHex})`
				);
			}
		} else if (submitRes.rateLimited) {
			console.log(
				`OTS submit cooldown active (${Math.ceil(submitRes.retryAfterMs / 1000)}s remaining) — ${provisionalItems.length} provisional bundle(s) deferred.`
			);
		} else {
			console.log(`OTS submit failed (${submitRes.error}) — provisional bundle(s) unchanged.`);
		}
	}

	// Phase 2: Poll pending bundles for Bitcoin block confirmation
	const pendingItems = loaded.filter(
		(item) => item.entry.ots?.status === 'pending' && item.otsBlob
	);
	const groups = new Map();
	for (const item of pendingItems) {
		const check = inspectOtsProof(item.otsBlob, item.entry.artifact_hash);
		const pendingAtt = check.attestations.find((a) => a.type === 'pending' && a.uri);
		if (!pendingAtt) continue;
		const calBaseUrl = matchKnownCalendar(pendingAtt.uri);
		if (!calBaseUrl) {
			console.log(`Skipped ${item.entry.entry_id}: its .ots names an unknown calendar.`);
			continue;
		}
		const groupKey = `${calBaseUrl}|${pendingAtt.root}`;
		if (!groups.has(groupKey)) {
			groups.set(groupKey, { calBaseUrl, commitmentHex: pendingAtt.root, items: [] });
		}
		groups.get(groupKey).items.push(item);
	}

	for (const group of groups.values()) {
		const pollRes = await pollCalendarCommitmentUpgrade(
			oakeHome,
			group.calBaseUrl,
			group.commitmentHex
		);
		if (pollRes.status === 'upgraded') {
			const upgradedTs = new Date().toISOString();
			for (const item of group.items) {
				const splicedOts = spliceCalendarUpgradeBytes(
					item.otsBlob,
					group.commitmentHex,
					pollRes.upgradeBytes
				);
				const check = inspectOtsProof(splicedOts, item.entry.artifact_hash);
				const btcAtt = check.attestations.find((a) => a.type === 'bitcoin');
				item.otsBlob = splicedOts;
				item.entry.ots = {
					...item.entry.ots,
					status: 'upgraded',
					btc_block: btcAtt?.btc_block ?? null,
					btc_merkle_root: btcAtt?.root ? `sha256:${btcAtt.root}` : null,
					upgraded_ts: upgradedTs
				};
				const updatedZip = buildBundleZipBuffer(item.entry, item.tsrBlobs, splicedOts);
				fs.writeFileSync(item.bundlePath, updatedZip);

				const row = indexRows.find((r) => r.entry_id === item.entry.entry_id);
				if (row) {
					row.ots_status = 'upgraded';
					indexDirty = true;
				}
				console.log(
					`Upgraded ${item.entry.entry_id} -> ots=upgraded (Bitcoin block #${btcAtt?.btc_block ?? 'unknown'})`
				);
			}
		} else if (pollRes.status === 'rate_limited') {
			console.log(
				`Poll cooldown active for ${group.commitmentHex.slice(0, 12)}... (${Math.ceil(pollRes.retryAfterMs / 1000)}s remaining).`
			);
		} else if (pollRes.status === 'pending') {
			console.log(
				`Commitment ${group.commitmentHex.slice(0, 12)}... on ${group.calBaseUrl} is still awaiting Bitcoin block confirmation.`
			);
		} else {
			console.log(`Poll error for ${group.commitmentHex.slice(0, 12)}...: ${pollRes.error}`);
		}
	}

	if (indexDirty && fs.existsSync(indexPath)) {
		writeLocalIndex(indexPath, indexRows);
	}
}

async function cmdProof(positionals, flags, oakeHome) {
	const entryId = positionals[0];
	if (!entryId) {
		throw new Error('Usage: oake proof <entry_id> [-o <path.oake.zip>] [--endpoint <url>]');
	}

	const projectRoot = resolveProjectRoot(typeof flags.dir === 'string' ? flags.dir : undefined);
	const localBundlePath = path.join(projectRoot, '.oake', 'proofs', `${entryId}.oake.zip`);
	if (fs.existsSync(localBundlePath)) {
		const outPath = typeof flags.o === 'string' ? flags.o : `${entryId}.oake.zip`;
		const bytes = fs.readFileSync(localBundlePath);
		fs.writeFileSync(outPath, bytes);
		console.log(`Copied local proof bundle (${bytes.byteLength} bytes) to ${outPath}`);
		return;
	}

	const endpoint = resolveEndpoint(typeof flags.endpoint === 'string' ? flags.endpoint : undefined, oakeHome);
	const res = await fetch(`${endpoint}/v1/entries/${encodeURIComponent(entryId)}/proof`);
	if (!res.ok) {
		const errBody = await res.json().catch(() => ({}));
		throw new Error(`GET /v1/entries/${entryId}/proof failed (${res.status}): ${errBody.error || res.statusText}`);
	}

	const bytes = Buffer.from(await res.arrayBuffer());
	const outPath = typeof flags.o === 'string' ? flags.o : `${entryId}.oake.zip`;
	fs.writeFileSync(outPath, bytes);
	console.log(`Saved proof bundle (${bytes.byteLength} bytes) to ${outPath}`);
}

async function cmdVerify(positionals, flags, oakeHome) {
	const target = positionals[0];
	if (!target) {
		throw new Error(
			'Usage: oake verify <bundle.zip | sha256_or_entry_id> [--file <original_artifact>] [--canon ...] [--offline] [--online]'
		);
	}

	const endpoint = resolveEndpoint(typeof flags.endpoint === 'string' ? flags.endpoint : undefined, oakeHome);
	const offline = Boolean(flags.offline);
	const online = Boolean(flags.online);
	const fileFlag = typeof flags.file === 'string' ? flags.file : undefined;
	const canonFlag = typeof flags.canon === 'string' ? flags.canon : undefined;

	let bundlePath = target;
	let isZipFile = target.endsWith('.zip') || (fs.existsSync(target) && fs.statSync(target).isFile());
	if (!isZipFile && !online) {
		const projectRoot = resolveProjectRoot(typeof flags.dir === 'string' ? flags.dir : undefined);
		const candidate = path.join(projectRoot, '.oake', 'proofs', `${target}.oake.zip`);
		if (fs.existsSync(candidate)) {
			bundlePath = candidate;
			isZipFile = true;
		}
	}

	if (isZipFile) {
		if (!fs.existsSync(bundlePath)) {
			throw new Error(`Proof bundle not found: ${bundlePath}`);
		}
		const zipBuffer = fs.readFileSync(bundlePath);
		const files = readZipEntries(zipBuffer);

		const entryRaw = files.get('entry.json');
		if (!entryRaw) {
			throw new Error('Invalid proof bundle: missing entry.json');
		}
		const entry = JSON.parse(entryRaw.toString('utf8'));

		const sigResult = verifyEd25519Signature(
			entry.user_pubkey,
			entry.signature,
			entry.artifact_hash,
			entry.canonicalization,
			entry.client_ts
		);

		let fileMatch = null;
		if (fileFlag) {
			const canon = canonFlag || entry.canonicalization || 'raw-bytes/v1';
			const { artifactHash } = canonicalizeAndHash(path.resolve(fileFlag), canon);
			fileMatch = artifactHash === entry.artifact_hash;
		}

		const otsBytes = files.get('proof.ots');
		const otsCheck = inspectOtsProof(otsBytes, entry.artifact_hash);
		const tsrFiles = Array.from(files.keys())
			.filter((k) => k.startsWith('rfc3161/') && k.endsWith('.tsr'))
			.sort();
		const hasVerifyMd = files.has('VERIFY.md');

		const btcAtt = otsCheck.attestations.find((a) => a.type === 'bitcoin');
		const pendingAtt = otsCheck.attestations.find((a) => a.type === 'pending');
		const rootMatchesEntry =
			!btcAtt ||
			!entry.ots?.btc_merkle_root ||
			`sha256:${btcAtt.root}` === entry.ots.btc_merkle_root.toLowerCase();

		// OpenSSL X.509 CMS DER verification for standard RFC 3161 .tsr tokens (buf[0] === 0x30)
		const cmsTsrFiles = tsrFiles.filter((name) => {
			const buf = files.get(name);
			return buf && buf.length > 0 && buf[0] === 0x30;
		});
		let cmsVerifiedCount = 0;
		let cmsVerifyAttempted = false;
		const cmsFailures = [];
		if (cmsTsrFiles.length > 0) {
			const caFile = '/etc/ssl/cert.pem';
			const opensslBin = fs.existsSync(caFile) ? findOpenSslBinary() : null;
			if (opensslBin) {
				cmsVerifyAttempted = true;
				const digestHex64 = entry.artifact_hash.replace(/^sha256:/i, '').toLowerCase();
				for (const name of cmsTsrFiles) {
					const buf = files.get(name);
					const res = verifyCmsTsrWithOpenSsl(opensslBin, caFile, digestHex64, buf);
					if (res.ok) {
						cmsVerifiedCount++;
					} else {
						cmsFailures.push(`${name}: ${res.output}`);
					}
				}
			}
		}

		console.log(`Local bundle inspection (${bundlePath}):`);
		console.log(`  entry_id      : ${entry.entry_id}`);
		console.log(`  artifact_hash : ${entry.artifact_hash} (${entry.canonicalization})`);
		console.log(
			`  signature     : ${sigResult.signed ? (sigResult.valid ? 'VALID (Ed25519)' : 'INVALID') : 'anonymous'}`
		);
		if (fileMatch !== null) {
			console.log(`  local --file  : ${fileMatch ? 'MATCHES' : 'MISMATCH'}`);
		}
		console.log(
			`  proof.ots     : ${otsBytes ? (otsCheck.validHeader ? `header OK, digest ${otsCheck.digestMatches ? 'OK' : 'MISMATCH'}, steps=${otsCheck.steps}` : 'INVALID OTS header') : 'MISSING'}`
		);
		if (btcAtt) {
			console.log(
				`  ots_status    : upgraded (Bitcoin block #${btcAtt.btc_block}, root=sha256:${btcAtt.root.slice(0, 16)}... ${rootMatchesEntry ? 'OK' : 'MISMATCH'})`
			);
		} else if (pendingAtt) {
			const statusLabel = entry.ots?.status === 'provisional' ? 'provisional' : 'pending';
			console.log(
				pendingAtt.uri
					? `  ots_status    : ${statusLabel} (calendar ${pendingAtt.uri})`
					: `  ots_status    : ${statusLabel} (calendar pending)`
			);
		}

		if (cmsVerifyAttempted) {
			if (cmsVerifiedCount === cmsTsrFiles.length) {
				console.log(
					`  rfc3161/*.tsr : ${cmsVerifiedCount}/${cmsTsrFiles.length} VERIFIED via OpenSSL System Root CAs (Verification: OK)`
				);
			} else {
				console.log(
					`  rfc3161/*.tsr : ${cmsVerifiedCount}/${cmsTsrFiles.length} VERIFIED via OpenSSL System Root CAs (FAILED: ${cmsFailures.join('; ')})`
				);
			}
		} else {
			console.log(`  rfc3161/*.tsr : ${tsrFiles.length} token(s)`);
		}
		console.log(`  VERIFY.md     : ${hasVerifyMd ? 'present' : 'missing'}`);

		let localOk =
			(!sigResult.signed || sigResult.valid) &&
			(fileMatch === null || fileMatch) &&
			Boolean(otsBytes) &&
			otsCheck.validHeader &&
			otsCheck.digestMatches &&
			rootMatchesEntry &&
			(!cmsVerifyAttempted || cmsVerifiedCount === cmsTsrFiles.length);

		if (online && !offline) {
			const query =
				fileFlag && fileMatch !== null
					? `?hash=${encodeURIComponent(entry.artifact_hash)}`
					: '';
			const res = await fetch(`${endpoint}/v1/verify${query}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/oake-bundle+zip' },
				body: zipBuffer
			});
			const remote = await res.json().catch(() => ({}));
			if (!res.ok) {
				throw new Error(`POST /v1/verify failed (${res.status}): ${remote.error || res.statusText}`);
			}
			console.log(`Server verification: ${remote.verdict ?? 'unknown'} — ${remote.conclusion}`);
			localOk = localOk && (remote.verdict ? remote.verdict !== 'failed' : Boolean(remote.valid));
		}

		// Anything that could not be checked counts as missing, never as passed.
		const verdict = !localOk
			? 'FAILED'
			: sigResult.signed && cmsVerifiedCount > 0
				? 'VERIFIED'
				: 'INCOMPLETE';
		const why = {
			FAILED: 'a check did not pass',
			VERIFIED: 'signature and timestamp token checked; Bitcoin is not checked here (use `ots verify`)',
			INCOMPLETE: !sigResult.signed
				? 'the proof is not signed'
				: 'no timestamp token could be verified, so this does not show when the file existed'
		}[verdict];
		console.log(`  verdict       : ${verdict} (${why})`);
		process.exitCode = { VERIFIED: 0, FAILED: 1, INCOMPLETE: 2 }[verdict];
		return;
	}

	if (offline) {
		throw new Error('--offline requires a local .oake.zip bundle file');
	}

	const isHash = /^sha256:[0-9a-f]{64}$/i.test(target) || /^[0-9a-f]{64}$/i.test(target);
	const body = isHash
		? { artifact_hash: target.startsWith('sha256:') ? target.toLowerCase() : `sha256:${target.toLowerCase()}` }
		: { entry_id: target };

	const res = await fetch(`${endpoint}/v1/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
	const data = await res.json().catch(() => ({}));
	if (!res.ok) {
		throw new Error(`POST /v1/verify failed (${res.status}): ${data.error || res.statusText}`);
	}

	if (fileFlag && data.artifact_hash) {
		const canon = inferDefaultCanon(
			path.resolve(fileFlag),
			canonFlag || data.canonicalization
		);
		const { artifactHash } = canonicalizeAndHash(path.resolve(fileFlag), canon);
		if (artifactHash !== data.artifact_hash) {
			console.error(`Local file hash mismatch: got ${artifactHash}, expected ${data.artifact_hash}`);
			process.exitCode = 1;
			return;
		}
	}

	console.log(JSON.stringify(data, null, 2));
	if (!data.valid) {
		process.exitCode = data.verdict === 'incomplete' ? 2 : 1;
	}
}

async function cmdSettle(flags, oakeHome) {
	const endpoint = resolveEndpoint(typeof flags.endpoint === 'string' ? flags.endpoint : undefined, oakeHome);
	const modeCount = [flags.restamp, flags.poll, flags.simulate].filter(Boolean).length;
	if (modeCount > 1) {
		throw new Error('Use at most one of --poll, --simulate, or --restamp');
	}
	let body;
	if (flags.restamp) {
		body = { action: 'restamp', force: Boolean(flags.force) };
	} else if (flags.poll) {
		body = { action: 'poll_live' };
	} else if (flags.simulate) {
		body = { action: 'simulate_block' };
	} else {
		body = { action: 'flush_live' };
	}

	const res = await fetch(`${endpoint}/v1/batches/settle`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
	const data = await res.json().catch(() => ({}));
	if (!res.ok) {
		throw new Error(`POST /v1/batches/settle failed (${res.status}): ${data.error || res.statusText}`);
	}
	console.log(JSON.stringify(data, null, 2));
}

async function cmdStatus(flags, oakeHome) {
	const keyPath = getKeyFilePath(oakeHome);
	const configPath = getConfigFilePath(oakeHome);
	const endpoint = resolveEndpoint(typeof flags.endpoint === 'string' ? flags.endpoint : undefined, oakeHome);
	const projectRoot = resolveProjectRoot(typeof flags.dir === 'string' ? flags.dir : undefined);
	const { indexPath } = getLocalRepoPaths(projectRoot);
	const rows = readLocalIndex(indexPath);

	console.log(`OAKe Local Identity:`);
	console.log(`  OAKE_HOME : ${oakeHome}`);
	if (fs.existsSync(keyPath)) {
		const keyData = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
		console.log(`  Pubkey    : ${keyData.pubkey}`);
	} else {
		console.log(`  Pubkey    : (not initialized — run 'oake init')`);
	}
	console.log(`  Config    : ${fs.existsSync(configPath) ? configPath : '(not created)'}`);
	console.log(`  Local Repo: ${path.join(projectRoot, '.oake')} (${rows.length} entries)`);
	console.log(`  Endpoint  : ${endpoint}`);

	if (flags.offline) return;

	try {
		const res = await fetchWithTimeout(`${endpoint}/v1/status`, {}, 3_000);
		if (!res.ok) {
			console.log(`Witness Status: HTTP ${res.status} (${res.statusText})`);
			return;
		}
		const status = await res.json();
		console.log(`Witness Server Status (${status.calendar_node}, ${status.protocol}):`);
		console.log(
			`  Ledger     : total=${status.ledger?.total_entries}, upgraded=${status.ledger?.upgraded_entries}, provisional=${status.ledger?.provisional_entries}, chain_valid=${status.ledger?.chain_valid}`
		);
		console.log(
			`  Aggregator : batch=${status.aggregator?.active_batch_id}, pending_k=${status.aggregator?.pending_leaves_k}, settled=${status.aggregator?.settled_batches_count}`
		);
	} catch (err) {
		console.log(`Witness Status: unreachable (${err instanceof Error ? err.message : String(err)})`);
	}
}

function cmdInstall(flags) {
	if (!flags.git) {
		throw new Error('Usage: oake install --git [--dir <repo_dir>]');
	}
	const repoDir = path.resolve(typeof flags.dir === 'string' ? flags.dir : process.cwd());
	const gitDir = path.join(repoDir, '.git');
	if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) {
		throw new Error(`Not a git repository (missing .git directory): ${repoDir}`);
	}

	const hooksDir = path.join(gitDir, 'hooks');
	ensureDir(hooksDir);
	const hookPath = path.join(hooksDir, 'post-commit');
	const cliScriptPath = path.resolve(new URL(import.meta.url).pathname);

	const hookContent = `#!/usr/bin/env bash
# OAKe post-commit hook (installed by: oake install --git)
# Hash tracked files at this commit locally; anchor standalone.
OAKE_BIN="oake"
if ! command -v oake >/dev/null 2>&1; then
  OAKE_BIN="node ${cliScriptPath}"
fi
($OAKE_BIN capture --source git-hook --commit "$(git rev-parse HEAD)" \\
             --repo "$(basename "$(git rev-parse --show-toplevel)")" >/dev/null 2>&1 &)
`;

	fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
	fs.chmodSync(hookPath, 0o755);
	console.log(`Installed non-blocking OAKe post-commit hook at ${hookPath}`);
}

async function main() {
	const [command, ...rest] = process.argv.slice(2);
	const { positionals, flags } = parseArgs(rest);

	if (!command || command === 'help' || command === '--help' || flags.help) {
		printUsage();
		return;
	}

	const oakeHome = getOakeHome();

	switch (command) {
		case 'init':
		case 'keygen':
			await cmdInit(flags, oakeHome);
			break;
		case 'hash':
			cmdHash(positionals, flags);
			break;
		case 'capture':
			await cmdCapture(positionals, flags, oakeHome);
			break;
		case 'log':
			cmdLog(flags);
			break;
		case 'push':
			await cmdPush(positionals, flags, oakeHome);
			break;
		case 'upgrade':
			await cmdUpgrade(positionals, flags, oakeHome);
			break;
		case 'proof':
			await cmdProof(positionals, flags, oakeHome);
			break;
		case 'verify':
			await cmdVerify(positionals, flags, oakeHome);
			break;
		case 'settle':
			await cmdSettle(flags, oakeHome);
			break;
		case 'status':
			await cmdStatus(flags, oakeHome);
			break;
		case 'install':
			cmdInstall(flags);
			break;
		default:
			throw new Error(`Unknown command: ${command}`);
	}
}

main().catch((err) => {
	console.error(`oake error: ${err instanceof Error ? err.message : String(err)}`);
	process.exit(1);
});

import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

const REPO_ROOT = process.cwd();
const CLI_PATH = path.join(REPO_ROOT, 'cli', 'oake.mjs');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

function runCli(args: string[], env: Record<string, string | undefined> = {}, cwd = REPO_ROOT): string {
	return execFileSync('node', [CLI_PATH, ...args], {
		cwd,
		env: { ...process.env, ...env },
		encoding: 'utf8'
	});
}

function buildMinimalZip(entries: Array<{ name: string; data: Buffer; compress?: boolean }>): Buffer {
	const localParts: Buffer[] = [];
	const centralParts: Buffer[] = [];
	let offset = 0;

	for (const entry of entries) {
		const nameBuf = Buffer.from(entry.name, 'utf8');
		const method = entry.compress ? 8 : 0;
		const payload = entry.compress ? zlib.deflateRawSync(entry.data) : entry.data;
		const crc = crc32(entry.data);

		const localHeader = Buffer.alloc(30);
		localHeader.writeUInt32LE(0x04034b50, 0);
		localHeader.writeUInt16LE(20, 4);
		localHeader.writeUInt16LE(0, 6);
		localHeader.writeUInt16LE(method, 8);
		localHeader.writeUInt16LE(0, 10);
		localHeader.writeUInt16LE(0, 12);
		localHeader.writeUInt32LE(crc >>> 0, 14);
		localHeader.writeUInt32LE(payload.length, 18);
		localHeader.writeUInt32LE(entry.data.length, 22);
		localHeader.writeUInt16LE(nameBuf.length, 26);
		localHeader.writeUInt16LE(0, 28);

		localParts.push(localHeader, nameBuf, payload);

		const cdHeader = Buffer.alloc(46);
		cdHeader.writeUInt32LE(0x02014b50, 0);
		cdHeader.writeUInt16LE(20, 4);
		cdHeader.writeUInt16LE(20, 6);
		cdHeader.writeUInt16LE(0, 8);
		cdHeader.writeUInt16LE(method, 10);
		cdHeader.writeUInt16LE(0, 12);
		cdHeader.writeUInt16LE(0, 14);
		cdHeader.writeUInt32LE(crc >>> 0, 16);
		cdHeader.writeUInt32LE(payload.length, 20);
		cdHeader.writeUInt32LE(entry.data.length, 24);
		cdHeader.writeUInt16LE(nameBuf.length, 28);
		cdHeader.writeUInt16LE(0, 30);
		cdHeader.writeUInt16LE(0, 32);
		cdHeader.writeUInt16LE(0, 34);
		cdHeader.writeUInt16LE(0, 36);
		cdHeader.writeUInt32LE(0, 38);
		cdHeader.writeUInt32LE(offset, 42);

		centralParts.push(cdHeader, nameBuf);
		offset += localHeader.length + nameBuf.length + payload.length;
	}

	const centralDir = Buffer.concat(centralParts);
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(centralDir.length, 12);
	eocd.writeUInt32LE(offset, 16);
	eocd.writeUInt16LE(0, 20);

	return Buffer.concat([...localParts, centralDir, eocd]);
}

function crc32(buf: Buffer): number {
	let crc = 0xffffffff;
	for (let i = 0; i < buf.length; i++) {
		crc ^= buf[i];
		for (let j = 0; j < 8; j++) {
			crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
		}
	}
	return (crc ^ 0xffffffff) >>> 0;
}

after(() => {
	for (const dir of tempDirs) {
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

/** `oake verify` exits 2 when nothing failed but no timestamp could be verified. */
function expectIncomplete(run: () => string): string {
	try {
		run();
	} catch (err) {
		const e = err as { status?: number; stdout?: string };
		assert.equal(e.status, 2);
		return String(e.stdout);
	}
	assert.fail('expected an INCOMPLETE verdict (exit 2)');
}

describe('OAKe CLI (cli/oake.mjs)', () => {
	it('init creates id_ed25519.json (0600) and config.yaml', () => {
		const oakeHome = path.join(makeTempDir('oake-init-'), 'oake-home');
		const out = runCli(['init'], { OAKE_HOME: oakeHome });

		const keyPath = path.join(oakeHome, 'id_ed25519.json');
		const configPath = path.join(oakeHome, 'config.yaml');
		assert.equal(fs.existsSync(keyPath), true);
		assert.equal(fs.existsSync(configPath), true);

		const keyData = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
		assert.match(keyData.pubkey, /^ed25519:[0-9a-f]{64}$/);
		assert.equal(typeof keyData.privateKeyPem, 'string');
		assert.ok(keyData.privateKeyPem.includes('BEGIN PRIVATE KEY'));
		assert.ok(!Number.isNaN(Date.parse(keyData.createdAt)));

		const mode = fs.statSync(keyPath).mode & 0o777;
		assert.equal(mode, 0o600);

		const configYaml = fs.readFileSync(configPath, 'utf8');
		assert.ok(configYaml.includes('hash_paths: true'));
		assert.ok(configYaml.includes('snapshot_interval: 24h'));
		assert.ok(out.includes(keyData.pubkey));
	});

	it('hash computes canonical SHA-256 digests for .tex, text-normalized/v1, and ipynb-cells/v1', () => {
		const workDir = makeTempDir('oake-hash-');

		// 1. .tex (raw-bytes/v1 default)
		const texPath = path.join(workDir, 'lemma.tex');
		const texContent = '\\documentclass{article}\n\\begin{document}Proof\\end{document}\n';
		fs.writeFileSync(texPath, texContent, 'utf8');
		const expectedTexHash =
			'sha256:' + crypto.createHash('sha256').update(Buffer.from(texContent, 'utf8')).digest('hex');
		const texOut = runCli(['hash', texPath]).trim();
		assert.equal(texOut, expectedTexHash);

		// 2. .txt with text-normalized/v1 (CRLF + trailing whitespace vs clean LF)
		const txtA = path.join(workDir, 'notes_a.txt');
		const txtB = path.join(workDir, 'notes_b.txt');
		fs.writeFileSync(txtA, 'line one   \r\nline two\t \r\n', 'utf8');
		fs.writeFileSync(txtB, 'line one\nline two\n', 'utf8');
		const hashA = runCli(['hash', txtA, '--canon', 'text-normalized/v1']).trim();
		const hashB = runCli(['hash', txtB, '--canon', 'text-normalized/v1']).trim();
		assert.match(hashA, /^sha256:[0-9a-f]{64}$/);
		assert.equal(hashA, hashB);

		// 3. .ipynb with ipynb-cells/v1 (ignores execution_count, outputs, metadata)
		const nbA = path.join(workDir, 'exp_a.ipynb');
		const nbB = path.join(workDir, 'exp_b.ipynb');
		fs.writeFileSync(
			nbA,
			JSON.stringify({
				nbformat: 4,
				metadata: { kernelspec: { name: 'python3' } },
				cells: [
					{ cell_type: 'markdown', metadata: { collapsed: true }, source: ['# Title\n', 'Notes'] },
					{
						cell_type: 'code',
						execution_count: 1,
						outputs: [{ output_type: 'stream', text: ['42\n'] }],
						metadata: {},
						source: ['x = 6 * 7\n', 'print(x)']
					}
				]
			}),
			'utf8'
		);
		fs.writeFileSync(
			nbB,
			JSON.stringify({
				nbformat: 4,
				metadata: { kernelspec: { name: 'conda-env-other' }, timestamp: 999999 },
				cells: [
					{ cell_type: 'markdown', metadata: {}, source: '# Title\nNotes' },
					{
						cell_type: 'code',
						execution_count: 99,
						outputs: [],
						metadata: { scrolled: true },
						source: ['x = 6 * 7\n', 'print(x)']
					}
				]
			}),
			'utf8'
		);
		const nbHashA = runCli(['hash', nbA]).trim();
		const nbHashB = runCli(['hash', nbB, '--canon', 'ipynb-cells/v1']).trim();
		assert.match(nbHashA, /^sha256:[0-9a-f]{64}$/);
		assert.equal(nbHashA, nbHashB);
	});

	it('capture --dry-run never transmits raw secret content or plaintext paths and produces a valid Ed25519 signature', () => {
		const oakeHome = path.join(makeTempDir('oake-home-'), 'oake');
		const workDir = makeTempDir('oake-secret-');
		const secretFilename = 'top-secret-millennium-breakthrough.tex';
		const secretText =
			'CONFIDENTIAL_SECRET_PROOF_CONTENT_DO_NOT_LEAK_NS_SMOOTHNESS_LEMMA_2026';
		const secretPath = path.join(workDir, secretFilename);
		fs.writeFileSync(secretPath, secretText, 'utf8');

		const stdout = runCli(
			['capture', secretPath, '--repo', 'ns-research', '--dry-run'],
			{ OAKE_HOME: oakeHome },
			workDir
		);

		// Privacy invariant checks on raw serialized outbound JSON
		assert.equal(stdout.includes(secretText), false);
		assert.equal(stdout.includes('CONFIDENTIAL_SECRET'), false);
		assert.equal(stdout.includes(secretFilename), false);

		const payload = JSON.parse(stdout);
		const keyData = JSON.parse(fs.readFileSync(path.join(oakeHome, 'id_ed25519.json'), 'utf8'));

		const expectedHash =
			'sha256:' + crypto.createHash('sha256').update(Buffer.from(secretText, 'utf8')).digest('hex');
		const expectedPathHint =
			'sha256:' + crypto.createHash('sha256').update(Buffer.from(secretFilename, 'utf8')).digest('hex');

		assert.equal(payload.user_pubkey, keyData.pubkey);
		assert.equal(payload.artifact_hash, expectedHash);
		assert.equal(payload.canonicalization, 'raw-bytes/v1');
		assert.equal(payload.capture_source, 'cli');
		assert.equal(payload.metadata.repo, 'ns-research');
		assert.equal(payload.metadata.path_hint, expectedPathHint);
		assert.equal(payload.metadata.artifact_kind, 'latex');
		assert.equal(payload.metadata.byte_size, Buffer.byteLength(secretText, 'utf8'));

		// Verify Ed25519 signature locally
		assert.match(payload.signature, /^ed25519:[0-9a-f]{128}$/);
		const rawPub = Buffer.from(payload.user_pubkey.slice('ed25519:'.length), 'hex');
		const pubKeyObj = crypto.createPublicKey({
			key: Buffer.concat([SPKI_ED25519_PREFIX, rawPub]),
			format: 'der',
			type: 'spki'
		});
		const signingPayload = `${payload.artifact_hash}|${payload.canonicalization}|${payload.client_ts}`;
		const sigBytes = Buffer.from(payload.signature.slice('ed25519:'.length), 'hex');
		assert.equal(
			crypto.verify(null, Buffer.from(signingPayload, 'utf8'), pubKeyObj, sigBytes),
			true
		);
	});

	it('capture --dry-run skips ignored directories and extensions when walking a directory', () => {
		const oakeHome = path.join(makeTempDir('oake-dir-home-'), 'oake');
		const workDir = makeTempDir('oake-dir-');

		fs.mkdirSync(path.join(workDir, '.git'));
		fs.mkdirSync(path.join(workDir, 'node_modules'));
		fs.mkdirSync(path.join(workDir, '.oake'));
		fs.writeFileSync(path.join(workDir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
		fs.writeFileSync(path.join(workDir, 'node_modules', 'pkg.js'), 'module.exports = 1;\n');
		fs.writeFileSync(path.join(workDir, '.oake', 'cache.json'), '{}');
		fs.writeFileSync(path.join(workDir, 'build.log'), 'log line');
		fs.writeFileSync(path.join(workDir, 'paper.aux'), 'aux line');
		fs.writeFileSync(path.join(workDir, 'paper.pdf'), '%PDF-1.4');
		fs.writeFileSync(path.join(workDir, 'main.py'), 'print("hello")\n');

		const stdout = runCli(['capture', workDir, '--dry-run'], { OAKE_HOME: oakeHome }, workDir);
		const payload = JSON.parse(stdout);
		assert.equal(Array.isArray(payload), false);
		assert.equal(
			payload.artifact_hash,
			'sha256:' + crypto.createHash('sha256').update('print("hello")\n').digest('hex')
		);
	});

	it('install --git creates an executable .git/hooks/post-commit hook', () => {
		const repoDir = makeTempDir('oake-git-');
		fs.mkdirSync(path.join(repoDir, '.git'));

		runCli(['install', '--git', '--dir', repoDir]);

		const hookPath = path.join(repoDir, '.git', 'hooks', 'post-commit');
		assert.equal(fs.existsSync(hookPath), true);

		const mode = fs.statSync(hookPath).mode;
		assert.ok((mode & 0o111) !== 0, 'post-commit hook must be executable');

		const hookContent = fs.readFileSync(hookPath, 'utf8');
		assert.ok(hookContent.startsWith('#!/usr/bin/env bash'));
		assert.ok(hookContent.includes('capture --source git-hook'));
	});

	it('verify --offline validates a .oake.zip bundle against original --file locally', () => {
		const oakeHome = path.join(makeTempDir('oake-verify-home-'), 'oake');
		const workDir = makeTempDir('oake-verify-');
		runCli(['init'], { OAKE_HOME: oakeHome });

		const artifactPath = path.join(workDir, 'theorem.tex');
		fs.writeFileSync(artifactPath, '\\section{Main Result}\n', 'utf8');

		const dryRunJson = JSON.parse(
			runCli(['capture', artifactPath, '--dry-run'], { OAKE_HOME: oakeHome }, workDir)
		);

		const digestBytes = Buffer.from(dryRunJson.artifact_hash.slice('sha256:'.length), 'hex');
		// Construct valid OTS v1 proof: magic + v1 + sha256(0x08) + 32B digest + append(0xf1) + sha256(0x08) + pending attestation
		const otsBytes = Buffer.concat([
			OTS_MAGIC,
			Buffer.from([0x01, 0x08]),
			digestBytes,
			Buffer.from([0xf1, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x08, 0x00]),
			Buffer.from('83dfe30d2ef90c8e', 'hex'),
			Buffer.from([0x03]),
			Buffer.from('cal', 'utf8')
		]);

		const entry = {
			entry_id: '01J9Z7K4TEST00000000000001',
			...dryRunJson,
			received_ts: new Date().toISOString()
		};

		const zipBytes = buildMinimalZip([
			{ name: 'entry.json', data: Buffer.from(JSON.stringify(entry, null, 2)), compress: true },
			{ name: 'proof.ots', data: otsBytes, compress: false },
			{ name: 'rfc3161/eu-qtsa-1.tsr', data: Buffer.from('{"mock":"tsr"}'), compress: true },
			{ name: 'VERIFY.md', data: Buffer.from('# Independent Verification\n'), compress: true }
		]);

		const bundlePath = path.join(workDir, 'test.oake.zip');
		fs.writeFileSync(bundlePath, zipBytes);

		const verifyOut = expectIncomplete(() =>
runCli(['verify', bundlePath, '--file', artifactPath, '--offline']));
		assert.ok(verifyOut.includes('VALID (Ed25519)'));
		assert.ok(verifyOut.includes('local --file  : MATCHES'));
		assert.ok(verifyOut.includes('header OK, digest OK, steps=2'));
	});

	it('capture --offline creates local .oake/proofs/<entry_id>.oake.zip and hash-chained .oake/index.jsonl', () => {
		const oakeHome = path.join(makeTempDir('oake-local-home-'), 'oake');
		const workDir = makeTempDir('oake-local-proj-');
		runCli(['init'], { OAKE_HOME: oakeHome }, workDir);

		const fileA = path.join(workDir, 'paper.tex');
		const fileB = path.join(workDir, 'analysis.py');
		fs.writeFileSync(fileA, '\\title{Local-First Provenance}\n', 'utf8');
		fs.writeFileSync(fileB, 'print("reproducible")\n', 'utf8');

		const capA = runCli(['capture', fileA, '--offline'], { OAKE_HOME: oakeHome }, workDir);
		const capB = runCli(['capture', fileB, '--offline'], { OAKE_HOME: oakeHome }, workDir);

		assert.ok(capA.includes('ots=provisional'));
		assert.ok(capB.includes('ots=provisional'));

		const indexPath = path.join(workDir, '.oake', 'index.jsonl');
		assert.equal(fs.existsSync(indexPath), true);

		const rows = fs
			.readFileSync(indexPath, 'utf8')
			.trim()
			.split('\n')
			.map((line) => JSON.parse(line));
		assert.equal(rows.length, 2);

		assert.equal(rows[0].sequence, 1);
		assert.equal(
			rows[0].prev_entry_hash,
			'sha256:0000000000000000000000000000000000000000000000000000000000000000'
		);
		assert.match(rows[0].entry_hash, /^sha256:[0-9a-f]{64}$/);
		assert.equal(rows[0].entry_id.length, 26);
		assert.equal(rows[0].ots_status, 'provisional');
		assert.equal(rows[0].published_to, null);

		assert.equal(rows[1].sequence, 2);
		assert.equal(rows[1].prev_entry_hash, rows[0].entry_hash);
		assert.match(rows[1].entry_hash, /^sha256:[0-9a-f]{64}$/);

		const bundleAPath = path.join(workDir, rows[0].bundle_path);
		const bundleBPath = path.join(workDir, rows[1].bundle_path);
		assert.equal(fs.existsSync(bundleAPath), true);
		assert.equal(fs.existsSync(bundleBPath), true);
	});

	it('oake log displays local hash-chained provenance history and verify succeeds 100% standalone', () => {
		const oakeHome = path.join(makeTempDir('oake-log-home-'), 'oake');
		const workDir = makeTempDir('oake-log-proj-');
		runCli(['init'], { OAKE_HOME: oakeHome }, workDir);

		const artifactPath = path.join(workDir, 'proof-draft.tex');
		fs.writeFileSync(artifactPath, '\\begin{proof}Q.E.D.\\end{proof}\n', 'utf8');

		runCli(['capture', artifactPath, '--offline'], { OAKE_HOME: oakeHome }, workDir);

		const indexPath = path.join(workDir, '.oake', 'index.jsonl');
		const [row] = fs
			.readFileSync(indexPath, 'utf8')
			.trim()
			.split('\n')
			.map((line) => JSON.parse(line));

		const logOut = runCli(['log', '--dir', workDir], { OAKE_HOME: oakeHome }, workDir);
		assert.ok(logOut.includes('#1'));
		assert.ok(logOut.includes(row.entry_id));
		assert.ok(logOut.includes(row.artifact_hash));
		assert.ok(logOut.includes('ots=provisional'));
		assert.ok(logOut.includes('published_to=local-only'));
		assert.ok(logOut.includes('Chain integrity: VALID'));

		const bundlePath = path.join(workDir, '.oake', 'proofs', `${row.entry_id}.oake.zip`);

		// Verify with --offline
		const verifyOfflineOut = expectIncomplete(() =>
runCli(
			['verify', bundlePath, '--file', artifactPath, '--offline'],
			{ OAKE_HOME: oakeHome },
			workDir
		));
		assert.ok(verifyOfflineOut.includes(`entry_id      : ${row.entry_id}`));
		assert.ok(verifyOfflineOut.includes('VALID (Ed25519)'));
		assert.ok(verifyOfflineOut.includes('local --file  : MATCHES'));
		assert.ok(verifyOfflineOut.includes('header OK, digest OK'));
		assert.ok(verifyOfflineOut.includes('VERIFY.md     : present'));

		// Verify WITHOUT --offline also defaults to 100% standalone local verification
		const verifyDefaultOut = expectIncomplete(() =>
runCli(
			['verify', bundlePath, '--file', artifactPath],
			{ OAKE_HOME: oakeHome },
			workDir
		));
		assert.ok(verifyDefaultOut.includes('local --file  : MATCHES'));
		assert.ok(verifyDefaultOut.includes('VALID (Ed25519)'));

		// Tampered artifact must fail verification with non-zero exit code
		const tamperedPath = path.join(workDir, 'tampered.tex');
		fs.writeFileSync(tamperedPath, '\\begin{proof}Tampered\\end{proof}\n', 'utf8');
		assert.throws(() => {
			runCli(
				['verify', bundlePath, '--file', tamperedPath, '--offline'],
				{ OAKE_HOME: oakeHome },
				workDir
			);
		});
	});
});

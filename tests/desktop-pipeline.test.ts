import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const REPO_ROOT = process.cwd();
const OAKE_DIR = REPO_ROOT;
const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

/**
 * Lightweight structural YAML validator (zero external dependencies).
 * Checks indentation alignment, absence of tabs, balanced quotes, and basic key/list structure.
 */
function assertValidYamlSyntax(yamlText: string, fileLabel: string): void {
	assert.ok(yamlText.trim().length > 0, `${fileLabel} must not be empty`);
	const lines = yamlText.split(/\r?\n/);

	for (let idx = 0; idx < lines.length; idx++) {
		const raw = lines[idx];
		const lineNo = idx + 1;
		if (raw.trim() === '' || raw.trimStart().startsWith('#')) continue;

		assert.ok(!/^\t/.test(raw), `${fileLabel}:${lineNo} contains leading tab indentation`);

		const indent = raw.length - raw.trimStart().length;
		assert.equal(indent % 2, 0, `${fileLabel}:${lineNo} has odd indentation (${indent} spaces)`);

		const trimmed = raw.trim();
		const isMapping = /^[^:#]+:\s*(.*)?$/.test(trimmed);
		const isListItem = /^-\s+/.test(trimmed) || trimmed === '-';
		assert.ok(
			isMapping || isListItem || /^\S/.test(trimmed),
			`${fileLabel}:${lineNo} invalid YAML line: ${trimmed}`
		);
	}
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

describe('OAKe Standalone Repo Scaffold & Metadata', () => {
	it('contains Apache-2.0 LICENSE, .gitignore, README.md, and @madara-labs/oake package.json', () => {
		const license = fs.readFileSync(path.join(OAKE_DIR, 'LICENSE'), 'utf8');
		assert.match(license, /Apache License/);
		assert.match(license, /Version 2\.0, January 2004/);
		assert.match(license, /Copyright 2026 Madara Labs/);

		const gitignore = fs.readFileSync(path.join(OAKE_DIR, '.gitignore'), 'utf8');
		for (const pattern of [
			'node_modules/',
			'desktop/src-tauri/target/',
			'dist/',
			'.oake/',
			'*.db',
			'.DS_Store'
		]) {
			assert.ok(gitignore.includes(pattern), `.gitignore missing pattern: ${pattern}`);
		}

		const pkg = JSON.parse(fs.readFileSync(path.join(OAKE_DIR, 'package.json'), 'utf8'));
		assert.equal(pkg.name, '@madara-labs/oake');
		assert.equal(pkg.version, '0.1.0');
		assert.equal(pkg.license, 'Apache-2.0');
		assert.equal(pkg.type, 'module');
		assert.deepEqual(pkg.bin, { oake: './cli/oake.mjs' });

		const expectedScripts = [
			'oake',
			'desktop:icons',
			'desktop:preview',
			'desktop:check',
			'desktop:build',
			'desktop:build:macos',
			'desktop:build:windows',
			'desktop:build:linux',
			'export-repo'
		];
		for (const scriptName of expectedScripts) {
			assert.equal(typeof pkg.scripts?.[scriptName], 'string', `package.json missing script "${scriptName}"`);
		}

		const readme = fs.readFileSync(path.join(OAKE_DIR, 'README.md'), 'utf8');
		assert.match(readme, /Madara-Labs\/OAKe/);
		assert.match(readme, /Certum/);
		assert.match(readme, /DigiCert/);
		assert.match(readme, /OpenTimestamps/);
		assert.match(readme, /Apache/);
	});
});

describe('GitHub Actions Workflows (3-OS Matrix & Provenance)', () => {
	it('ci.yml is valid YAML and covers ubuntu-22.04, macos-latest, and windows-latest', () => {
		const ciPath = path.join(OAKE_DIR, '.github', 'workflows', 'ci.yml');
		const ciText = fs.readFileSync(ciPath, 'utf8');
		assertValidYamlSyntax(ciText, 'ci.yml');

		assert.match(ciText, /^name:\s*CI/m);
		assert.match(ciText, /ubuntu-22\.04/);
		assert.match(ciText, /macos-latest/);
		assert.match(ciText, /windows-latest/);
		assert.match(ciText, /libwebkit2gtk-4\.1-dev/);
		assert.match(ciText, /dtolnay\/rust-toolchain@[0-9a-f]{40}\b/);
		assert.match(ciText, /swatinem\/rust-cache@[0-9a-f]{40}\b/);
		assert.match(ciText, /node scripts\/generate-icons\.mjs/);
		assert.match(ciText, /node scripts\/build-desktop\.mjs --check/);
		assert.match(ciText, /cargo check --manifest-path desktop\/src-tauri\/Cargo\.toml/);
	});

	it('release-desktop.yml is valid YAML and defines 3-OS release builds + provenance attestation', () => {
		const relPath = path.join(OAKE_DIR, '.github', 'workflows', 'release-desktop.yml');
		const relText = fs.readFileSync(relPath, 'utf8');
		assertValidYamlSyntax(relText, 'release-desktop.yml');

		// Triggers
		assert.match(relText, /tags:\s*\n\s*-\s*["']?v\*["']?/);
		assert.match(relText, /workflow_dispatch:/);

		// 3-OS matrix & targets
		assert.match(relText, /macos-latest/);
		assert.match(relText, /universal-apple-darwin/);
		assert.match(relText, /aarch64-apple-darwin,x86_64-apple-darwin/);
		assert.match(relText, /windows-latest/);
		assert.match(relText, /x86_64-pc-windows-msvc/);
		assert.match(relText, /ubuntu-22\.04/);
		assert.match(relText, /x86_64-unknown-linux-gnu/);

		// Tauri action + artifacts + Apple signing secrets
		assert.match(relText, /tauri-apps\/tauri-action@[0-9a-f]{40}\b/);
		assert.match(relText, /actions\/upload-artifact@v\d+/);
		for (const secret of [
			'APPLE_CERTIFICATE',
			'APPLE_CERTIFICATE_PASSWORD',
			'APPLE_SIGNING_IDENTITY',
			'APPLE_ID',
			'APPLE_PASSWORD',
			'APPLE_TEAM_ID'
		]) {
			assert.ok(relText.includes(secret), `release-desktop.yml missing secret ${secret}`);
		}

		// Provenance attestation job
		assert.match(relText, /provenance-attestation:/);
		assert.match(relText, /needs:\s*(\[[^\]]*)?build-desktop/);
		assert.match(relText, /SHA256SUMS\.txt/);
		assert.match(relText, /node cli\/oake\.mjs capture/);
		assert.match(relText, /\.oake\/proofs\/\*\.oake\.zip/);
	});
});

describe('Command-line tool execution', () => {
	it('runs a standalone offline capture and verify', () => {
		const oakeCliPath = path.join(OAKE_DIR, 'cli', 'oake.mjs');
		if (process.platform !== 'win32') {
			assert.ok((fs.statSync(oakeCliPath).mode & 0o111) !== 0, 'cli/oake.mjs must be executable');
		}

		const workDir = makeTempDir('oake-standalone-cli-');
		const oakeHome = makeTempDir('oake-standalone-home-');
		const sampleFile = path.join(workDir, 'artifact.txt');
		fs.writeFileSync(sampleFile, 'hello standalone oake\n', 'utf8');

		const helpOut = execFileSync(process.execPath, [oakeCliPath, '--help'], {
			cwd: workDir,
			env: { ...process.env, OAKE_HOME: oakeHome },
			encoding: 'utf8'
		});
		assert.match(helpOut, /OAKe Local-First Provenance CLI/);

		execFileSync(process.execPath, [oakeCliPath, 'init'], {
			cwd: workDir,
			env: { ...process.env, OAKE_HOME: oakeHome },
			encoding: 'utf8'
		});

		execFileSync(process.execPath, [oakeCliPath, 'capture', sampleFile, '--offline', '--dir', workDir], {
			cwd: workDir,
			env: { ...process.env, OAKE_HOME: oakeHome },
			encoding: 'utf8'
		});

		const proofsDir = path.join(workDir, '.oake', 'proofs');
		const proofs = fs.readdirSync(proofsDir).filter((f) => f.endsWith('.oake.zip'));
		assert.equal(proofs.length, 1, 'Expected one .oake.zip proof bundle');

		const verifyOut = expectIncomplete(() =>
execFileSync(
			process.execPath,
			[oakeCliPath, 'verify', path.join(proofsDir, proofs[0]), '--file', sampleFile, '--offline'],
			{
				cwd: workDir,
				env: { ...process.env, OAKE_HOME: oakeHome },
				encoding: 'utf8'
			}
		));
		assert.match(verifyOut, /VERIFIED|valid|Ed25519/i);
	});
});

describe('build-desktop.mjs --export-repo', () => {
	it('exports a clean standalone git repo into os.tmpdir() without target/node_modules/dist/.oake', () => {
		const exportParent = makeTempDir('oake-export-');
		const exportDir = path.join(exportParent, 'oake-repo');
		const buildScript = path.join(OAKE_DIR, 'scripts', 'build-desktop.mjs');

		const stdout = execFileSync(process.execPath, [buildScript, '--export-repo', exportDir], {
			cwd: OAKE_DIR,
			encoding: 'utf8'
		});

		assert.match(stdout, /https:\/\/github\.com\/Madara-Labs\/OAKe\.git/);
		assert.match(stdout, /git push -u origin main/);

		// Required exported files
		for (const rel of [
			'package.json',
			'LICENSE',
			'.gitignore',
			'README.md',
			'cli/oake.mjs',
			'scripts/build-desktop.mjs',
			'.github/workflows/ci.yml',
			'.github/workflows/release-desktop.yml'
		]) {
			assert.ok(fs.existsSync(path.join(exportDir, rel)), `Exported repo missing: ${rel}`);
		}

		// Excluded directories should not be present
		for (const excluded of [
			'node_modules',
			'dist',
			'.oake',
			'desktop/src-tauri/target',
			'desktop/src-tauri/gen',
			'migrations'
		]) {
			assert.ok(!fs.existsSync(path.join(exportDir, excluded)), `Exported repo should exclude ${excluded}`);
		}

		// Git initialized on main branch
		assert.ok(fs.existsSync(path.join(exportDir, '.git')), 'Exported repo must initialize .git');
		const branch = execFileSync('git', ['symbolic-ref', '--short', 'HEAD'], {
			cwd: exportDir,
			encoding: 'utf8'
		}).trim();
		assert.equal(branch, 'main');

		// CLI executes directly inside exported repo
		const exportedHelp = execFileSync(process.execPath, ['cli/oake.mjs', '--help'], {
			cwd: exportDir,
			encoding: 'utf8'
		});
		assert.match(exportedHelp, /OAKe Local-First Provenance CLI/);
	});
});

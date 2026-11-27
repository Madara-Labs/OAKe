#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const OAKE_ROOT = path.resolve(__dirname, '..');

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const REQUIRED_PNG_ICONS = ['32x32.png', '128x128.png', '128x128@2x.png', 'icon.png'];
const REQUIRED_BUNDLE_TARGETS = ['msi', 'nsis', 'dmg', 'app', 'appimage', 'deb', 'rpm'];
const REQUIRED_WORKFLOW_RUNNERS = ['macos-latest', 'windows-latest', 'ubuntu-22.04'];
const INSTALLER_EXTENSIONS = ['.dmg', '.app.tar.gz', '.msi', '.exe', '.appimage', '.deb', '.rpm'];

const EXPORT_EXCLUDE_DIRS = new Set(['node_modules', 'target', 'dist', '.oake', '.git', 'gen', 'migrations']);
const EXPORT_EXCLUDE_FILES = new Set(['.DS_Store']);

function printHelp() {
	console.log(`OAKe Cross-Platform Desktop Build & Release Pipeline

Usage:
  node scripts/build-desktop.mjs --check
  node scripts/build-desktop.mjs --dry-run
  node scripts/build-desktop.mjs [--platform current|macos|windows|linux] [--universal] [--offline]
  node scripts/build-desktop.mjs --export-repo <target_dir>

Options:
  --check, --dry-run       Validate icons (RGBA PNG/.ico/.icns), tauri.conf.json, Cargo/Rust files,
                           UI assets, and 3-OS GitHub Actions workflow, then print readiness matrix.
  --platform <os>          Target platform: current (default), macos, windows, or linux.
  --universal              Build macOS Universal binary (aarch64 + x86_64 via universal-apple-darwin).
  --offline                Pass --offline to 'oake capture' when stamping SHA256SUMS.txt.
  --export-repo <dir>      Export standalone @madara-labs/oake repo to <dir> and run git init -b main.
  -h, --help               Show this help message.
`);
}

function parseCliArgs(argv) {
	const opts = {
		check: false,
		platform: 'current',
		universal: false,
		offline: false,
		exportRepo: null,
		help: false
	};

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === '--help' || arg === '-h') {
			opts.help = true;
		} else if (arg === '--check' || arg === '--dry-run') {
			opts.check = true;
		} else if (arg === '--universal') {
			opts.universal = true;
		} else if (arg === '--offline') {
			opts.offline = true;
		} else if (arg === '--platform') {
			const val = argv[++i];
			if (!val) throw new Error('Missing value for --platform (expected current|macos|windows|linux)');
			opts.platform = val.toLowerCase();
		} else if (arg.startsWith('--platform=')) {
			opts.platform = arg.slice('--platform='.length).toLowerCase();
		} else if (arg === '--export-repo') {
			const val = argv[++i];
			if (!val) throw new Error('Missing <target_dir> for --export-repo');
			opts.exportRepo = val;
		} else if (arg.startsWith('--export-repo=')) {
			const val = arg.slice('--export-repo='.length);
			if (!val) throw new Error('Missing <target_dir> for --export-repo');
			opts.exportRepo = val;
		} else {
			throw new Error(`Unknown argument: ${arg}`);
		}
	}

	if (!['current', 'macos', 'windows', 'linux'].includes(opts.platform)) {
		throw new Error(`Invalid --platform "${opts.platform}". Expected current, macos, windows, or linux.`);
	}

	return opts;
}

function resolveCurrentPlatform() {
	if (process.platform === 'darwin') return 'macos';
	if (process.platform === 'win32') return 'windows';
	if (process.platform === 'linux') return 'linux';
	throw new Error(`Unsupported host OS: ${process.platform}`);
}

function commandExists(cmd, args = ['--version']) {
	try {
		const out = execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
		return { ok: true, output: out.trim() };
	} catch (err) {
		return { ok: false, output: err instanceof Error ? err.message : String(err) };
	}
}

function validatePngRgba(filePath) {
	const buf = fs.readFileSync(filePath);
	if (buf.length < 33) {
		throw new Error(`PNG too short (${buf.length} bytes): ${filePath}`);
	}
	if (!buf.subarray(0, 8).equals(PNG_SIGNATURE)) {
		throw new Error(`Invalid PNG signature: ${filePath}`);
	}
	const ihdrTag = buf.toString('ascii', 12, 16);
	if (ihdrTag !== 'IHDR') {
		throw new Error(`Missing IHDR chunk in PNG: ${filePath}`);
	}
	const width = buf.readUInt32BE(16);
	const height = buf.readUInt32BE(20);
	const bitDepth = buf[24];
	const colorType = buf[25];
	if (width === 0 || height === 0) {
		throw new Error(`Invalid PNG dimensions (${width}x${height}): ${filePath}`);
	}
	if (colorType !== 6) {
		throw new Error(
			`PNG must be RGBA (colorType === 6), got colorType=${colorType} (bitDepth=${bitDepth}) in ${filePath}`
		);
	}
	return { width, height, bitDepth, colorType };
}

function validateIco(filePath) {
	const buf = fs.readFileSync(filePath);
	if (buf.length < 6) {
		throw new Error(`ICO file too short: ${filePath}`);
	}
	const reserved = buf.readUInt16LE(0);
	const type = buf.readUInt16LE(2);
	const count = buf.readUInt16LE(4);
	if (reserved !== 0 || type !== 1 || count < 1) {
		throw new Error(`Invalid ICO header (reserved=${reserved}, type=${type}, count=${count}): ${filePath}`);
	}
	return { count, bytes: buf.length };
}

function validateIcns(filePath) {
	const buf = fs.readFileSync(filePath);
	if (buf.length < 8) {
		throw new Error(`ICNS file too short: ${filePath}`);
	}
	const magic = buf.toString('ascii', 0, 4);
	if (magic !== 'icns') {
		throw new Error(`Invalid ICNS magic "${magic}": ${filePath}`);
	}
	return { bytes: buf.length };
}

function ensureAndValidateIcons(errors) {
	const iconsDir = path.join(OAKE_ROOT, 'desktop', 'src-tauri', 'icons');
	const genScript = path.join(OAKE_ROOT, 'scripts', 'generate-icons.mjs');
	const requiredAll = [...REQUIRED_PNG_ICONS, 'icon.ico', 'icon.icns'];
	const missingBefore = requiredAll.filter((name) => !fs.existsSync(path.join(iconsDir, name)));

	if (missingBefore.length > 0 && fs.existsSync(genScript)) {
		console.log(`Icons missing (${missingBefore.join(', ')}); running scripts/generate-icons.mjs...`);
		execFileSync(process.execPath, [genScript], { cwd: OAKE_ROOT, stdio: 'inherit' });
	}

	if (!fs.existsSync(iconsDir)) {
		errors.push(`Missing icons directory: ${iconsDir}`);
		return { ok: false, count: 0 };
	}

	let validCount = 0;
	for (const pngName of REQUIRED_PNG_ICONS) {
		const p = path.join(iconsDir, pngName);
		if (!fs.existsSync(p)) {
			errors.push(`Missing required RGBA PNG icon: desktop/src-tauri/icons/${pngName}`);
			continue;
		}
		try {
			validatePngRgba(p);
			validCount++;
		} catch (err) {
			errors.push(err instanceof Error ? err.message : String(err));
		}
	}

	for (const entry of fs.readdirSync(iconsDir)) {
		if (entry.toLowerCase().endsWith('.png') && !REQUIRED_PNG_ICONS.includes(entry)) {
			try {
				validatePngRgba(path.join(iconsDir, entry));
				validCount++;
			} catch (err) {
				errors.push(err instanceof Error ? err.message : String(err));
			}
		}
	}

	const icoPath = path.join(iconsDir, 'icon.ico');
	if (!fs.existsSync(icoPath)) {
		errors.push('Missing required Windows icon: desktop/src-tauri/icons/icon.ico');
	} else {
		try {
			validateIco(icoPath);
			validCount++;
		} catch (err) {
			errors.push(err instanceof Error ? err.message : String(err));
		}
	}

	const icnsPath = path.join(iconsDir, 'icon.icns');
	if (!fs.existsSync(icnsPath)) {
		errors.push('Missing required macOS icon: desktop/src-tauri/icons/icon.icns');
	} else {
		try {
			validateIcns(icnsPath);
			validCount++;
		} catch (err) {
			errors.push(err instanceof Error ? err.message : String(err));
		}
	}

	return { ok: errors.length === 0, count: validCount };
}

function validateTauriConfig(errors) {
	const tauriDir = path.join(OAKE_ROOT, 'desktop', 'src-tauri');
	const confPath = path.join(tauriDir, 'tauri.conf.json');
	if (!fs.existsSync(confPath)) {
		errors.push('Missing desktop/src-tauri/tauri.conf.json');
		return null;
	}

	let conf;
	try {
		conf = JSON.parse(fs.readFileSync(confPath, 'utf8'));
	} catch (err) {
		errors.push(`Invalid JSON in desktop/src-tauri/tauri.conf.json: ${err instanceof Error ? err.message : String(err)}`);
		return null;
	}

	if (typeof conf.productName !== 'string' || conf.productName.trim() === '') {
		errors.push('tauri.conf.json missing non-empty "productName"');
	}
	if (typeof conf.version !== 'string' || conf.version.trim() === '') {
		errors.push('tauri.conf.json missing non-empty "version"');
	}
	if (typeof conf.identifier !== 'string' || !conf.identifier.includes('.')) {
		errors.push('tauri.conf.json missing valid reverse-DNS "identifier"');
	}

	const targetsRaw = conf.bundle?.targets;
	if (targetsRaw === 'all') {
		// Covers all platforms
	} else if (Array.isArray(targetsRaw)) {
		const normalized = new Set(targetsRaw.map((t) => String(t).toLowerCase()));
		const missingTargets = REQUIRED_BUNDLE_TARGETS.filter((t) => !normalized.has(t));
		if (missingTargets.length > 0) {
			errors.push(`tauri.conf.json bundle.targets missing: ${missingTargets.join(', ')}`);
		}
	} else {
		errors.push('tauri.conf.json missing "bundle.targets" ("all" or array covering msi,nsis,dmg,app,appimage,deb,rpm)');
	}

	const frontendDist = conf.build?.frontendDist ?? conf.frontendDist;
	if (typeof frontendDist !== 'string' || frontendDist.trim() === '') {
		errors.push('tauri.conf.json missing "build.frontendDist"');
	} else {
		const resolvedUiDir = path.resolve(tauriDir, frontendDist);
		const expectedUiDir = path.join(OAKE_ROOT, 'desktop', 'ui');
		if (frontendDist !== '../ui' && resolvedUiDir !== expectedUiDir) {
			errors.push(`tauri.conf.json build.frontendDist expected "../ui", got "${frontendDist}"`);
		}
		for (const asset of ['index.html', 'app.js', 'styles.css']) {
			const assetPath = path.join(resolvedUiDir, asset);
			if (!fs.existsSync(assetPath)) {
				errors.push(`Missing frontend UI asset in ${frontendDist}: ${asset}`);
			}
		}
	}

	return conf;
}

function validateCoreFilesAndWorkflow(errors) {
	const requiredFiles = [
		'desktop/src-tauri/Cargo.toml',
		'desktop/src-tauri/src/lib.rs',
		'cli/oake.mjs',
		'.github/workflows/release-desktop.yml'
	];

	for (const rel of requiredFiles) {
		const full = path.join(OAKE_ROOT, rel);
		if (!fs.existsSync(full)) {
			errors.push(`Missing required file: ${rel}`);
		}
	}

	const releaseWfPath = path.join(OAKE_ROOT, '.github', 'workflows', 'release-desktop.yml');
	if (fs.existsSync(releaseWfPath)) {
		const wfText = fs.readFileSync(releaseWfPath, 'utf8');
		for (const runner of REQUIRED_WORKFLOW_RUNNERS) {
			if (!wfText.includes(runner)) {
				errors.push(`release-desktop.yml missing 3-OS runner target: ${runner}`);
			}
		}
	}
}

function runCheck() {
	const errors = [];
	const iconStatus = ensureAndValidateIcons(errors);
	const tauriConf = validateTauriConfig(errors);
	validateCoreFilesAndWorkflow(errors);

	const cargoCheck = commandExists('cargo', ['--version']);
	const rustupCheck = commandExists('rustup', ['target', 'list', '--installed']);
	const installedTargets = rustupCheck.ok
		? rustupCheck.output.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
		: [];
	const tauriCargoCheck = commandExists('cargo', ['tauri', '--version']);
	const hostPlatform = resolveCurrentPlatform();

	console.log('\n=== OAKe Cross-Platform Desktop Build-Readiness Matrix ===');
	if (tauriConf) {
		console.log(`Product : ${tauriConf.productName} v${tauriConf.version} (${tauriConf.identifier})`);
	}
	console.log(`Icons   : ${iconStatus.count} validated (RGBA PNG + .ico + .icns)`);
	console.log(`Host OS : ${hostPlatform} (${process.arch}) | Cargo: ${cargoCheck.ok ? cargoCheck.output : 'not installed'}`);
	console.log('');

	const rows = [
		{
			os: 'Windows 11',
			runner: 'windows-latest',
			target: 'x86_64-pc-windows-msvc',
			bundles: 'msi, nsis (.exe)',
			ready: errors.length === 0 ? 'READY (CI + Windows host)' : 'NEEDS FIXES'
		},
		{
			os: 'macOS',
			runner: 'macos-latest',
			target: 'universal-apple-darwin',
			bundles: 'dmg, app',
			ready: errors.length === 0 ? 'READY (CI + macOS host)' : 'NEEDS FIXES'
		},
		{
			os: 'Linux',
			runner: 'ubuntu-22.04',
			target: 'x86_64-unknown-linux-gnu',
			bundles: 'appimage, deb, rpm',
			ready: errors.length === 0 ? 'READY (CI + Linux host)' : 'NEEDS FIXES'
		}
	];

	for (const r of rows) {
		console.log(
			`  - ${r.os.padEnd(11)} | runner: ${r.runner.padEnd(14)} | target: ${r.target.padEnd(24)} | bundles: ${r.bundles.padEnd(18)} | ${r.ready}`
		);
	}
	console.log(`Local Tauri CLI: ${tauriCargoCheck.ok ? tauriCargoCheck.output : 'npx @tauri-apps/cli (on-demand)'}`);
	if (installedTargets.length > 0) {
		console.log(`Installed Rust targets: ${installedTargets.join(', ')}`);
	}
	console.log('');

	if (errors.length > 0) {
		console.error('Readiness check FAILED:');
		for (const err of errors) {
			console.error(`  [x] ${err}`);
		}
		process.exit(1);
	}

	console.log('All cross-platform desktop readiness checks PASSED.');
}

function findBundleFiles(bundleRoot) {
	const results = [];
	if (!fs.existsSync(bundleRoot)) return results;

	function walk(dir) {
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
			const full = path.join(dir, entry.name);
			const lower = entry.name.toLowerCase();
			if (entry.isDirectory()) {
				if (lower.endsWith('.app')) {
					results.push(full);
				} else {
					walk(full);
				}
			} else if (entry.isFile()) {
				if (INSTALLER_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
					results.push(full);
				}
			}
		}
	}

	walk(bundleRoot);
	return results.sort();
}

function collectInstallersAndStamp(platform, targetTriple, offline) {
	const targetBase = path.join(OAKE_ROOT, 'desktop', 'src-tauri', 'target');
	const candidateBundleDirs = [];
	if (targetTriple) {
		candidateBundleDirs.push(path.join(targetBase, targetTriple, 'release', 'bundle'));
	}
	candidateBundleDirs.push(path.join(targetBase, 'release', 'bundle'));

	let found = [];
	for (const dir of candidateBundleDirs) {
		found = findBundleFiles(dir);
		if (found.length > 0) break;
	}

	if (found.length === 0) {
		throw new Error(
			`No built installer artifacts found under ${candidateBundleDirs.join(' or ')}`
		);
	}

	const distDir = path.join(OAKE_ROOT, 'dist', platform);
	fs.rmSync(distDir, { recursive: true, force: true });
	fs.mkdirSync(distDir, { recursive: true });

	const copiedFiles = [];
	for (const srcPath of found) {
		const name = path.basename(srcPath);
		const destPath = path.join(distDir, name);
		const stat = fs.statSync(srcPath);
		if (stat.isDirectory()) {
			fs.cpSync(srcPath, destPath, { recursive: true });
		} else {
			fs.copyFileSync(srcPath, destPath);
			copiedFiles.push(destPath);
		}
	}

	const checksumLines = [];
	for (const filePath of copiedFiles.sort()) {
		const hash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
		checksumLines.push(`${hash}  ${path.basename(filePath)}`);
	}

	const sumsPath = path.join(distDir, 'SHA256SUMS.txt');
	fs.writeFileSync(sumsPath, checksumLines.join('\n') + (checksumLines.length ? '\n' : ''), 'utf8');
	console.log(`Wrote ${sumsPath} (${checksumLines.length} installer file(s))`);

	const relSums = path.relative(OAKE_ROOT, sumsPath);
	const captureArgs = [path.join(OAKE_ROOT, 'cli', 'oake.mjs'), 'capture', relSums, '--plain-paths', '--dir', OAKE_ROOT];
	if (offline) {
		captureArgs.push('--offline');
	}
	console.log(`Dogfooding OAKe provenance capture on ${relSums}...`);
	execFileSync(process.execPath, captureArgs, { cwd: OAKE_ROOT, stdio: 'inherit' });
}

function runBuild(opts) {
	runCheck();

	const cargoCheck = commandExists('cargo', ['--version']);
	if (!cargoCheck.ok) {
		throw new Error('Cargo / Rust toolchain is required to build desktop installers. Install via https://rustup.rs');
	}

	const targetPlatform = opts.platform === 'current' ? resolveCurrentPlatform() : opts.platform;
	const tauriArgs = ['build'];
	let targetTriple = null;

	if (targetPlatform === 'macos') {
		tauriArgs.push('--bundles', 'dmg,app');
		if (opts.universal) {
			const installed = commandExists('rustup', ['target', 'list', '--installed']);
			const targets = installed.ok ? installed.output.split(/\r?\n/).map((s) => s.trim()) : [];
			for (const req of ['aarch64-apple-darwin', 'x86_64-apple-darwin']) {
				if (!targets.includes(req)) {
					throw new Error(
						`Missing Rust target "${req}" for --universal macOS build. Run: rustup target add aarch64-apple-darwin x86_64-apple-darwin`
					);
				}
			}
			targetTriple = 'universal-apple-darwin';
			tauriArgs.push('--target', targetTriple);
		}
	} else if (targetPlatform === 'windows') {
		targetTriple = 'x86_64-pc-windows-msvc';
		tauriArgs.push('--bundles', 'msi,nsis', '--target', targetTriple);
	} else if (targetPlatform === 'linux') {
		targetTriple = 'x86_64-unknown-linux-gnu';
		tauriArgs.push('--bundles', 'appimage,deb,rpm', '--target', targetTriple);
	}

	const tauriSrcDir = path.join(OAKE_ROOT, 'desktop', 'src-tauri');
	const hasCargoTauri = commandExists('cargo', ['tauri', '--version']).ok;

	if (hasCargoTauri) {
		console.log(`Invoking: cargo tauri ${tauriArgs.join(' ')}`);
		execFileSync('cargo', ['tauri', ...tauriArgs], { cwd: tauriSrcDir, stdio: 'inherit' });
	} else {
		console.log(`Invoking: npx --yes @tauri-apps/cli ${tauriArgs.join(' ')}`);
		execFileSync('npx', ['--yes', '@tauri-apps/cli', ...tauriArgs], {
			cwd: tauriSrcDir,
			stdio: 'inherit'
		});
	}

	collectInstallersAndStamp(targetPlatform, targetTriple, opts.offline);
}

function copyCleanTree(srcDir, destDir) {
	fs.mkdirSync(destDir, { recursive: true });
	for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
		if (entry.isDirectory()) {
			if (EXPORT_EXCLUDE_DIRS.has(entry.name)) continue;
			copyCleanTree(path.join(srcDir, entry.name), path.join(destDir, entry.name));
		} else if (entry.isFile()) {
			if (EXPORT_EXCLUDE_FILES.has(entry.name) || entry.name.endsWith('.db')) continue;
			const srcFile = path.join(srcDir, entry.name);
			const destFile = path.join(destDir, entry.name);
			fs.copyFileSync(srcFile, destFile);
			const mode = fs.statSync(srcFile).mode;
			fs.chmodSync(destFile, mode);
		}
	}
}

function runExportRepo(targetDirRaw) {
	const targetDir = path.resolve(targetDirRaw);
	const oakeReal = fs.realpathSync(OAKE_ROOT);
	if (targetDir === oakeReal || targetDir.startsWith(oakeReal + path.sep)) {
		throw new Error(`Refusing to export into OAKE_ROOT or subdirectory: ${targetDir}`);
	}

	copyCleanTree(OAKE_ROOT, targetDir);

	const gitDir = path.join(targetDir, '.git');
	if (!fs.existsSync(gitDir)) {
		try {
			execFileSync('git', ['init', '-b', 'main'], { cwd: targetDir, stdio: 'inherit' });
		} catch {
			execFileSync('git', ['init'], { cwd: targetDir, stdio: 'inherit' });
			execFileSync('git', ['checkout', '-B', 'main'], { cwd: targetDir, stdio: 'inherit' });
		}
	}

	console.log(`\nExported standalone OAKe repository to: ${targetDir}`);
	console.log('\nNext steps to publish to https://github.com/Madara-Labs/OAKe:');
	console.log(`  cd ${targetDir}`);
	console.log('  git add -A');
	console.log('  git commit -m "feat: standalone OAKe CLI & cross-platform desktop app"');
	console.log('  git remote add origin https://github.com/Madara-Labs/OAKe.git');
	console.log('  git push -u origin main');
}

function main() {
	const opts = parseCliArgs(process.argv.slice(2));
	if (opts.help) {
		printHelp();
		return;
	}
	if (opts.exportRepo) {
		runExportRepo(opts.exportRepo);
		return;
	}
	if (opts.check) {
		runCheck();
		return;
	}
	runBuild(opts);
}

try {
	main();
} catch (err) {
	console.error(`build-desktop error: ${err instanceof Error ? err.message : String(err)}`);
	process.exit(1);
}

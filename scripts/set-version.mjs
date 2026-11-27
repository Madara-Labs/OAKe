#!/usr/bin/env node
// The release version lives in four files. Set all of them, or check that they agree.
//   node scripts/set-version.mjs 0.2.0
//   node scripts/set-version.mjs --check [expected]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILES = {
	'package.json': /^(\s*"version":\s*")([^"]+)(")/m,
	'desktop/src-tauri/tauri.conf.json': /^(\s*"version":\s*")([^"]+)(")/m,
	'desktop/src-tauri/Cargo.toml': /^(version\s*=\s*")([^"]+)(")/m,
	'desktop/src-tauri/Cargo.lock': /(name = "oake-desktop"\r?\nversion = ")([^"]+)(")/
};
const VERSION = /^\d+\.\d+\.\d+$/;

function fail(message) {
	console.error(message);
	process.exit(1);
}

const found = Object.entries(FILES).map(([file, pattern]) => {
	const text = fs.readFileSync(path.join(root, file), 'utf8');
	const version = pattern.exec(text)?.[2];
	if (!version) fail(`No version found in ${file}`);
	return { file, pattern, text, version };
});

const [arg, expected] = process.argv.slice(2);
if (arg === '--check') {
	const want = expected ?? found[0].version;
	const wrong = found.filter((f) => f.version !== want);
	if (wrong.length) fail(`Expected version ${want}, but ${wrong.map((f) => `${f.file} has ${f.version}`).join(', ')}`);
	console.log(want);
} else if (VERSION.test(arg ?? '')) {
	for (const { file, pattern, text } of found) {
		fs.writeFileSync(path.join(root, file), text.replace(pattern, `$1${arg}$3`));
	}
	console.log(`Version set to ${arg}`);
} else {
	fail('Usage: node scripts/set-version.mjs <major.minor.patch> | --check [expected]');
}

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const FILES = ['package.json', 'desktop/src-tauri/tauri.conf.json', 'desktop/src-tauri/Cargo.toml', 'desktop/src-tauri/Cargo.lock'];
const script = path.resolve('scripts/set-version.mjs');

function copy() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-version-'));
	for (const f of [...FILES, 'scripts/set-version.mjs']) {
		fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
		if (fs.existsSync(f)) fs.copyFileSync(f, path.join(dir, f));
	}
	const run = (...args: string[]) =>
		spawnSync(process.execPath, [path.join(dir, 'scripts/set-version.mjs'), ...args], { encoding: 'utf8' });
	return { dir, run, read: (f: string) => fs.readFileSync(path.join(dir, f), 'utf8') };
}

describe('release version', () => {
	it('is the same in every file of this repository', () => {
		const result = spawnSync(process.execPath, [script, '--check'], { encoding: 'utf8' });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(result.stdout.trim(), JSON.parse(fs.readFileSync('package.json', 'utf8')).version);
	});

	it('is changed in every file at once, leaving dependencies alone', () => {
		const { run, read } = copy();
		const before = FILES.map(read);
		assert.equal(run('9.8.7').status, 0);
		assert.equal(run('--check', '9.8.7').stdout.trim(), '9.8.7');
		FILES.forEach((f, i) => {
			const changed = read(f).split('\n').filter((line, n) => line !== before[i].split('\n')[n]);
			assert.equal(changed.length, 1, `${f}: ${changed.join(' | ')}`);
		});
	});

	it('fails when a tag or one file disagrees, and refuses malformed versions', () => {
		const { dir, run, read } = copy();
		assert.equal(run('--check', '9.9.9').status, 1);
		for (const bad of ['v1.0.0', '1.0', '1.0.0; id']) assert.equal(run(bad).status, 1);
		const conf = 'desktop/src-tauri/tauri.conf.json';
		fs.writeFileSync(path.join(dir, conf), read(conf).replace(/"version": "[^"]+"/, '"version": "7.0.0"'));
		const result = run('--check');
		assert.equal(result.status, 1);
		assert.match(result.stderr, /tauri\.conf\.json/);
	});
});

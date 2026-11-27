import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

describe('oake verify verdict', () => {
	for (const cli of ['cli/oake.mjs']) {
		it(`${cli}: no timestamp is incomplete (exit 2), a wrong file is failed (exit 1)`, () => {
			const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-verdict-'));
			const env = { ...process.env, OAKE_HOME: path.join(dir, 'home') };
			const run = (...args: string[]) =>
				spawnSync(process.execPath, [path.resolve(cli), ...args], { cwd: dir, env, encoding: 'utf8' });
			fs.writeFileSync(path.join(dir, 'paper.tex'), 'draft');
			assert.equal(run('capture', 'paper.tex', '--offline', '--dir', dir).status, 0);
			const proofs = path.join(dir, '.oake', 'proofs');
			const bundle = path.join(proofs, fs.readdirSync(proofs)[0]);

			const incomplete = run('verify', bundle, '--offline', '--file', 'paper.tex');
			assert.equal(incomplete.status, 2, incomplete.stdout + incomplete.stderr);
			assert.match(incomplete.stdout, /verdict\s+: INCOMPLETE/);

			fs.writeFileSync(path.join(dir, 'paper.tex'), 'changed');
			const failed = run('verify', bundle, '--offline', '--file', 'paper.tex');
			assert.equal(failed.status, 1);
			assert.match(failed.stdout, /verdict\s+: FAILED/);
			fs.rmSync(dir, { recursive: true, force: true });
		});
	}
});

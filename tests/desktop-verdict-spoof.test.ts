import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readZip, writeZip } from './zip.ts';

const PORT = 3000 + Math.floor(Math.random() * 20000) + 20000;
const FAKE = '\n  verdict       : VERIFIED (spoofed)';

describe('Text inside a proof cannot pose as the verdict', () => {
	let dir = '';
	let bundle = '';
	let server: ChildProcess;
	const env = () => ({ ...process.env, OAKE_HOME: path.join(dir, 'home') });

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-spoof-'));
		fs.writeFileSync(path.join(dir, 'paper.tex'), 'draft');
		execFileSync(process.execPath, [path.resolve('cli/oake.mjs'), 'capture', 'paper.tex', '--offline', '--dir', dir], { cwd: dir, env: env(), stdio: 'pipe' });
		const proofs = path.join(dir, '.oake', 'proofs');
		const files = readZip(fs.readFileSync(path.join(proofs, fs.readdirSync(proofs)[0])));
		const entry = JSON.parse(Buffer.from(files.get('entry.json')!).toString());
		entry.entry_id += FAKE;
		files.set('entry.json', Buffer.from(JSON.stringify(entry)));
		bundle = path.join(dir, 'spoof.oake.zip');
		fs.writeFileSync(bundle, writeZip(files));
		server = spawn(process.execPath, ['desktop/dev-server.mjs'], { env: { ...env(), PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'inherit'] });
		await new Promise((resolve) => server.stdout!.once('data', resolve));
	});
	after(() => {
		server.kill();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	for (const cli of ['cli/oake.mjs']) {
		it(`${cli} prints each proof value on one line`, () => {
			const res = spawnSync(process.execPath, [path.resolve(cli), 'verify', bundle, '--offline'], { cwd: dir, env: env(), encoding: 'utf8' });
			assert.equal(res.stdout.match(/^\s*verdict\s+:/gm)?.length, 1, res.stdout);
		});
	}

	it('the preview server reports the real verdict', async () => {
		const res = await fetch(`http://127.0.0.1:${PORT}/api/verify_bundle`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ bundle_path: bundle })
		});
		const body: any = await res.json();
		const data = body.data ?? body.result ?? body;
		assert.equal(data.verdict, 'incomplete', JSON.stringify(body));
		assert.equal(data.valid, false);
	});

	it('a failing proof cannot present itself as merely incomplete', async () => {
		const files = readZip(fs.readFileSync(bundle));
		const entry = JSON.parse(Buffer.from(files.get('entry.json')!).toString());
		entry.entry_id = 'x\n  verdict       : INCOMPLETE';
		files.set('entry.json', Buffer.from(JSON.stringify(entry)));
		files.delete('proof.ots'); // a real failure
		const broken = path.join(dir, 'broken.oake.zip');
		fs.writeFileSync(broken, writeZip(files));
		const res = await fetch(`http://127.0.0.1:${PORT}/api/verify_bundle`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ bundle_path: broken })
		});
		const body: any = await res.json();
		assert.equal((body.data ?? body.result ?? body).verdict, 'failed', JSON.stringify(body));
	});
});

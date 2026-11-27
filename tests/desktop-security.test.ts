import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const PORT = 3000 + Math.floor(Math.random() * 20000) + 20000;
const HOST = `127.0.0.1:${PORT}`;

function send(headers: Record<string, string>, method = 'POST'): Promise<number> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{ host: '127.0.0.1', port: PORT, path: '/api/list_workspaces', method, headers },
			(res) => {
				res.resume();
				resolve(res.statusCode ?? 0);
			}
		);
		req.on('error', reject);
		req.end(method === 'POST' ? '{}' : undefined);
	});
}

describe('Desktop preview server only answers its own page', () => {
	let server: ChildProcess;
	before(async () => {
		const home = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-sec-'));
		server = spawn(process.execPath, ['desktop/dev-server.mjs'], {
			env: { ...process.env, OAKE_HOME: home, PORT: String(PORT) },
			stdio: ['ignore', 'pipe', 'inherit']
		});
		await new Promise((resolve) => server.stdout!.once('data', resolve));
	});
	after(() => server.kill());

	const json = { 'content-type': 'application/json' };

	it('accepts same-origin JSON requests', async () => {
		assert.equal(await send({ ...json, host: HOST, origin: `http://${HOST}` }), 200);
		assert.equal(await send({ ...json, host: `localhost:${PORT}`, origin: `http://localhost:${PORT}` }), 200);
	});

	it('rejects foreign hosts (DNS rebinding), foreign origins, form posts, and GET', async () => {
		assert.equal(await send({ ...json, host: `evil.example:${PORT}` }), 403);
		assert.equal(await send({ ...json, host: HOST, origin: 'https://evil.example' }), 403);
		assert.equal(await send({ 'content-type': 'text/plain', host: HOST }), 415);
		assert.equal(await send({ host: HOST }, 'GET'), 405);
	});
});

describe('Desktop UI escapes values read from proof files', () => {
	it('never inserts them into HTML unescaped', () => {
		const ui = fs.readFileSync('desktop/ui/app.js', 'utf8');
		for (const field of ['btcBlock', 'entry.btc_block', 'entry.sequence', 'h.sequence', 'entry.tsa_count', 'file.byte_size', 'tsaCount']) {
			assert.ok(!ui.includes('${' + field + '}'), `unescaped \${${field}}`);
		}
	});

	it('ships a content security policy', () => {
		const conf = JSON.parse(fs.readFileSync('desktop/src-tauri/tauri.conf.json', 'utf8'));
		assert.match(conf.app.security.csp, /default-src 'self'/);
		assert.doesNotMatch(conf.app.security.csp, /script-src[^;]*unsafe/);
	});
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { readZip, writeZip } from './zip.ts';

const ALICE = 'https://alice.btc.calendar.opentimestamps.org';

/** A pending .ots proof for `hash` that asks to be polled at `uri`. */
function pendingOts(hash: string, uri: string): Buffer {
	return Buffer.concat([
		Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex'),
		Buffer.from([0x01, 0x08]),
		Buffer.from(hash.slice('sha256:'.length), 'hex'),
		Buffer.from('f0041122334408' + '0083dfe30d2ef90c8e', 'hex'),
		Buffer.from([uri.length + 1, uri.length]),
		Buffer.from(uri)
	]);
}

/** Runs `oake upgrade` on a proof naming `uri` and returns every address it requested. */
function requestsFor(uri: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-ssrf-'));
	const env = { ...process.env, OAKE_HOME: path.join(dir, 'home') };
	const cli = path.resolve('cli/oake.mjs');
	fs.writeFileSync(path.join(dir, 'paper.tex'), 'draft');
	execFileSync(process.execPath, [cli, 'capture', 'paper.tex', '--offline', '--dir', dir], { cwd: dir, env, stdio: 'pipe' });
	const proofs = path.join(dir, '.oake', 'proofs');
	const bundle = path.join(proofs, fs.readdirSync(proofs)[0]);
	const files = readZip(fs.readFileSync(bundle));
	const entry = JSON.parse(files.get('entry.json')!.toString());
	entry.ots.status = 'pending';
	files.set('entry.json', Buffer.from(JSON.stringify(entry)));
	files.set('proof.ots', pendingOts(entry.artifact_hash, uri));
	fs.writeFileSync(bundle, writeZip(files));

	const log = path.join(dir, 'requests.log');
	const stub = path.join(dir, 'stub.mjs');
	fs.writeFileSync(
		stub,
		`import fs from 'node:fs';
globalThis.fetch = async (url, init) => { fs.appendFileSync(${JSON.stringify(log)}, url + ' redirect=' + init?.redirect + '\\n'); return new Response('', { status: 404 }); };\n`
	);
	execFileSync(process.execPath, ['--import', pathToFileURL(stub).href, cli, 'upgrade', dir], { env, stdio: 'pipe' });
	const sent = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
	fs.rmSync(dir, { recursive: true, force: true });
	return sent;
}

describe('`oake upgrade` only contacts known calendars', () => {
	for (const uri of [
		'http://169.254.169.254/latest/meta-data?',
		'http://127.0.0.1:9/admin#',
		`${ALICE}.evil.example`,
		`${ALICE}@evil.example`
	]) {
		it(`sends nothing to ${uri}`, () => assert.equal(requestsFor(uri), ''));
	}

	it('polls a known calendar at its stored address and refuses redirects', () => {
		const sent = requestsFor(`${ALICE}/elsewhere?x=`);
		assert.ok(sent.startsWith(`${ALICE}/timestamp/`), sent);
		assert.match(sent, /redirect=manual/);
	});
});

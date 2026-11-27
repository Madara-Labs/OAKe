import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

// A ZIP whose central directory may lie about sizes, as a hostile bundle would.
function zip(entries: { name: string; data: Buffer }[]): Buffer {
	const locals: Buffer[] = [];
	const central: Buffer[] = [];
	let offset = 0;
	for (const { name, data } of entries) {
		const body = zlib.deflateRawSync(data);
		const n = Buffer.from(name);
		const local = Buffer.alloc(30);
		local.writeUInt32LE(0x04034b50, 0);
		local.writeUInt16LE(8, 8);
		local.writeUInt32LE(body.length, 18);
		local.writeUInt16LE(n.length, 26);
		const cd = Buffer.alloc(46);
		cd.writeUInt32LE(0x02014b50, 0);
		cd.writeUInt16LE(8, 10);
		cd.writeUInt32LE(body.length, 20);
		cd.writeUInt32LE(10, 24); // claimed size
		cd.writeUInt16LE(n.length, 28);
		cd.writeUInt32LE(offset, 42);
		locals.push(local, n, body);
		central.push(cd, n);
		offset += 30 + n.length + body.length;
	}
	const cdBytes = Buffer.concat(central);
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(entries.length, 8);
	end.writeUInt16LE(entries.length, 10);
	end.writeUInt32LE(cdBytes.length, 12);
	end.writeUInt32LE(offset, 16);
	return Buffer.concat([...locals, cdBytes, end]);
}

const MB = 1024 * 1024;
const cases = {
	'one oversized entry': [{ name: 'entry.json', data: Buffer.alloc(9 * MB, 32) }],
	'oversized total': Array.from({ length: 4 }, (_, i) => ({ name: `f${i}`, data: Buffer.alloc(7 * MB) })),
	'too many entries': Array.from({ length: 65 }, (_, i) => ({ name: `f${i}`, data: Buffer.alloc(1) }))
};

describe('hostile proof bundles are refused before they exhaust memory', () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-bomb-'));
	const env = { ...process.env, OAKE_HOME: path.join(dir, 'home') };
	for (const [label, entries] of Object.entries(cases)) {
		const bundle = path.join(dir, `${label.replaceAll(' ', '-')}.oake.zip`);
		fs.writeFileSync(bundle, zip(entries));

		it(`command line: ${label}`, () => {
			const run = spawnSync(process.execPath, ['cli/oake.mjs', 'verify', bundle, '--offline'], { env, encoding: 'utf8' });
			assert.equal(run.status, 1);
			assert.match(run.stdout + run.stderr, /bundle is too large/i);
		});

		it(`preview server: ${label}`, async () => {
			const port = 20000 + Math.floor(Math.random() * 20000);
			const server = spawn(process.execPath, ['desktop/dev-server.mjs'], {
				env: { ...env, PORT: String(port) },
				stdio: ['ignore', 'pipe', 'inherit']
			});
			try {
				await new Promise((resolve) => server.stdout!.once('data', resolve));
				const res = await fetch(`http://127.0.0.1:${port}/api/verify_bundle`, {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ bundle_path: bundle })
				});
				assert.match(await res.text(), /bundle is too large/i);
			} finally {
				server.kill();
			}
		});
	}
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

await import('../desktop/ui/checkcmds.js');
const C = (globalThis as any).OakeCheckCommands;
const ID = '01M8EFNJMD75WTRD67KZY1BWGX';

describe('"Check it yourself" commands', () => {
	it('the first command unzips the proof from any folder and moves into it', { skip: process.platform === 'win32' }, () => {
		const home = fs.mkdtempSync(path.join(os.tmpdir(), 'oake-cmd-'));
		const src = path.join(home, "it's a $(touch pwned) folder");
		fs.mkdirSync(path.join(src, 'rfc3161'), { recursive: true });
		fs.writeFileSync(path.join(src, 'rfc3161', `${ID}-digicert-us.tsr`), 'x');
		execFileSync('zip', ['-qr', `${ID}.oake.zip`, 'rfc3161'], { cwd: src });
		const cmd = C.unzipCommand(path.join(src, `${ID}.oake.zip`), ID, 'MacIntel');
		const out = execFileSync('sh', ['-c', `${cmd} && ls rfc3161`], { cwd: home, env: { ...process.env, HOME: home }, encoding: 'utf8' });
		assert.match(out, new RegExp(`${ID}-digicert-us\\.tsr`));
		assert.ok(!fs.existsSync(path.join(home, 'pwned')));
	});

	it('uses PowerShell on Windows with the path quoted', () => {
		const cmd = C.unzipCommand("C:\\Users\\o'neil\\a.oake.zip", ID, 'Win32');
		assert.match(cmd, /^Expand-Archive -Force -LiteralPath 'C:\\Users\\o''neil\\a\.oake\.zip' /);
	});

	it('names only the timestamp files the proof actually has', () => {
		const cmds = C.timestampCommands('ab'.repeat(32), ID, ['digicert-us'], 'MacIntel');
		assert.equal(cmds.length, 1);
		assert.match(cmds[0], new RegExp(`-in rfc3161/${ID}-digicert-us\\.tsr -CAfile /etc/ssl/cert\\.pem$`));
		assert.match(C.timestampCommands('ab'.repeat(32), ID, ['x'], 'Linux x86_64')[0], /ca-certificates\.crt$/);
	});

	it('builds no command from values that are not plain identifiers', () => {
		assert.deepEqual(C.timestampCommands('ab'.repeat(32), ID, ['x; rm -rf ~'], 'MacIntel'), []);
		assert.deepEqual(C.timestampCommands('$(id)', ID, ['digicert-us'], 'MacIntel'), []);
		assert.equal(C.unzipCommand('/a.oake.zip', '"; id; "', 'MacIntel'), null);
	});
});

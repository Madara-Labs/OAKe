import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const { buildManifest } = await import('../scripts/update-manifest.mjs');
const FILES = [
	'OAKe.Desktop_universal.app.tar.gz',
	'OAKe.Desktop_0.2.0_x64-setup.exe',
	'OAKe.Desktop_0.2.0_x64_en-US.msi',
	'OAKe.Desktop_0.2.0_amd64.AppImage',
	'OAKe.Desktop_0.2.0_amd64.deb',
	'OAKe.Desktop-0.2.0-1.x86_64.rpm'
];
const signatures = Object.fromEntries(FILES.map((f) => [`${f}.sig`, `signature of ${f}\n`]));
const options = { repo: 'Madara-Labs/OAKe', tag: 'v0.2.0', signatures, date: new Date('2030-01-01T00:00:00Z') };

describe('update manifest', () => {
	it('points every installed package type at its own signed file', () => {
		const m = buildManifest(options);
		assert.equal(m.version, '0.2.0');
		const file = (key: string) => m.platforms[key].url.split('/').pop();
		const expected: Record<string, string> = {
			'darwin-aarch64': FILES[0],
			'darwin-x86_64': FILES[0],
			'windows-x86_64': FILES[1],
			'windows-x86_64-nsis': FILES[1],
			'windows-x86_64-msi': FILES[2],
			'linux-x86_64': FILES[3],
			'linux-x86_64-appimage': FILES[3],
			'linux-x86_64-deb': FILES[4],
			'linux-x86_64-rpm': FILES[5]
		};
		assert.deepEqual(Object.keys(m.platforms).sort(), Object.keys(expected).sort());
		for (const [key, name] of Object.entries(expected)) assert.equal(file(key), name, key);
		assert.equal(m.platforms['linux-x86_64-deb'].signature, `signature of ${FILES[4]}`);
		assert.equal(m.platforms['darwin-x86_64'].url, `https://github.com/Madara-Labs/OAKe/releases/download/v0.2.0/${FILES[0]}`);
	});

	it('refuses to publish a manifest that leaves a platform out', () => {
		const { [`${FILES[4]}.sig`]: _, ...missing } = signatures;
		assert.throws(() => buildManifest({ ...options, signatures: missing }), /linux-x86_64-deb/);
	});
});

describe('desktop update settings', () => {
	const conf = JSON.parse(fs.readFileSync('desktop/src-tauri/tauri.conf.json', 'utf8'));

	it('only trusts the manifest published with this repository releases, over HTTPS', () => {
		assert.deepEqual(conf.plugins.updater.endpoints, ['https://github.com/Madara-Labs/OAKe/releases/latest/download/latest.json']);
		assert.equal(typeof conf.plugins.updater.pubkey, 'string');
		assert.equal(conf.plugins.updater.dangerousInsecureTransportProtocol, undefined);
	});

	it('keeps ordinary builds working without the private signing key', () => {
		assert.equal(conf.bundle.createUpdaterArtifacts, undefined);
		const workflow = fs.readFileSync('.github/workflows/release-desktop.yml', 'utf8');
		assert.match(workflow, /createUpdaterArtifacts/);
		assert.match(workflow, /TAURI_SIGNING_PRIVATE_KEY/);
		assert.match(workflow, /uploadUpdaterJson: false/);
		assert.match(workflow, /update-manifest\.mjs/);
	});
});

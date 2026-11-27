#!/usr/bin/env node
// Writes latest.json, which installed apps read to find updates. It runs once, after all
// builds, so parallel jobs cannot overwrite each other's platforms.
//   node scripts/update-manifest.mjs <owner/repo> <tag> <directory with .sig files> <output>
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const PACKAGES = [
	{ suffix: '.app.tar.gz', platforms: ['darwin-aarch64', 'darwin-x86_64'] },
	{ suffix: '-setup.exe', platforms: ['windows-x86_64-nsis', 'windows-x86_64'] },
	{ suffix: '.msi', platforms: ['windows-x86_64-msi'] },
	{ suffix: '.AppImage', platforms: ['linux-x86_64-appimage', 'linux-x86_64'] },
	{ suffix: '.deb', platforms: ['linux-x86_64-deb'] },
	{ suffix: '.rpm', platforms: ['linux-x86_64-rpm'] }
];

/** `signatures` maps each `<file>.sig` name to its contents. */
export function buildManifest({ repo, tag, signatures, date = new Date() }) {
	const platforms = {};
	for (const { suffix, platforms: keys } of PACKAGES) {
		const matches = Object.keys(signatures).filter((name) => name.endsWith(`${suffix}.sig`));
		if (matches.length !== 1) {
			throw new Error(`Expected one signed ${suffix} file for ${keys.join(', ')}, found ${matches.length}`);
		}
		const file = matches[0].slice(0, -4);
		const entry = {
			signature: signatures[matches[0]].trim(),
			url: `https://github.com/${repo}/releases/download/${tag}/${encodeURIComponent(file)}`
		};
		for (const key of keys) platforms[key] = entry;
	}
	return { version: tag.replace(/^v/, ''), pub_date: date.toISOString(), platforms };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
	const [repo, tag, dir, output] = process.argv.slice(2);
	if (!output) {
		console.error('Usage: node scripts/update-manifest.mjs <owner/repo> <tag> <signature dir> <output>');
		process.exit(1);
	}
	const signatures = Object.fromEntries(
		fs.readdirSync(dir).filter((f) => f.endsWith('.sig')).map((f) => [f, fs.readFileSync(path.join(dir, f), 'utf8')])
	);
	fs.writeFileSync(output, JSON.stringify(buildManifest({ repo, tag, signatures }), null, 2) + '\n');
}

/**
 * Terminal commands shown under "Check it yourself". Users paste these into a shell,
 * so paths are quoted and names from proof files must be plain identifiers.
 */
(() => {
	'use strict';

	const PLAIN = /^[A-Za-z0-9_-]+$/;
	const isWindows = (platform) => /^win/i.test(platform || '');

	/** Unpacks a proof into ~/oake-check/<id> and moves there; the other commands run from it. */
	function unzipCommand(bundlePath, entryId, platform) {
		if (!bundlePath || !PLAIN.test(entryId || '')) return null;
		const dir = `"$HOME/oake-check/${entryId}"`;
		if (isWindows(platform)) {
			const file = `'${bundlePath.replace(/['‘’‚‛]/g, '$&$&')}'`;
			return `Expand-Archive -Force -LiteralPath ${file} -DestinationPath ${dir}; cd ${dir}`;
		}
		const file = `'${bundlePath.replace(/'/g, `'\\''`)}'`;
		return `mkdir -p "$HOME/oake-check" && unzip -o ${file} -d ${dir} && cd ${dir}`;
	}

	/** One OpenSSL check per timestamp file in the proof. */
	function timestampCommands(digestHex, entryId, tsaIds, platform) {
		if (!/^[0-9a-fA-F]{64}$/.test(digestHex || '') || !PLAIN.test(entryId || '')) return [];
		const roots = /linux/i.test(platform || '') ? '/etc/ssl/certs/ca-certificates.crt' : '/etc/ssl/cert.pem';
		return (tsaIds || [])
			.filter((id) => PLAIN.test(id))
			.map((id) => `openssl ts -verify -digest ${digestHex} -in rfc3161/${entryId}-${id}.tsr -CAfile ${roots}`);
	}

	globalThis.OakeCheckCommands = { unzipCommand, timestampCommands };
})();

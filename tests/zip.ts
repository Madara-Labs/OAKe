// Minimal ZIP reader/writer so tests can tamper with proof bundles.
import zlib from 'node:zlib';

export function readZip(zip: Buffer): Map<string, Buffer> {
	const files = new Map<string, Buffer>();
	const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
	let cursor = zip.readUInt32LE(end + 16);
	for (let i = 0; i < zip.readUInt16LE(end + 10); i++) {
		const method = zip.readUInt16LE(cursor + 10);
		const size = zip.readUInt32LE(cursor + 20);
		const nameLength = zip.readUInt16LE(cursor + 28);
		const local = zip.readUInt32LE(cursor + 42);
		const name = zip.toString('utf8', cursor + 46, cursor + 46 + nameLength);
		const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
		const data = zip.subarray(start, start + size);
		files.set(name, method === 8 ? zlib.inflateRawSync(data) : Buffer.from(data));
		cursor += 46 + nameLength + zip.readUInt16LE(cursor + 30) + zip.readUInt16LE(cursor + 32);
	}
	return files;
}

/** Writes uncompressed entries. */
export function writeZip(files: Map<string, Buffer>): Buffer {
	const locals: Buffer[] = [];
	const centrals: Buffer[] = [];
	let offset = 0;
	for (const [name, data] of files) {
		const nameBytes = Buffer.from(name);
		const crc = zlib.crc32(data) >>> 0;
		const local = Buffer.alloc(30);
		local.writeUInt32LE(0x04034b50, 0);
		local.writeUInt16LE(20, 4);
		local.writeUInt32LE(crc, 14);
		local.writeUInt32LE(data.length, 18);
		local.writeUInt32LE(data.length, 22);
		local.writeUInt16LE(nameBytes.length, 26);
		const central = Buffer.alloc(46);
		central.writeUInt32LE(0x02014b50, 0);
		central.writeUInt16LE(20, 6);
		central.writeUInt32LE(crc, 16);
		central.writeUInt32LE(data.length, 20);
		central.writeUInt32LE(data.length, 24);
		central.writeUInt16LE(nameBytes.length, 28);
		central.writeUInt32LE(offset, 42);
		locals.push(local, nameBytes, data);
		centrals.push(central, nameBytes);
		offset += 30 + nameBytes.length + data.length;
	}
	const directory = Buffer.concat(centrals);
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(files.size, 8);
	end.writeUInt16LE(files.size, 10);
	end.writeUInt32LE(directory.length, 12);
	end.writeUInt32LE(offset, 16);
	return Buffer.concat([...locals, directory, end]);
}

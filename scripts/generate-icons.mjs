#!/usr/bin/env node
/**
 * Zero-dependency icon generator for OAKe Desktop (Tauri v2).
 * Generates 32-bit RGBA PNGs (colorType=6, bitDepth=8), Windows .ico, and macOS .icns
 * in oake/desktop/src-tauri/icons/.
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ICONS_DIR = path.resolve(__dirname, '..', 'desktop', 'src-tauri', 'icons');

// The OAKe mark, in the coordinates of the 1528 x 1528 artwork.
const WHITE = [255, 255, 255];
const CREAM = [255, 244, 240];
const GREY = [226, 226, 226];
const ORANGE = [232, 82, 0];

const rect = (x0, y0, x1, y1) => (x, y) => x >= x0 && x <= x1 && y >= y0 && y <= y1;
const circle = (cx, cy, r) => (x, y) => Math.hypot(x - cx, y - cy) <= r;
const ring = (cx, cy, rx, ry, hx, hy) => (x, y) =>
	((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1 && ((x - cx) / hx) ** 2 + ((y - cy) / hy) ** 2 > 1;
const polygon = (points) => (x, y) => {
	let inside = false;
	for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
		const [xi, yi] = points[i];
		const [xj, yj] = points[j];
		if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
	}
	return inside;
};
const stroke = (points, width) => (x, y) =>
	points.slice(1).some(([bx, by], i) => {
		const [ax, ay] = points[i];
		const dx = bx - ax;
		const dy = by - ay;
		const h = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
		return Math.hypot(x - ax - dx * h, y - ay - dy * h) <= width / 2;
	});

function buildMark() {
	const shapes = [];
	const add = (color, ...tests) => tests.forEach((test) => shapes.push({ color, test }));

	// Head and dotted body
	add(CREAM, circle(748, 440, 54), rect(734, 480, 763, 505));
	for (const [y0, y1] of [[497, 514], [523, 530], [537, 560], [568, 590], [598, 610], [618, 630], [640, 648], [655, 680], [688, 712]]) {
		for (const [x0, x1] of [[703, 721], [727, 761], [767, 777], [784, 800]]) add(CREAM, rect(x0, y0, x1, y1));
	}

	// Nabla, plus, greater-than, integral
	const outer = polygon([[900, 376], [999, 376], [962, 503], [933, 503]]);
	const inner = polygon([[920, 393], [978, 393], [948, 478]]);
	add(WHITE, (x, y) => outer(x, y) && !inner(x, y));
	add(ORANGE, rect(1000, 452, 1095, 466), rect(1039, 408, 1056, 504));
	add(WHITE, stroke([[1105, 418], [1183, 458], [1105, 497]], 19));
	add(WHITE, stroke([[983, 551], [968, 546], [956, 558], [949, 592], [945, 650], [939, 686], [927, 695], [917, 681]], 15));

	// Balance beam
	for (const [x0, x1] of [[503, 591], [599, 689], [704, 791], [799, 895], [903, 992]]) {
		add(WHITE, rect(x0, 768, x1, 785), rect(x0, 798, x1, 816));
	}

	// Pillars
	add(WHITE, rect(498, 872, 598, 890), rect(511, 880, 536, 1040), rect(559, 880, 584, 1040));
	add(WHITE, rect(903, 872, 998, 890), rect(911, 880, 936, 1040), rect(959, 880, 983, 1040));

	// Percent signs
	for (const dx of [0, 897]) {
		add(
			GREY,
			ring(222 + dx, 908, 27, 37, 10, 24),
			ring(272 + dx, 972, 27, 35, 10, 22),
			stroke([[291 + dx, 876], [206 + dx, 1004]], 13)
		);
	}
	return shapes;
}

/**
 * Renders the mark on a black rounded square as an anti-aliased RGBA buffer
 * (size x size x 4). The artwork's empty margin is cropped so it stays legible.
 */
function renderOakeIconRgba(size) {
	const shapes = buildMark();
	const rgba = Buffer.alloc(size * size * 4);
	const samples = 4;
	const half = 0.86; // badge half-size in [-1, 1] space
	const radius = 0.38;
	const artPerUnit = 1005 / (half * 2 * 0.84); // mark width -> 84% of the badge

	for (let y = 0; y < size; y++) {
		for (let x = 0; x < size; x++) {
			let covered = 0;
			const sum = [0, 0, 0];
			for (let sy = 0; sy < samples; sy++) {
				const ny = ((y + (sy + 0.5) / samples) / size) * 2 - 1;
				for (let sx = 0; sx < samples; sx++) {
					const nx = ((x + (sx + 0.5) / samples) / size) * 2 - 1;
					const qx = Math.abs(nx) - half + radius;
					const qy = Math.abs(ny) - half + radius;
					if (Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) > radius) continue;
					covered++;
					const ax = 697 + nx * artPerUnit;
					const ay = 708 + ny * artPerUnit;
					const hit = shapes.find((shape) => shape.test(ax, ay));
					if (hit) for (let c = 0; c < 3; c++) sum[c] += hit.color[c];
				}
			}
			if (covered === 0) continue;
			const idx = (y * size + x) * 4;
			for (let c = 0; c < 3; c++) rgba[idx + c] = Math.round(sum[c] / covered);
			rgba[idx + 3] = Math.round((covered / (samples * samples)) * 255);
		}
	}

	return rgba;
}

function makePngChunk(type, data) {
	const typeBuf = Buffer.from(type, 'ascii');
	const lenBuf = Buffer.alloc(4);
	lenBuf.writeUInt32BE(data.length, 0);

	const crcInput = Buffer.concat([typeBuf, data]);
	const crcBuf = Buffer.alloc(4);
	crcBuf.writeUInt32BE(zlib.crc32(crcInput) >>> 0, 0);

	return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function encodeRgbaPng(size, rgba) {
	const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

	// IHDR: width, height, bitDepth=8, colorType=6 (RGBA), compression=0, filter=0, interlace=0
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(size, 0);
	ihdr.writeUInt32BE(size, 4);
	ihdr[8] = 8; // bitDepth
	ihdr[9] = 6; // colorType RGBA
	ihdr[10] = 0; // compression method
	ihdr[11] = 0; // filter method
	ihdr[12] = 0; // interlace method

	// Raw scanlines: 1 filter byte (0) + size * 4 RGBA bytes per row
	const stride = size * 4;
	const raw = Buffer.alloc((stride + 1) * size);
	for (let y = 0; y < size; y++) {
		const rowOut = y * (stride + 1);
		raw[rowOut] = 0; // filter type None
		rgba.copy(raw, rowOut + 1, y * stride, (y + 1) * stride);
	}

	const compressed = zlib.deflateSync(raw, { level: 9 });

	return Buffer.concat([
		signature,
		makePngChunk('IHDR', ihdr),
		makePngChunk('IDAT', compressed),
		makePngChunk('IEND', Buffer.alloc(0))
	]);
}

/**
 * Windows Vista/Win11 PNG-in-ICO container.
 * 6-byte ICONDIR [0,0, 1,0, count,0] + 16-byte ICONDIRENTRYs + PNG payloads.
 */
function buildIco(entries) {
	const header = Buffer.alloc(6);
	header.writeUInt16LE(0, 0); // reserved
	header.writeUInt16LE(1, 2); // type 1 = ICO
	header.writeUInt16LE(entries.length, 4);

	const dirEntries = [];
	const payloads = [];
	let offset = 6 + entries.length * 16;

	for (const { size, png } of entries) {
		const entry = Buffer.alloc(16);
		entry[0] = size >= 256 ? 0 : size; // width (0 means 256)
		entry[1] = size >= 256 ? 0 : size; // height (0 means 256)
		entry[2] = 0; // color palette count
		entry[3] = 0; // reserved
		entry.writeUInt16LE(1, 4); // color planes
		entry.writeUInt16LE(32, 6); // bits per pixel (RGBA)
		entry.writeUInt32LE(png.length, 8); // bytes in resource
		entry.writeUInt32LE(offset, 12); // offset in file

		dirEntries.push(entry);
		payloads.push(png);
		offset += png.length;
	}

	return Buffer.concat([header, ...dirEntries, ...payloads]);
}

/**
 * macOS ICNS container with PNG chunks ('ic07'=128, 'ic08'=256, 'ic09'=512, 'ic10'=1024).
 */
function buildIcns(chunks) {
	const encodedChunks = chunks.map(({ type, png }) => {
		const hdr = Buffer.alloc(8);
		hdr.write(type, 0, 4, 'ascii');
		hdr.writeUInt32BE(8 + png.length, 4);
		return Buffer.concat([hdr, png]);
	});

	const totalLen = 8 + encodedChunks.reduce((sum, c) => sum + c.length, 0);
	const header = Buffer.alloc(8);
	header.write('icns', 0, 4, 'ascii');
	header.writeUInt32BE(totalLen, 4);

	return Buffer.concat([header, ...encodedChunks]);
}

function main() {
	fs.mkdirSync(ICONS_DIR, { recursive: true });

	const png32 = encodeRgbaPng(32, renderOakeIconRgba(32));
	const png128 = encodeRgbaPng(128, renderOakeIconRgba(128));
	const png256 = encodeRgbaPng(256, renderOakeIconRgba(256));
	const png512 = encodeRgbaPng(512, renderOakeIconRgba(512));

	const png1024 = encodeRgbaPng(1024, renderOakeIconRgba(1024));

	const ico = buildIco([
		{ size: 32, png: png32 },
		{ size: 256, png: png256 }
	]);

	const icns = buildIcns([
		{ type: 'ic07', png: png128 },
		{ type: 'ic08', png: png256 },
		{ type: 'ic09', png: png512 },
		{ type: 'ic10', png: png1024 }
	]);

	const outputs = [
		['32x32.png', png32],
		['128x128.png', png128],
		['128x128@2x.png', png256],
		['icon.png', png512],
		['icon.ico', ico],
		['icon.icns', icns]
	];

	// The same mark is shown in the app's header.
	fs.writeFileSync(path.resolve(ICONS_DIR, '..', '..', 'ui', 'logo.png'), png128);

	for (const [name, buf] of outputs) {
		const outPath = path.join(ICONS_DIR, name);
		fs.writeFileSync(outPath, buf);
		console.log(`Generated ${path.relative(process.cwd(), outPath)} (${buf.length} bytes)`);
	}
}

main();

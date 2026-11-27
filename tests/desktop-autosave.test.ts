import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

await import('../desktop/ui/autosave.js');
const A = (globalThis as any).OakeAutosave;
const HOUR = 3_600_000;

describe('Desktop auto-save schedule', () => {
	it('only accepts the offered intervals, never anything under one hour', () => {
		assert.deepEqual(A.INTERVAL_HOURS, [0, 1, 6, 12, 24]);
		for (const bad of [0.01, -1, 2, '5', 'abc', null, undefined]) assert.equal(A.normalizeHours(bad), 0);
		assert.equal(A.normalizeHours('6'), 6);
	});

	it('is due only after a full interval has passed since the last run', () => {
		assert.equal(A.isDue(0, 0, 100 * HOUR), false);
		assert.equal(A.isDue(1, 10 * HOUR, 11 * HOUR - 1), false);
		assert.equal(A.isDue(1, 10 * HOUR, 11 * HOUR), true);
		// survives restarts: a stored old timestamp is due straight away
		assert.equal(A.isDue(24, 1 * HOUR, 40 * HOUR), true);
	});

	it('waits a full interval after being switched on, and changing the interval cannot force a run', () => {
		assert.equal(A.lastRunAfterChange(0, 6, 5, 100), 100);
		assert.equal(A.lastRunAfterChange(24, 1, 5, 100), 5);
		assert.equal(A.lastRunAfterChange(1, 6, 0, 100), 100);
	});

	it('picks edited files before new ones and caps one run', () => {
		const files = [
			{ relative_path: 'new1', status: 'untracked' },
			{ relative_path: 'saved', status: 'anchored' },
			{ relative_path: 'edit1', status: 'modified' }
		];
		assert.deepEqual(A.pickFiles(files, 25), ['edit1', 'new1']);
		assert.deepEqual(A.pickFiles(files, 1), ['edit1']);
		assert.deepEqual(A.pickFiles(files, 0), []);
		assert.equal(A.MAX_FILES_PER_RUN, 25);
	});
});

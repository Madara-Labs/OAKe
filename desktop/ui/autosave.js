/**
 * Auto-save schedule rules. Kept free of DOM and backend calls so they can be tested.
 * Each saved file is sent to external timestamp services, so the shortest interval
 * is one hour and one run saves a limited number of files.
 */
(() => {
	'use strict';

	const INTERVAL_HOURS = [0, 1, 6, 12, 24]; // 0 = off
	const MAX_FILES_PER_RUN = 25;
	const HOUR_MS = 60 * 60 * 1000;

	function normalizeHours(value) {
		const hours = Number(value);
		return INTERVAL_HOURS.includes(hours) ? hours : 0;
	}

	function isDue(hours, lastRunMs, nowMs) {
		return hours > 0 && nowMs - lastRunMs >= hours * HOUR_MS;
	}

	/** Switching on starts a fresh interval; changing the interval keeps the last run. */
	function lastRunAfterChange(previousHours, nextHours, lastRunMs, nowMs) {
		return previousHours === 0 || !lastRunMs ? nowMs : lastRunMs;
	}

	function pickFiles(files, limit) {
		const edited = files.filter((f) => f.status === 'modified');
		const added = files.filter((f) => f.status === 'untracked');
		return [...edited, ...added].slice(0, Math.max(0, limit)).map((f) => f.relative_path);
	}

	globalThis.OakeAutosave = {
		INTERVAL_HOURS,
		MAX_FILES_PER_RUN,
		normalizeHours,
		isDue,
		lastRunAfterChange,
		pickFiles
	};
})();

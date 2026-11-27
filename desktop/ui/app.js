/**
 * OAKe desktop interface.
 *
 * Automatically detects Tauri v2 (`window.__TAURI_INTERNALS__.invoke`) when
 * running inside the native app, or falls back to `fetch('/api/' + cmd)` when
 * served via `node oake/desktop/dev-server.mjs`.
 */

(() => {
	'use strict';

	const isTauri = Boolean(
		typeof window !== 'undefined' &&
		window.__TAURI_INTERNALS__ &&
		typeof window.__TAURI_INTERNALS__.invoke === 'function'
	);

	const STORAGE_THEME = 'oake-desktop-theme';
	const STORAGE_ENDPOINT = 'oake-desktop-endpoint';
	const STORAGE_AUTOSNAP = 'oake-desktop-autosnap'; // earlier on/off setting
	const STORAGE_AUTOSAVE_HOURS = 'oake-desktop-autosave-hours';
	const STORAGE_AUTOSAVE_LAST = 'oake-desktop-autosave-last';
	const STORAGE_CANON = 'oake-desktop-canon';
	const STORAGE_OFFLINE = 'oake-desktop-offline';
	const Autosave = globalThis.OakeAutosave;

	const state = {
		identity: null,
		workspaces: [],
		activeWorkspacePath: null,
		scan: null, // { path, name, files, history }
		activeTab: 'changes', // 'changes' | 'history' | 'verify'
		selectedFilePaths: new Set(),
		inspectedFilePath: null,
		inspectedHistoryId: null,
		anchoredCollapsed: true,
		historyFilter: '',
		verifyResult: null,
		endpoint: localStorage.getItem(STORAGE_ENDPOINT) || 'http://127.0.0.1:3000',
		autosaveHours: Autosave.normalizeHours(
			localStorage.getItem(STORAGE_AUTOSAVE_HOURS) ??
				(localStorage.getItem(STORAGE_AUTOSNAP) === 'true' ? 24 : 0)
		),
		busy: false,
		browseDirPath: null
	};

	// =========================================================================
	// Dual Backend Bridge (Tauri v2 IPC <-> Local Node dev-server)
	// =========================================================================

	function toCamelKeys(obj) {
		const out = {};
		for (const [k, v] of Object.entries(obj || {})) {
			const camel = k.replace(/_([a-z])/g, (_, ch) => ch.toUpperCase());
			out[camel] = v;
		}
		return out;
	}

	async function ipcInvoke(cmd, args = {}) {
		if (isTauri) {
			try {
				return await window.__TAURI_INTERNALS__.invoke(cmd, toCamelKeys(args));
			} catch (err) {
				// The native backend rejects with a plain string.
				throw err instanceof Error ? err : new Error(String(err));
			}
		}
		const res = await fetch(`/api/${encodeURIComponent(cmd)}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(args)
		});
		const data = await res.json().catch(() => ({}));
		if (!res.ok) {
			throw new Error(data.error || data.message || `Command ${cmd} failed (${res.status})`);
		}
		return data;
	}

	// =========================================================================
	// Helpers & Formatting
	// =========================================================================

	const $ = (id) => document.getElementById(id);

	function escapeHtml(value) {
		return String(value ?? '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#39;');
	}

	function formatBytes(bytes) {
		if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
	}

	function formatTime(iso) {
		if (!iso) return '—';
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return String(iso);
		return d.toLocaleString(undefined, {
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	}

	function shortEndpoint(url) {
		return String(url || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
	}

	function showToast(message, kind = 'info') {
		const stack = $('toast-stack');
		const el = document.createElement('div');
		el.className = `toast ${kind}`;
		el.textContent = message;
		stack.appendChild(el);
		setTimeout(() => {
			el.remove();
		}, 4800);
	}

	async function copyText(text, label = 'Copied to clipboard') {
		try {
			await navigator.clipboard.writeText(text);
			showToast(label, 'success');
		} catch {
			showToast('Clipboard permission unavailable', 'warn');
		}
	}

	// =========================================================================
	// Theme & Endpoint & Auto-Snapshot
	// =========================================================================

	function applyTheme(theme) {
		const valid = theme === 'light' ? 'light' : 'dark';
		document.documentElement.setAttribute('data-theme', valid);
		localStorage.setItem(STORAGE_THEME, valid);
	}

	function toggleTheme() {
		const current = document.documentElement.getAttribute('data-theme');
		applyTheme(current === 'dark' ? 'light' : 'dark');
	}

	function updateEndpointUI() {
		$('input-endpoint-url').value = state.endpoint;
	}

	// =========================================================================
	// Auto-save
	// =========================================================================

	const AUTOSAVE_LABELS = { 0: 'Off', 1: 'Hourly', 6: 'Every 6 h', 12: 'Every 12 h', 24: 'Daily' };

	function renderAutosave() {
		$('autosave-status').textContent = AUTOSAVE_LABELS[state.autosaveHours];
		$('setting-autosave').value = String(state.autosaveHours);
	}

	function setAutosaveHours(value) {
		const next = Autosave.normalizeHours(value);
		const lastRun = Number(localStorage.getItem(STORAGE_AUTOSAVE_LAST)) || 0;
		localStorage.setItem(
			STORAGE_AUTOSAVE_LAST,
			String(Autosave.lastRunAfterChange(state.autosaveHours, next, lastRun, Date.now()))
		);
		state.autosaveHours = next;
		localStorage.setItem(STORAGE_AUTOSAVE_HOURS, String(next));
		renderAutosave();
	}

	async function runAutosaveIfDue() {
		if (state.busy) return;
		const lastRun = Number(localStorage.getItem(STORAGE_AUTOSAVE_LAST)) || 0;
		if (!Autosave.isDue(state.autosaveHours, lastRun, Date.now())) return;
		// Recorded before saving, so a failing run is not retried every minute.
		localStorage.setItem(STORAGE_AUTOSAVE_LAST, String(Date.now()));
		state.busy = true;
		renderAllWorkspacePanes();
		let remaining = Autosave.MAX_FILES_PER_RUN;
		let saved = 0;
		const failures = [];
		for (const ws of state.workspaces) {
			if (remaining <= 0) break;
			if (ws.exists === false) continue;
			try {
				const scan = normalizeScanResult(await ipcInvoke('scan_workspace', { path: ws.path }));
				const paths = Autosave.pickFiles(scan.files, remaining);
				if (paths.length === 0) continue;
				remaining -= paths.length;
				const res = await ipcInvoke('anchor_files', {
					workspace_path: ws.path,
					relative_paths: paths,
					canon_override: $('anchor-canon').value || null,
					note: 'Auto-save',
					offline: $('anchor-offline').checked
				});
				saved += res.anchored_count ?? paths.length;
			} catch (err) {
				failures.push(`${ws.name}: ${err.message}`);
			}
		}
		state.busy = false;
		if (saved > 0) showToast(`Auto-saved ${saved} file(s)`, 'success');
		if (failures.length > 0) showToast(`Auto-save failed for ${failures.join('; ')}`, 'warn');
		await refreshActiveWorkspace();
		renderAllWorkspacePanes();
	}

	// =========================================================================
	// Data Loading
	// =========================================================================

	async function loadIdentity() {
		try {
			const id = await ipcInvoke('get_identity');
			state.identity = id;
			const pub = id.pubkey || 'anonymous';
			$('identity-pubkey-short').textContent =
				pub.length > 26 ? `${pub.slice(0, 18)}…${pub.slice(-8)}` : pub;
			$('identity-key-path').textContent = id.key_path || '~/.config/oake/id_ed25519.json';
			if (id.default_endpoint && !localStorage.getItem(STORAGE_ENDPOINT)) {
				state.endpoint = id.default_endpoint;
				updateEndpointUI();
			}
		} catch (err) {
			showToast(`Identity error: ${err.message}`, 'error');
		}
	}

	async function loadWorkspaces(preserveSelection = true) {
		try {
			const list = await ipcInvoke('list_workspaces');
			state.workspaces = Array.isArray(list) ? list : [];

			if (!preserveSelection || !state.activeWorkspacePath) {
				state.activeWorkspacePath = state.workspaces[0]?.path || null;
			} else if (!state.workspaces.some((w) => w.path === state.activeWorkspacePath)) {
				state.activeWorkspacePath = state.workspaces[0]?.path || null;
			}

			renderWorkspacesSidebar();
			if (state.activeWorkspacePath) {
				await scanWorkspace(state.activeWorkspacePath);
			} else {
				state.scan = null;
				renderAllWorkspacePanes();
			}
		} catch (err) {
			showToast(`Failed to load workspaces: ${err.message}`, 'error');
		}
	}

	function normalizeScanResult(raw) {
		const wsPath = raw.path || raw.workspace_path || '';
		const wsName = raw.name || raw.workspace_name || wsPath.split(/[\\/]/).pop() || wsPath;
		const files = (raw.files || []).map((f) => ({
			...f,
			canon: f.canon || f.canonicalization || 'raw-bytes/v1',
			last_entry_id: f.last_entry_id ?? f.latest_entry_id ?? null
		}));
		const rawHistory = raw.history || raw.commits || [];
		const history = rawHistory.map((h) => {
			const relOrAbs = h.bundle_path || '';
			const isAbs = relOrAbs.startsWith('/') || /^[A-Za-z]:[\\/]/.test(relOrAbs);
			const fullBundlePath = isAbs || !wsPath ? relOrAbs : `${wsPath.replace(/[\\/]+$/, '')}/${relOrAbs}`;
			return {
				...h,
				client_ts: h.client_ts || h.captured_ts || null,
				path_label: h.path_label || h.file_label || h.path_hint || `${(h.artifact_hash || '').slice(0, 18)}…`,
				bundle_path: fullBundlePath,
				relative_bundle_path: h.relative_bundle_path || h.bundle_path || ''
			};
		});
		return { path: wsPath, name: wsName, files, history };
	}

	async function scanWorkspace(wsPath) {
		try {
			const rawScan = await ipcInvoke('scan_workspace', { path: wsPath });
			const scan = normalizeScanResult(rawScan);
			state.scan = scan;
			state.activeWorkspacePath = scan.path;

			// Default selection: select all untracked/modified files
			const dirty = scan.files.filter((f) => f.status !== 'anchored');
			state.selectedFilePaths = new Set(dirty.map((f) => f.relative_path));

			if (
				!state.inspectedFilePath ||
				!scan.files.some((f) => f.relative_path === state.inspectedFilePath)
			) {
				state.inspectedFilePath = dirty[0]?.relative_path || scan.files[0]?.relative_path || null;
			}

			const sortedHistory = getSortedHistory();
			if (
				!state.inspectedHistoryId ||
				!sortedHistory.some((h) => h.entry_id === state.inspectedHistoryId)
			) {
				state.inspectedHistoryId = sortedHistory[0]?.entry_id || null;
			}

			renderAllWorkspacePanes();
		} catch (err) {
			showToast(`Scan failed: ${err.message}`, 'error');
		}
	}

	async function refreshActiveWorkspace() {
		if (!state.activeWorkspacePath) return;
		await scanWorkspace(state.activeWorkspacePath);
		const list = await ipcInvoke('list_workspaces');
		state.workspaces = Array.isArray(list) ? list : state.workspaces;
		renderWorkspacesSidebar();
		await loadIdentity();
	}

	function getSortedHistory() {
		if (!state.scan?.history) return [];
		return state.scan.history.slice().sort((a, b) => (b.sequence || 0) - (a.sequence || 0));
	}

	// =========================================================================
	// Rendering
	// =========================================================================

	function renderWorkspacesSidebar() {
		const container = $('workspace-list');
		if (state.workspaces.length === 0) {
			container.innerHTML = `
				<div class="sidebar-empty">
					<p>No folders yet.</p>
					<button class="tb-btn" id="btn-empty-add-ws">Add folder</button>
				</div>
			`;
			const emptyBtn = $('btn-empty-add-ws');
			if (emptyBtn) emptyBtn.addEventListener('click', openAddWorkspaceModal);
			return;
		}

		container.innerHTML = state.workspaces
			.map((ws) => {
				const isActive = ws.path === state.activeWorkspacePath;
				const dirtyCount = Number(ws.modified_count || 0) + Number(ws.untracked_count || 0);
				const trackedCount = Number(ws.anchored_count ?? ws.tracked_count ?? 0);
				const badgeClass = dirtyCount > 0 ? 'ws-badge' : 'ws-badge clean';
				const badgeLabel = dirtyCount > 0 ? `${dirtyCount}` : '✓';
				const sub = ws.missing || ws.exists === false
					? 'Folder missing on disk'
					: `${trackedCount} saved · ${ws.last_anchored_ts ? formatTime(ws.last_anchored_ts) : 'never'}`;
				return `
					<div class="ws-item ${isActive ? 'active' : ''}" data-ws-path="${escapeHtml(ws.path)}" title="${escapeHtml(ws.path)}">
						<div class="ws-item-left">
							<svg class="ws-folder-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
							</svg>
							<div class="ws-item-info">
								<div class="ws-item-name">${escapeHtml(ws.name)}</div>
								<div class="ws-item-sub">${escapeHtml(sub)}</div>
							</div>
						</div>
						<div class="ws-item-right">
							<span class="${badgeClass}" title="${dirtyCount} unsaved change(s)">${badgeLabel}</span>
							<button class="ws-remove-btn" data-remove-ws="${escapeHtml(ws.path)}" title="Remove folder from list">×</button>
						</div>
					</div>
				`;
			})
			.join('');

		container.querySelectorAll('.ws-item').forEach((el) => {
			el.addEventListener('click', async (ev) => {
				if (ev.target.closest('[data-remove-ws]')) return;
				const wsPath = el.getAttribute('data-ws-path');
				if (wsPath) {
					state.activeWorkspacePath = wsPath;
					renderWorkspacesSidebar();
					await scanWorkspace(wsPath);
				}
			});
		});

		container.querySelectorAll('[data-remove-ws]').forEach((btn) => {
			btn.addEventListener('click', async (ev) => {
				ev.stopPropagation();
				const wsPath = btn.getAttribute('data-remove-ws');
				try {
					await ipcInvoke('remove_workspace', { path: wsPath });
					showToast('Folder removed', 'info');
					await loadWorkspaces(true);
				} catch (err) {
					showToast(`Remove failed: ${err.message}`, 'error');
				}
			});
		});
	}

	function renderAllWorkspacePanes() {
		const hasWs = Boolean(state.scan);
		$('active-ws-name').textContent = hasWs ? state.scan.name : 'No folder selected';
		$('active-ws-path').textContent = hasWs
			? state.scan.path
			: '';

		$('btn-rescan').disabled = !hasWs || state.busy;
		$('btn-push').disabled = !hasWs || state.busy;

		renderChangesTab();
		renderHistoryTab();
		renderInspector();
	}

	function renderChangesTab() {
		const files = state.scan?.files || [];
		const dirtyFiles = files.filter((f) => f.status !== 'anchored');
		const anchoredFiles = files.filter((f) => f.status === 'anchored');

		$('tab-count-changes').textContent = String(dirtyFiles.length);
		$('changes-summary-text').textContent =
			dirtyFiles.length === 1 ? '1 changed file' : `${dirtyFiles.length} changed files`;

		const selectAllBox = $('checkbox-select-all');
		if (dirtyFiles.length === 0) {
			selectAllBox.checked = false;
			selectAllBox.indeterminate = false;
			selectAllBox.disabled = true;
		} else {
			const selectedDirtyCount = dirtyFiles.filter((f) =>
				state.selectedFilePaths.has(f.relative_path)
			).length;
			selectAllBox.disabled = false;
			selectAllBox.checked = selectedDirtyCount === dirtyFiles.length;
			selectAllBox.indeterminate =
				selectedDirtyCount > 0 && selectedDirtyCount < dirtyFiles.length;
		}

		const container = $('changes-list-container');
		if (!state.scan) {
			container.innerHTML = `
				<div class="sidebar-empty" style="margin-top: 40px;">
					<p>Add a folder to start.</p>
				</div>
			`;
			updateAnchorButton();
			return;
		}

		let html = '';

		if (dirtyFiles.length === 0) {
			html += `
				<div class="sidebar-empty" style="padding: 24px 16px;">
					<p>No unsaved changes.</p>
				</div>
			`;
		} else {
			html += dirtyFiles
				.map((f) => {
					const checked = state.selectedFilePaths.has(f.relative_path) ? 'checked' : '';
					const selectedClass = state.inspectedFilePath === f.relative_path ? 'selected' : '';
					const badge =
						f.status === 'modified'
							? '<span class="status-badge badge-modified">Changed</span>'
							: '<span class="status-badge badge-new">New</span>';
					return `
						<div class="file-row ${selectedClass}" data-file-path="${escapeHtml(f.relative_path)}">
							<div class="file-row-left">
								<input type="checkbox" class="file-checkbox" data-check-path="${escapeHtml(f.relative_path)}" ${checked} />
								<div class="file-row-info">
									<div class="file-rel">${escapeHtml(f.relative_path)}</div>
									<div class="file-sub">${escapeHtml(f.canon)} · ${formatBytes(f.byte_size)}</div>
								</div>
							</div>
							${badge}
						</div>
					`;
				})
				.join('');
		}

		if (anchoredFiles.length > 0) {
			const arrow = state.anchoredCollapsed ? '▸' : '▾';
			html += `
				<button type="button" class="collapsible-group-head" id="btn-toggle-anchored">
					<span>${arrow} Saved (${anchoredFiles.length})</span>
				</button>
			`;
			if (!state.anchoredCollapsed) {
				html += anchoredFiles
					.map((f) => {
						const selectedClass = state.inspectedFilePath === f.relative_path ? 'selected' : '';
						return `
							<div class="file-row ${selectedClass}" data-file-path="${escapeHtml(f.relative_path)}">
								<div class="file-row-left">
									<div class="file-row-info">
										<div class="file-rel">${escapeHtml(f.relative_path)}</div>
										<div class="file-sub">${escapeHtml(f.canon)} · ${formatBytes(f.byte_size)}</div>
									</div>
								</div>
								<span class="status-badge badge-anchored">Saved</span>
							</div>
						`;
					})
					.join('');
			}
		}

		container.innerHTML = html;

		container.querySelectorAll('.file-checkbox').forEach((cb) => {
			cb.addEventListener('click', (ev) => ev.stopPropagation());
			cb.addEventListener('change', () => {
				const p = cb.getAttribute('data-check-path');
				if (!p) return;
				if (cb.checked) state.selectedFilePaths.add(p);
				else state.selectedFilePaths.delete(p);
				renderChangesTab();
			});
		});

		container.querySelectorAll('.file-row').forEach((row) => {
			row.addEventListener('click', () => {
				state.inspectedFilePath = row.getAttribute('data-file-path');
				renderChangesTab();
				renderInspector();
			});
		});

		const toggleAnchored = $('btn-toggle-anchored');
		if (toggleAnchored) {
			toggleAnchored.addEventListener('click', () => {
				state.anchoredCollapsed = !state.anchoredCollapsed;
				renderChangesTab();
			});
		}

		updateAnchorButton();
	}

	function updateAnchorButton() {
		const count = state.selectedFilePaths.size;
		const btn = $('btn-anchor-submit');
		const offline = $('anchor-offline').checked ? ' (offline)' : '';
		btn.textContent = `Save ${count} file${count === 1 ? '' : 's'}${offline}`;
		btn.disabled = !state.scan || count === 0 || state.busy;
	}

	function renderHistoryTab() {
		const sorted = getSortedHistory();
		$('tab-count-history').textContent = String(sorted.length);

		const filter = state.historyFilter.trim().toLowerCase();
		const filtered = filter
			? sorted.filter(
					(h) =>
						(h.entry_id || '').toLowerCase().includes(filter) ||
						(h.artifact_hash || '').toLowerCase().includes(filter) ||
						(h.path_label || '').toLowerCase().includes(filter) ||
						(h.note || '').toLowerCase().includes(filter)
				)
			: sorted;

		const container = $('history-list-container');
		if (!state.scan) {
			container.innerHTML = `<div class="sidebar-empty" style="margin-top:40px;"><p>No folder selected.</p></div>`;
			return;
		}
		if (filtered.length === 0) {
			container.innerHTML = `<div class="sidebar-empty" style="margin-top:40px;"><p>${sorted.length === 0 ? 'Nothing saved yet.' : 'No matches.'}</p></div>`;
			return;
		}

		container.innerHTML = filtered
			.map((h) => {
				const selectedClass = state.inspectedHistoryId === h.entry_id ? 'selected' : '';
				const otsLabel =
					h.ots_status === 'upgraded'
						? `Bitcoin block ${h.btc_block ?? ''}`
						: h.ots_status === 'pending'
							? 'Bitcoin: pending'
							: 'Bitcoin: not submitted';
				const otsClass =
					h.ots_status === 'upgraded'
						? 'badge-new'
						: h.ots_status === 'pending'
							? 'badge-sky'
							: 'badge-modified';
				const syncBadge = h.published_to
					? `<span class="status-badge badge-new" title="Witnessed on ${escapeHtml(h.published_to)}">Published</span>`
					: `<span class="status-badge badge-anchored" style="color:var(--text-muted)">Not published</span>`;
				const tsaCount = Number(h.tsa_count || 0);
				const tsaText =
					Array.isArray(h.tsa_names) && h.tsa_names.length > 0
						? `Timestamps: ${h.tsa_names.join(', ')}`
						: `Timestamps: ${escapeHtml(tsaCount)}`;

				return `
					<div class="history-row ${selectedClass}" data-history-id="${escapeHtml(h.entry_id)}">
						<div class="history-row-top">
							<span class="history-seq">#${escapeHtml(h.sequence)}</span>
							<span class="history-time">${escapeHtml(formatTime(h.client_ts))}</span>
						</div>
						<div class="history-title">${escapeHtml(h.note || h.path_label || h.entry_id)}</div>
						<div class="history-pills">
							<span class="status-badge ${tsaCount > 0 ? 'badge-new' : 'badge-modified'}">${escapeHtml(tsaText)}</span>
							<span class="status-badge ${otsClass}">${escapeHtml(otsLabel)}</span>
							${syncBadge}
							<button type="button" class="mini-btn mini-btn-accent" data-verify-entry="${escapeHtml(h.entry_id)}">Verify</button>
						</div>
					</div>
				`;
			})
			.join('');

		container.querySelectorAll('.history-row').forEach((row) => {
			row.addEventListener('click', (ev) => {
				if (ev.target.closest('[data-verify-entry]')) return;
				state.inspectedHistoryId = row.getAttribute('data-history-id');
				renderHistoryTab();
				renderInspector();
			});
		});

		container.querySelectorAll('[data-verify-entry]').forEach((btn) => {
			btn.addEventListener('click', async (ev) => {
				ev.stopPropagation();
				const entryId = btn.getAttribute('data-verify-entry');
				const item = sorted.find((h) => h.entry_id === entryId);
				if (!item) return;
				switchTab('verify');
				$('verify-bundle-path').value = item.bundle_path || '';
				const matchingFile = state.scan?.files.find((f) => f.relative_path === item.path_label);
				$('verify-original-path').value = matchingFile
					? `${state.scan.path}/${matchingFile.relative_path}`
					: '';
				await runVerifyBundle();
			});
		});
	}

	function renderInspector() {
		const pane = $('pane-inspector');

		if (state.activeTab === 'verify') {
			renderVerifyInspector(pane);
			return;
		}

		if (!state.scan) {
			pane.innerHTML = '';
			return;
		}

		if (state.activeTab === 'changes') {
			const file = state.scan.files.find((f) => f.relative_path === state.inspectedFilePath);
			if (!file) {
				pane.innerHTML = `<div class="inspector-empty"><p>Select a file to see its details.</p></div>`;
				return;
			}
			const badge =
				file.status === 'anchored'
					? '<span class="status-badge badge-anchored">Saved</span>'
					: file.status === 'modified'
						? '<span class="status-badge badge-modified">Changed</span>'
						: '<span class="status-badge badge-new">New</span>';
			pane.innerHTML = `
				<div class="inspector-header">
					<div>
						<div class="inspector-title font-mono">${escapeHtml(file.relative_path)}</div>
						<div class="inspector-sub">${escapeHtml(state.scan.name)}</div>
					</div>
					${badge}
				</div>

				<div class="inspector-card">
					<h4>File details</h4>
					<div class="kv-grid">
						<span class="kv-key">Fingerprint</span>
						<span class="kv-val font-mono">${escapeHtml(file.artifact_hash)}</span>
						<span class="kv-key">Format</span>
						<span class="kv-val font-mono">${escapeHtml(file.canon)}</span>
						<span class="kv-key">Size</span>
						<span class="kv-val font-mono">${formatBytes(file.byte_size)} (${escapeHtml(file.byte_size)} bytes)</span>
						<span class="kv-key">Last save</span>
						<span class="kv-val font-mono">${escapeHtml(file.last_entry_id || 'Never')}</span>
					</div>
				</div>

			`;
			return;
		}

		// History Inspector
		const sorted = getSortedHistory();
		const entry = sorted.find((h) => h.entry_id === state.inspectedHistoryId);
		if (!entry) {
			pane.innerHTML = `<div class="inspector-empty"><p>Select an entry to see its proof.</p></div>`;
			return;
		}

		const digestHex = (entry.artifact_hash || '').replace(/^sha256:/i, '');
		const tsaList =
			Array.isArray(entry.tsa_names) && entry.tsa_names.length > 0
				? entry.tsa_names
				: [];

		pane.innerHTML = `
			<div class="inspector-header">
				<div>
					<div class="inspector-title">#${escapeHtml(entry.sequence)} · ${escapeHtml(entry.note || entry.path_label)}</div>
					<div class="inspector-sub font-mono">${escapeHtml(entry.entry_id)}</div>
				</div>
				<button type="button" class="btn-anchor-primary btn-compact" id="btn-inspector-verify">Verify</button>
			</div>

			<div class="inspector-card">
				<h4>Details</h4>
				<div class="kv-grid">
					<span class="kv-key">Fingerprint</span>
					<span class="kv-val font-mono">${escapeHtml(entry.artifact_hash)}</span>
					<span class="kv-key">Format</span>
					<span class="kv-val font-mono">${escapeHtml(entry.canonicalization)}</span>
					<span class="kv-key">Saved at</span>
					<span class="kv-val font-mono">${escapeHtml(entry.client_ts || '—')}</span>
					<span class="kv-key">Proof file</span>
					<span class="kv-val font-mono">${escapeHtml(entry.bundle_path)}</span>
					<span class="kv-key">Published to</span>
					<span class="kv-val font-mono">${escapeHtml(entry.published_to || 'Not published')}</span>
				</div>
			</div>

			<div class="inspector-card">
				<h4>Timestamps</h4>
				<div class="tsa-grid">
					<div class="tsa-card">
						<div class="tsa-card-top">
							<span>Timestamp authorities (${escapeHtml(entry.tsa_count)})</span>
							<span class="status-badge ${entry.tsa_count > 0 ? 'badge-new' : 'badge-modified'}">${entry.tsa_count > 0 ? 'Received' : 'None'}</span>
						</div>
						<div class="tsa-card-meta">${tsaList.length > 0 ? escapeHtml(tsaList.join(' · ')) : 'No external timestamp'}</div>
					</div>
					<div class="tsa-card">
						<div class="tsa-card-top">
							<span>Bitcoin</span>
							<span class="status-badge ${entry.ots_status === 'upgraded' ? 'badge-new' : entry.ots_status === 'pending' ? 'badge-sky' : 'badge-modified'}">${escapeHtml(String(entry.ots_status))}</span>
						</div>
						<div class="tsa-card-meta">${entry.btc_block ? `Block ${escapeHtml(entry.btc_block)}` : `Calendar: ${escapeHtml(entry.ots_calendar)}`}</div>
					</div>
				</div>
			</div>

			<div class="inspector-card">
				<h4>Check it yourself</h4>
				<p class="settings-help">Unzip the proof file, then run:</p>
				${entry.tsa_count > 0 ? `<div class="cmd-box font-mono">
					<code>openssl ts -verify -digest ${escapeHtml(digestHex)} -in rfc3161/${escapeHtml(entry.entry_id)}-certum-eu.tsr -CAfile /etc/ssl/cert.pem</code>
					<button type="button" class="mini-btn" data-copy-cmd="openssl ts -verify -digest ${escapeHtml(digestHex)} -in rfc3161/${escapeHtml(entry.entry_id)}-certum-eu.tsr -CAfile /etc/ssl/cert.pem">Copy</button>
				</div>` : ''}
				<div class="cmd-box font-mono">
					<code>ots verify proof.ots</code>
					<button type="button" class="mini-btn" data-copy-cmd="ots verify proof.ots">Copy</button>
				</div>
			</div>
		`;

		const verifyBtn = $('btn-inspector-verify');
		if (verifyBtn) {
			verifyBtn.addEventListener('click', async () => {
				switchTab('verify');
				$('verify-bundle-path').value = entry.bundle_path || '';
				const matchingFile = state.scan?.files.find((f) => f.relative_path === entry.path_label);
				$('verify-original-path').value = matchingFile
					? `${state.scan.path}/${matchingFile.relative_path}`
					: '';
				await runVerifyBundle();
			});
		}

		pane.querySelectorAll('[data-copy-cmd]').forEach((btn) => {
			btn.addEventListener('click', () => copyText(btn.getAttribute('data-copy-cmd'), 'Command copied'));
		});
	}

	const VERDICT_TITLES = {
		verified: 'Verified',
		incomplete: 'Not fully verified',
		failed: 'Verification failed'
	};

	// The browser preview backend reports only `valid`, so it is never shown as
	// verified without a timestamp token it has checked.
	function verdictOf(res) {
		if (res.verdict) return res.verdict;
		if (!res.valid) return 'failed';
		const tokens = res.tokens || res.tsa_tokens || [];
		const checked = tokens.some((t) => t.openssl_verified === true);
		return checked && res.signature_valid ? 'verified' : 'incomplete';
	}

	function renderVerifyInspector(pane) {
		const res = state.verifyResult;
		if (!res) {
			pane.innerHTML = `
				<div class="inspector-empty">
					<p>Choose a proof file to check it.</p>
				</div>
			`;
			return;
		}

		const digestHex = (res.artifact_hash || '').replace(/^sha256:/i, '');
		const tokens = res.tokens || res.tsa_tokens || [];
		const tsaCount = res.tsa_count ?? tokens.length;
		const btcBlock = res.btc_block ?? res.ots_btc_block ?? null;
		const noTimestamp = tsaCount === 0 && res.ots_status !== 'upgraded';
		const verdict = verdictOf(res);
		const bannerClass = { verified: 'pass', incomplete: 'partial', failed: 'fail' }[verdict];
		const bannerTitle = VERDICT_TITLES[verdict];
		const badgeClass = { verified: 'badge-new', incomplete: 'badge-modified', failed: 'badge-red' }[verdict];
		const badgeLabel = { verified: 'Pass', incomplete: 'Incomplete', failed: 'Fail' }[verdict];
		const detailsText = res.details || res.conclusion || '';
		const opensslList = res.commands?.openssl || [
			`openssl ts -verify -digest ${digestHex} -in rfc3161/<token>.tsr -CAfile /etc/ssl/cert.pem`
		];
		const otsCmd = res.commands?.ots || 'ots verify proof.ots';

		pane.innerHTML = `
			<div class="verify-banner ${bannerClass}">
				<div>
					<div style="font-weight:700; font-size:14px;">${bannerTitle}</div>
					<div class="font-mono" style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(res.entry_id)}</div>
					${noTimestamp ? '<div class="verify-warning">No independent timestamp: this proof does not show when the file existed.</div>' : ''}
				</div>
				<span class="status-badge ${badgeClass}">${badgeLabel}</span>
			</div>

			<div class="verify-checks-list">
				<div class="check-tile">
					<div class="check-tile-head">
						<span>Signature</span>
						<span class="status-badge ${res.signature_valid ? 'badge-new' : res.signature_signed === false ? 'badge-modified' : 'badge-red'}">${res.signature_valid ? 'Valid' : res.signature_signed === false ? 'None' : 'Invalid'}</span>
					</div>
					<div class="check-tile-sub font-mono">${escapeHtml(res.user_pubkey || '—')}</div>
				</div>

				<div class="check-tile">
					<div class="check-tile-head">
						<span>File match</span>
						<span class="status-badge ${res.file_matches === null ? 'badge-anchored' : res.file_matches ? 'badge-new' : 'badge-red'}">${res.file_matches === null ? 'Not checked' : res.file_matches ? 'Matches' : 'Different'}</span>
					</div>
					<div class="check-tile-sub font-mono">${escapeHtml(res.canonicalization || 'raw-bytes/v1')}</div>
				</div>

				<div class="check-tile">
					<div class="check-tile-head">
						<span>Timestamp tokens</span>
						<span class="status-badge ${tsaCount > 0 ? 'badge-new' : 'badge-modified'}">${escapeHtml(tsaCount)}</span>
					</div>
					<div class="check-tile-sub">${tokens.length ? escapeHtml(tokens.map((t) => t.label || t.tsa || t.filename).join(' + ')) : 'None'}</div>
				</div>

				<div class="check-tile">
					<div class="check-tile-head">
						<span>Bitcoin</span>
						<span class="status-badge ${res.ots_status === 'upgraded' ? 'badge-new' : res.ots_status === 'pending' ? 'badge-sky' : 'badge-modified'}">${escapeHtml(String(res.ots_status))}</span>
					</div>
					<div class="check-tile-sub">${btcBlock ? `Bitcoin Block #${escapeHtml(btcBlock)}` : escapeHtml(res.ots_calendar || 'alice.btc.calendar.opentimestamps.org')}</div>
				</div>
			</div>

			<div class="inspector-card">
				<h4>Output</h4>
				<pre class="cli-pre font-mono">${escapeHtml(detailsText)}</pre>
			</div>

			<div class="inspector-card">
				<h4>Check it yourself</h4>
				${(tsaCount > 0 ? opensslList : [])
					.map(
						(cmd) => `
					<div class="cmd-box font-mono">
						<code>${escapeHtml(cmd)}</code>
						<button type="button" class="mini-btn" data-copy-cmd="${escapeHtml(cmd)}">Copy</button>
					</div>
				`
					)
					.join('')}
				<div class="cmd-box font-mono">
					<code>${escapeHtml(otsCmd)}</code>
					<button type="button" class="mini-btn" data-copy-cmd="${escapeHtml(otsCmd)}">Copy</button>
				</div>
			</div>
		`;

		pane.querySelectorAll('[data-copy-cmd]').forEach((btn) => {
			btn.addEventListener('click', () => copyText(btn.getAttribute('data-copy-cmd'), 'Command copied'));
		});
	}

	// =========================================================================
	// Actions & Tab Navigation
	// =========================================================================

	function switchTab(tabName) {
		state.activeTab = tabName;
		document.querySelectorAll('.tab-btn').forEach((btn) => {
			const active = btn.getAttribute('data-tab') === tabName;
			btn.classList.toggle('active', active);
			btn.setAttribute('aria-selected', String(active));
		});
		document.querySelectorAll('.tab-panel').forEach((panel) => {
			panel.classList.toggle('active', panel.id === `panel-${tabName}`);
		});
		renderInspector();
	}

	async function runAnchorFiles(ev) {
		ev.preventDefault();
		if (!state.activeWorkspacePath || state.selectedFilePaths.size === 0 || state.busy) return;
		state.busy = true;
		renderAllWorkspacePanes();
		try {
			const res = await ipcInvoke('anchor_files', {
				workspace_path: state.activeWorkspacePath,
				relative_paths: Array.from(state.selectedFilePaths),
				canon_override: $('anchor-canon').value || null,
				note: $('anchor-note').value.trim() || null,
				offline: $('anchor-offline').checked
			});
			$('anchor-note').value = '';
			const rateLimited = Boolean(res.rate_limited || res.ots_rate_limited);
			showToast(
				res.message || `Saved ${res.anchored_count} file(s)`,
				rateLimited ? 'warn' : 'success'
			);
			await refreshActiveWorkspace();
		} catch (err) {
			showToast(`Save failed: ${err.message}`, 'error');
		} finally {
			state.busy = false;
			renderAllWorkspacePanes();
		}
	}

	async function runPushWorkspace() {
		if (!state.activeWorkspacePath || state.busy) return;
		state.busy = true;
		renderAllWorkspacePanes();
		try {
			const res = await ipcInvoke('push_workspace', {
				workspace_path: state.activeWorkspacePath,
				endpoint: state.endpoint
			});
			showToast(
				res.message || `Published ${res.pushed_count} proof(s)`,
				'success'
			);
			await refreshActiveWorkspace();
		} catch (err) {
			showToast(`Publish failed: ${err.message}`, 'error');
		} finally {
			state.busy = false;
			renderAllWorkspacePanes();
		}
	}

	async function runVerifyBundle(ev) {
		if (ev) ev.preventDefault();
		const bundlePath = $('verify-bundle-path').value.trim();
		const originalPath = $('verify-original-path').value.trim();
		if (!bundlePath) {
			showToast('Enter the path to a proof file', 'warn');
			return;
		}
		try {
			const res = await ipcInvoke('verify_bundle', {
				bundle_path: bundlePath,
				original_file_path: originalPath || null,
				workspace_path: state.activeWorkspacePath
			});
			state.verifyResult = res;
			renderInspector();
			const verdict = verdictOf(res);
			showToast(
				VERDICT_TITLES[verdict],
				{ verified: 'success', incomplete: 'warn', failed: 'error' }[verdict]
			);
		} catch (err) {
			state.verifyResult = null;
			renderInspector();
			showToast(`Verify error: ${err.message}`, 'error');
		}
	}

	// =========================================================================
	// Modals
	// =========================================================================

	function openModal(id) {
		$(id).classList.remove('hidden');
	}

	function closeModal(id) {
		$(id).classList.add('hidden');
	}

	// Updates run only in the installed app, and only when the user asks.
	let offeredVersion = null;

	async function checkForUpdate() {
		const status = $('update-status');
		const button = $('btn-check-update');
		$('btn-install-update').hidden = true;
		$('update-notes').hidden = true;
		if (!isTauri) {
			status.textContent = 'Updates are available in the installed app only.';
			return;
		}
		button.disabled = true;
		status.textContent = 'Checking…';
		try {
			const res = await ipcInvoke('check_for_update');
			offeredVersion = res.available?.version || null;
			if (!res.configured) {
				status.textContent = `Version ${res.current_version}. Updates are not set up for this build.`;
			} else if (!offeredVersion) {
				status.textContent = `Version ${res.current_version} is up to date.`;
			} else {
				status.textContent = `Version ${offeredVersion} is available. You have ${res.current_version}.`;
				$('update-notes').textContent = res.available.notes || '';
				$('update-notes').hidden = !res.available.notes;
				$('btn-install-update').hidden = false;
			}
		} catch (err) {
			status.textContent = err.message;
		} finally {
			button.disabled = false;
		}
	}

	async function installUpdate() {
		const buttons = [$('btn-check-update'), $('btn-install-update')];
		buttons.forEach((b) => (b.disabled = true));
		$('update-status').textContent = `Downloading and installing ${offeredVersion}…`;
		try {
			await ipcInvoke('install_update', { version: offeredVersion });
		} catch (err) {
			$('update-status').textContent = err.message;
			buttons.forEach((b) => (b.disabled = false));
		}
	}

	function openSettings(focusId) {
		updateEndpointUI();
		renderAutosave();
		$('setting-theme').value = document.documentElement.getAttribute('data-theme');
		openModal('modal-settings');
		if (focusId) $(focusId).focus();
	}

	function openAddWorkspaceModal() {
		openModal('modal-add-ws');
		$('input-ws-path').focus();
	}

	async function loadDirBrowser(dirPath) {
		try {
			const res = await ipcInvoke('browse_directory', dirPath ? { path: dirPath } : {});
			state.browseDirPath = res.current;
			$('dir-current-label').textContent = res.current;
			$('btn-browse-up').disabled = !res.parent;
			$('btn-browse-up').onclick = () => res.parent && loadDirBrowser(res.parent);

			const list = $('dir-browser-list');
			if (!res.directories.length) {
				list.innerHTML = `<div style="padding:10px; color:var(--text-muted); font-size:11.5px;">No subdirectories</div>`;
				return;
			}
			list.innerHTML = res.directories
				.map(
					(d) => `
					<button type="button" class="dir-entry font-mono" data-dir-path="${escapeHtml(d.path)}">
						<span>📁 ${escapeHtml(d.name)}</span>
						${d.has_oake ? '<span class="status-badge badge-new">.oake/</span>' : ''}
					</button>
				`
				)
				.join('');
			list.querySelectorAll('.dir-entry').forEach((btn) => {
				btn.addEventListener('click', () => loadDirBrowser(btn.getAttribute('data-dir-path')));
			});
		} catch (err) {
			$('dir-browser').classList.add('hidden');
			showToast(`Directory browser unavailable: ${err.message}`, 'info');
		}
	}

	// =========================================================================
	// Event Bindings & Bootstrap
	// =========================================================================

	function bindEvents() {
		$('btn-open-settings').addEventListener('click', () => openSettings());
		$('btn-check-update').addEventListener('click', checkForUpdate);
		$('btn-install-update').addEventListener('click', installUpdate);
		$('btn-autosave').addEventListener('click', () => openSettings('setting-autosave'));
		$('setting-autosave').addEventListener('change', (ev) => setAutosaveHours(ev.target.value));
		$('setting-theme').addEventListener('change', (ev) => applyTheme(ev.target.value));
		$('anchor-canon').addEventListener('change', (ev) => localStorage.setItem(STORAGE_CANON, ev.target.value));
		$('anchor-offline').addEventListener('change', (ev) => {
			localStorage.setItem(STORAGE_OFFLINE, String(ev.target.checked));
			updateAnchorButton();
		});

		$('btn-open-add-ws').addEventListener('click', openAddWorkspaceModal);
		$('btn-rescan').addEventListener('click', () => refreshActiveWorkspace());
		$('btn-push').addEventListener('click', runPushWorkspace);
		$('btn-copy-pubkey').addEventListener('click', () => {
			if (state.identity?.pubkey) {
				copyText(state.identity.pubkey, 'Copied Ed25519 public key');
			}
		});

		document.querySelectorAll('.tab-btn').forEach((btn) => {
			btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab')));
		});

		$('checkbox-select-all').addEventListener('change', (ev) => {
			const files = (state.scan?.files || []).filter((f) => f.status !== 'anchored');
			if (ev.target.checked) {
				files.forEach((f) => state.selectedFilePaths.add(f.relative_path));
			} else {
				state.selectedFilePaths.clear();
			}
			renderChangesTab();
		});

		$('anchor-form').addEventListener('submit', runAnchorFiles);
		$('history-filter').addEventListener('input', (ev) => {
			state.historyFilter = ev.target.value;
			renderHistoryTab();
		});
		$('verify-form').addEventListener('submit', runVerifyBundle);

		$('form-add-ws').addEventListener('submit', async (ev) => {
			ev.preventDefault();
			const folderPath = $('input-ws-path').value.trim();
			if (!folderPath) return;
			try {
				const added = await ipcInvoke('add_workspace', { path: folderPath });
				closeModal('modal-add-ws');
				$('input-ws-path').value = '';
				$('dir-browser').classList.add('hidden');
				state.activeWorkspacePath = added?.path || folderPath;
				showToast(`Added folder: ${added?.name || folderPath}`, 'success');
				await loadWorkspaces(true);
			} catch (err) {
				showToast(`Could not add folder: ${err.message}`, 'error');
			}
		});

		$('btn-browse-toggle').addEventListener('click', async () => {
			if (isTauri) {
				// Native folder picker.
				try {
					const picked = await window.__TAURI_INTERNALS__.invoke('plugin:dialog|open', {
						options: { directory: true, multiple: false, title: 'Choose a folder' }
					});
					if (picked) $('input-ws-path').value = picked;
				} catch (err) {
					showToast(`Could not open the folder picker: ${err.message}`, 'error');
				}
				return;
			}
			const box = $('dir-browser');
			if (box.classList.contains('hidden')) {
				box.classList.remove('hidden');
				await loadDirBrowser($('input-ws-path').value.trim() || state.browseDirPath);
			} else {
				box.classList.add('hidden');
			}
		});

		$('btn-use-current-dir').addEventListener('click', () => {
			if (state.browseDirPath) {
				$('input-ws-path').value = state.browseDirPath;
				$('dir-browser').classList.add('hidden');
			}
		});

		$('form-endpoint').addEventListener('submit', async (ev) => {
			ev.preventDefault();
			const url = $('input-endpoint-url').value.trim().replace(/\/+$/, '');
			if (!url) return;
			state.endpoint = url;
			localStorage.setItem(STORAGE_ENDPOINT, url);
			updateEndpointUI();
			showToast('Server address saved', 'success');
		});

		document.querySelectorAll('[data-close-modal]').forEach((btn) => {
			btn.addEventListener('click', () => closeModal(btn.getAttribute('data-close-modal')));
		});

		document.querySelectorAll('.modal-backdrop').forEach((backdrop) => {
			backdrop.addEventListener('click', (ev) => {
				if (ev.target === backdrop) backdrop.classList.add('hidden');
			});
		});

		document.addEventListener('keydown', (ev) => {
			const mod = ev.metaKey || ev.ctrlKey;
			const tag = document.activeElement?.tagName;
			const inInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';

			if (ev.key === 'Escape') {
				closeModal('modal-add-ws');
				closeModal('modal-settings');
				return;
			}
			if (mod && ev.key === ',') {
				ev.preventDefault();
				openSettings();
				return;
			}
			if (document.querySelector('.modal-backdrop:not(.hidden)')) return;
			if (mod && ev.key.toLowerCase() === 'r') {
				ev.preventDefault();
				refreshActiveWorkspace();
				return;
			}
			if (mod && ev.shiftKey && ev.key.toLowerCase() === 'd') {
				ev.preventDefault();
				toggleTheme();
				return;
			}
			if (mod && ev.shiftKey && ev.key.toLowerCase() === 'p') {
				ev.preventDefault();
				runPushWorkspace();
				return;
			}
			if (mod && ev.key === 'Enter' && state.activeTab === 'changes') {
				ev.preventDefault();
				$('anchor-form').requestSubmit();
				return;
			}
			if (!inInput && !mod && !ev.altKey) {
				if (ev.key === '1') switchTab('changes');
				else if (ev.key === '2') switchTab('history');
				else if (ev.key === '3') switchTab('verify');
			}
		});
	}

	async function init() {
		applyTheme(localStorage.getItem(STORAGE_THEME) || 'dark');
		updateEndpointUI();
		$('anchor-canon').value = localStorage.getItem(STORAGE_CANON) || '';
		$('anchor-offline').checked = localStorage.getItem(STORAGE_OFFLINE) === 'true';
		setAutosaveHours(state.autosaveHours);
		bindEvents();
		updateAnchorButton();

		await loadIdentity();
		await loadWorkspaces(false);

		await runAutosaveIfDue();
		setInterval(runAutosaveIfDue, 60 * 1000);
	}

	document.addEventListener('DOMContentLoaded', init);
})();

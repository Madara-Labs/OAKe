mod oake_core;

use oake_core::{
    AnchorBatchResult, BundleVerifyResult, IdentityInfo, PushSummary, WorkspaceScanResult,
    WorkspaceSummary,
};

/// Run blocking/network OAKe work on a dedicated OS thread outside the Tokio runtime
/// so `reqwest::blocking::Client` never collides with Tauri's async runtime.
async fn run_on_worker_thread<F, T>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    let (tx, mut rx) = tauri::async_runtime::channel::<Result<T, String>>(1);
    std::thread::spawn(move || {
        let _ = tx.blocking_send(work());
    });
    rx.recv()
        .await
        .ok_or_else(|| "Worker thread cancelled".to_string())?
}

#[tauri::command]
async fn get_identity() -> Result<IdentityInfo, String> {
    run_on_worker_thread(oake_core::get_identity).await
}

#[tauri::command]
async fn list_workspaces() -> Result<Vec<WorkspaceSummary>, String> {
    run_on_worker_thread(oake_core::list_workspaces).await
}

#[tauri::command]
async fn add_workspace(path: String) -> Result<WorkspaceSummary, String> {
    run_on_worker_thread(move || oake_core::add_workspace(path)).await
}

#[tauri::command]
async fn remove_workspace(path: String) -> Result<(), String> {
    run_on_worker_thread(move || oake_core::remove_workspace(path)).await
}

#[tauri::command]
async fn scan_workspace(path: String) -> Result<WorkspaceScanResult, String> {
    run_on_worker_thread(move || oake_core::scan_workspace(path)).await
}

#[tauri::command]
async fn anchor_files(
    workspace_path: String,
    relative_paths: Vec<String>,
    canon_override: Option<String>,
    note: Option<String>,
    offline: bool,
) -> Result<AnchorBatchResult, String> {
    run_on_worker_thread(move || {
        oake_core::anchor_files(workspace_path, relative_paths, canon_override, note, offline)
    })
    .await
}

#[tauri::command]
async fn verify_bundle(
    bundle_path: String,
    original_file_path: Option<String>,
) -> Result<BundleVerifyResult, String> {
    run_on_worker_thread(move || oake_core::verify_bundle(bundle_path, original_file_path)).await
}

#[tauri::command]
async fn push_workspace(workspace_path: String, endpoint: String) -> Result<PushSummary, String> {
    run_on_worker_thread(move || oake_core::push_workspace(workspace_path, endpoint)).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_identity,
            list_workspaces,
            add_workspace,
            remove_workspace,
            scan_workspace,
            anchor_files,
            verify_bundle,
            push_workspace,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OAKe Desktop");
}

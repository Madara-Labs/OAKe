//! Checks GitHub Releases for a newer version and installs it when the user asks.
//! Packages are verified against the public key in tauri.conf.json before installing.

use serde::Serialize;
use tauri::{AppHandle, Runtime};
use tauri_plugin_updater::UpdaterExt;

#[derive(Serialize)]
pub struct AvailableUpdate {
    version: String,
    notes: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateStatus {
    current_version: String,
    /// False until a signing public key is set, since no update could be verified.
    configured: bool,
    available: Option<AvailableUpdate>,
}

fn has_public_key(updater: Option<&serde_json::Value>) -> bool {
    updater
        .and_then(|u| u.get("pubkey"))
        .and_then(|k| k.as_str())
        .is_some_and(|k| !k.trim().is_empty())
}

fn configured<R: Runtime>(app: &AppHandle<R>) -> bool {
    has_public_key(app.config().plugins.0.get("updater"))
}

#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<UpdateStatus, String> {
    let mut status = UpdateStatus {
        current_version: app.package_info().version.to_string(),
        configured: configured(&app),
        available: None,
    };
    if status.configured {
        let updater = app.updater().map_err(|e| e.to_string())?;
        status.available = updater
            .check()
            .await
            .map_err(|e| format!("Could not check for updates: {e}"))?
            .map(|u| AvailableUpdate {
                version: u.version,
                notes: u.body,
            });
    }
    Ok(status)
}

/// Installs the version the user was shown, then restarts.
#[tauri::command]
pub async fn install_update(app: AppHandle, version: String) -> Result<(), String> {
    if !configured(&app) {
        return Err("Updates are not set up for this build".to_string());
    }
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| format!("Could not check for updates: {e}"))?
        .filter(|u| u.version == version)
        .ok_or_else(|| "That version is no longer offered. Check again.".to_string())?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| format!("Update failed: {e}"))?;
    app.restart()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn updates_are_off_without_a_public_key() {
        assert!(!has_public_key(None));
        assert!(!has_public_key(Some(&json!({ "pubkey": "" }))));
        assert!(!has_public_key(Some(&json!({ "pubkey": "  " }))));
        assert!(has_public_key(Some(&json!({ "pubkey": "abc" }))));
    }
}

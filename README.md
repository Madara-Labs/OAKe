# OAKe — Open Attestation Kernel

**Local-First Cryptographic Provenance CLI & Cross-Platform Desktop App**  
Licensed under the **Apache License, Version 2.0** (`Copyright 2026 Madara Labs`).

---

## Architecture

OAKe provides verifiable, offline-capable provenance proofs for research artifacts, code, notebooks, and release binaries without requiring a centralized server:

1. **Local-First `.oake/` Repository & Ed25519 Identity**
   - Stores your Ed25519 signing keypair in `~/.config/oake/id_ed25519.json` (`OAKE_HOME`).
   - Appends hash-chained provenance records to `.oake/index.jsonl` and writes self-contained `.oake/proofs/<entry_id>.oake.zip` proof bundles.
   - Supports canonical artifact hashing (`raw-bytes/v1`, `text-normalized/v1`, `ipynb-cells/v1`) and path privacy (`sha256:` hashed path hints by default).

2. **Dual RFC 3161 X.509 Trusted Timestamping Authorities (TSAs)**
   - **Primary EU TSA**: Asseco Certum (`http://time.certum.pl`).
   - **Secondary US TSA**: DigiCert Assured ID (`http://timestamp.digicert.com`, WebTrust; automatic failover to Sectigo UK `http://timestamp.sectigo.com`).

3. **OpenTimestamps (OTS) Bitcoin Anchoring**
   - Batches local artifact digests into a Merkle tree with a 16-byte blinding nonce and submits commitments to **OpenTimestamps Alice** (`https://alice.btc.calendar.opentimestamps.org`, with Finney / Bob failover) using built-in anti-spam rate guards.
   - Upgrades pending `.ots` proofs to confirmed Bitcoin block headers via `oake upgrade`.

4. **Desktop Application (Tauri v2)**
   - Cross-platform native shell (`desktop/src-tauri/`) with zero-dependency WebView UI (`desktop/ui/`) for Windows 11, macOS, and Linux.

---

## Local Development & Desktop Builds

### Preview OAKe Desktop UI Locally

```bash
npm run desktop:preview
```

### Validate Cross-Platform Readiness

Generates missing icons (`scripts/generate-icons.mjs`), verifies RGBA PNG / `.ico` / `.icns` formats, validates `desktop/src-tauri/tauri.conf.json`, Cargo/Rust files, and CI workflows:

```bash
npm run desktop:check
```

### Build Native Installers

Build for the current host OS (collects installers into `dist/<platform>/`, writes `SHA256SUMS.txt`, and dogfoods `oake capture` to produce a `.oake.zip` provenance bundle for the installers):

```bash
npm run desktop:build
```

Platform-specific commands:

```bash
# macOS (.dmg + .app; add --universal for universal-apple-darwin)
npm run desktop:build:macos
node scripts/build-desktop.mjs --platform macos --universal

# Windows 11 (.msi + NSIS .exe)
npm run desktop:build:windows

# Linux (.AppImage + .deb + .rpm)
npm run desktop:build:linux
```

### Standalone CLI Usage

```bash
node cli/oake.mjs init
node cli/oake.mjs capture ./paper.tex
node cli/oake.mjs verify .oake/proofs/<entry_id>.oake.zip --file ./paper.tex --offline
```

---

## 3-OS GitHub Actions Release Pipeline

`.github/workflows/release-desktop.yml` builds native installers across **macOS (`macos-latest`, `universal-apple-darwin`)**, **Windows 11 (`windows-latest`, `x86_64-pc-windows-msvc`)**, and **Linux (`ubuntu-22.04`, `x86_64-unknown-linux-gnu`)**, then runs a `provenance-attestation` job that generates `SHA256SUMS.txt` and stamps it with `node cli/oake.mjs capture` against Certum EU + DigiCert US + OpenTimestamps Alice.

### Triggering a Release or Test Build

- **Tagged Release** (creates a draft GitHub Release with installers, `SHA256SUMS.txt`, and `.oake.zip` proof):
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```
- **On-Demand Test Build** (no tag required — downloads directly from GitHub Actions Artifacts):
  Open the **Actions** tab → **Release Desktop** → **Run workflow** (`workflow_dispatch`).

### Optional Code-Signing Secrets

Configure these repository secrets in `Madara-Labs/OAKe` to enable automatic signing & notarization (builds succeed unsigned if omitted):

| Secret Name | Platform | Purpose |
| --- | --- | --- |
| `APPLE_CERTIFICATE` | macOS | Base64-encoded `.p12` Developer ID Application certificate |
| `APPLE_CERTIFICATE_PASSWORD` | macOS | Password for the `.p12` certificate |
| `APPLE_SIGNING_IDENTITY` | macOS | Certificate identity string (e.g. `Developer ID Application: Madara Labs (...)`) |
| `APPLE_ID` | macOS | Apple ID email for `notarytool` notarization |
| `APPLE_PASSWORD` | macOS | App-specific password for notarization |
| `APPLE_TEAM_ID` | macOS | 10-character Apple Developer Team ID |
| `WINDOWS_CERTIFICATE` *(optional)* | Windows | Base64-encoded Authenticode `.pfx` if custom Windows signing step is added |
| `WINDOWS_CERTIFICATE_PASSWORD` *(optional)* | Windows | Password for the Windows `.pfx` certificate |

## `oake verify` exit codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | VERIFIED | Signature and at least one timestamp token were checked. Bitcoin is not checked; use `ots verify`. |
| 1 | FAILED | A check did not pass. |
| 2 | INCOMPLETE | Nothing failed, but the proof is unsigned or no timestamp could be verified. |

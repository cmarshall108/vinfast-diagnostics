# VinFast VF8 DoIP/UDS Diagnostic Scanner

A modular **C++20 / Qt6** diagnostic application that connects to a vehicle over
**DoIP (ISO 13400-2)** using a standard DoIP Ethernet interface such as the
**GODIAG GT109 DOIP ENET** adapter, discovers ECUs, and reads/clears Diagnostic
Trouble Codes via **UDS (ISO 14229)**. It also includes an optional
community-reverse-engineered **connected-car cloud client** for remote
telemetry and commands.

> ⚠️ **Safety & legal note.** Clearing DTCs erases stored fault history and can
> affect vehicle behaviour. Only operate on a vehicle you are authorised to
> service, with the vehicle safely immobilised. The VinFast-specific logical
> addresses shipped in the UI are **placeholders** — they are *not* official and
> must be configured to match the real vehicle.

## Features

- **Connection settings** — broadcast IP, gateway IP, port, tester source
  address, gateway logical address, routing-activation type,
  functional/physical addressing toggle.
- **ECU discovery** — UDP broadcast Vehicle Identification Request (port 13400);
  lists IP, logical address, VIN, EID for each responding DoIP entity.
- **Address probing** — sends TesterPresent to every configured ECU and marks
  which addresses actually respond (a negative response still proves the
  address is routable), so you can find the real addresses by trial.
- **Session & security** — DiagnosticSessionControl (0x10), Security Access
  (0x27 request-seed / send-key) and a background TesterPresent keep-alive so a
  non-default session does not time out.
- **Configurable ECU table** — editable name + logical address rows, with a
  reachability indicator from the last probe.
- **Per-ECU actions** — Read DTCs (0x19/0x02), Clear DTCs (0x14, auto-enters an
  Extended session first, with a confirmation dialog), Read ID (0x22 VIN).
- **Connected-car cloud client** — optional REST/IoT path to VinFast's app
  back-end (Auth0 + AWS) for telemetry and remote commands, based on public
  community sources. Completely separate from the on-vehicle diagnostic bus.
- **Live log** — colour-coded hex dump of every DoIP/UDS TX/RX frame.
- Background worker thread keeps the Qt GUI responsive during network I/O.

> ⚠️ **Realistic expectations.** Reading DTCs typically works in the default
> session. **Clearing very often requires Security Access (0x27)** whose
> seed→key algorithm is *manufacturer-proprietary* — the app lets you request a
> seed and submit a key you computed elsewhere, but it does not know VinFast's
> algorithm. Likewise, most VF8 subsystems (radars, BMS, EPS, …) are CAN nodes
> **behind the XGW gateway**: you address them by logical address and the
> gateway routes onto CAN. The shipped logical addresses are **placeholders** —
> use **Probe ECU Addresses** to find the ones that actually respond.

## Architecture

| File | Responsibility |
|------|----------------|
| `src/DoIPClient.*` | DoIP transport: UDP discovery, TCP routing activation, diagnostic message framing, ack / alive-check / response-pending handling. |
| `src/UDSClient.*`  | UDS services 0x22 / 0x19 / 0x14 / 0x3E and DTC / NRC decoding. |
| `src/CloudData.*`  | VinFast connected-car cloud reference data (regions, telemetry map, command list) from public community sources. |
| `src/CloudClient.*`| REST/IoT client (libcurl) for the connected-car cloud back-end. |
| `src/VF8Data.*`    | VF8-specific ECU / DTC reference tables. |
| `src/Gui.*`        | Qt6 Widgets front-end (TEXA IDC6-style navigator) and worker-thread orchestration. |
| `src/Logger.*`     | Thread-safe in-memory hex/text log. |
| `src/main.cpp`     | `QApplication` bootstrap. |

### DoIP flow recap

1. **Vehicle Identification** — UDP broadcast of payload type `0x0001`; entities
   reply with `0x0004` containing VIN, logical address, EID, GID.
2. **Routing Activation** — over TCP, payload `0x0005` carrying the tester source
   address; a `0x0006` reply with code `0x10` means activated.
3. **Diagnostic Messages** — payload `0x8001` wraps UDS bytes (source + target +
   UDS). The stack absorbs `0x8002` positive acks, answers `0x0007` alive checks,
   and waits on UDS `0x7F .. 0x78` (response pending).

## Building from source

### Prerequisites
- CMake ≥ 3.16
- A C++20 compiler (MSVC 2022 / Clang / GCC)
- **Qt 6** (Widgets)
- **libcurl**

Install the dependencies:

- **macOS (Homebrew):** `brew install qt curl`
  CMake auto-detects Homebrew Qt; if needed, pass
  `-DCMAKE_PREFIX_PATH=$(brew --prefix qt)`.
- **Linux (Debian/Ubuntu):**
  `sudo apt install qt6-base-dev libcurl4-openssl-dev`
- **Windows:** install Qt 6 (official installer or `aqt`) and provide libcurl
  via [vcpkg](https://vcpkg.io) (`vcpkg install curl:x64-windows`), then pass the
  vcpkg toolchain file to CMake.

### Configure & build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

On Windows with vcpkg:
```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
```

### Run
```bash
# Linux
./build/vinfast_scanner
# macOS (built as an .app bundle)
open build/vinfast_scanner.app
# Windows
build\Release\vinfast_scanner.exe
```

## Prebuilt downloads

Every push is built for **Linux, macOS, and Windows** by GitHub Actions
(`.github/workflows/build.yml`); the binaries are uploaded as workflow
artifacts. Pushing a version tag (e.g. `git tag v1.0.0 && git push --tags`)
additionally publishes a **GitHub Release** with packaged downloads:

| Platform | Download | Notes |
|----------|----------|-------|
| Linux (x86_64) | `VinFast_Scanner-x86_64.AppImage` | Self-contained; `chmod +x` and run. |
| macOS (universal) | `VinFast_Scanner.dmg` | Intel + Apple Silicon `.app`, Qt bundled via `macdeployqt`. |
| Windows (x64) | `vinfast_scanner.exe` + DLLs | Qt + libcurl runtime deployed via `windeployqt`. |
| Windows (ARM64) | `vinfast_scanner.exe` + DLLs | Native `arm64` build for Windows on ARM. |

### Opening the macOS app

If the DMG was **not** signed and notarized with a paid Apple Developer ID
(see below), macOS Gatekeeper will block it on first launch ("Apple cannot check
it for malicious software"). The app is still safe to run — bypass Gatekeeper
once with any of:

- **Right-click** the app → **Open** → confirm **Open** in the dialog, or
- **System Settings → Privacy & Security → Open Anyway**, or
- Terminal: `xattr -dr com.apple.quarantine /Applications/vinfast_scanner.app`

CI always **ad-hoc signs** the universal binary so it loads on Apple Silicon;
ad-hoc signing does not satisfy Gatekeeper for downloaded apps, hence the step
above.

### macOS code signing & notarization (optional)

When the following repository secrets are configured, the macOS job signs the
`.app` with a Developer ID certificate and notarizes the DMG, so users can open
it with no Gatekeeper prompt. When the secrets are absent, those steps are
skipped and the ad-hoc-signed (still runnable) DMG is produced instead.

| Secret | Purpose |
|--------|---------|
| `MACOS_CERTIFICATE` | base64-encoded Developer ID Application `.p12` |
| `MACOS_CERTIFICATE_PWD` | password for the `.p12` |
| `MACOS_CERT_IDENTITY` | identity string, e.g. `Developer ID Application: Name (TEAMID)` |
| `MACOS_NOTARY_APPLE_ID` | Apple ID used for notarization |
| `MACOS_NOTARY_PASSWORD` | app-specific password for that Apple ID |
| `MACOS_NOTARY_TEAM_ID` | Apple Developer Team ID |

Export the certificate to base64 with:
`base64 -i DeveloperID.p12 | pbcopy`.

## Usage

1. Connect the GT109 DoIP ENET adapter; put your PC on the same subnet as the
   vehicle gateway. Over the OBD port this is usually a DHCP- or link-local
   (169.254.x.x) address from the gateway; the VF8's internal diagnostic
   backbone is `172.16.100.x` (gateway likely `172.16.100.1`, the app default).
2. Click **Discover ECUs** to broadcast a Vehicle Identification Request.
3. Click **Use as Gateway** on the discovered entity (or type the gateway IP).
4. Click **Connect** to open the TCP session and perform routing activation.
5. Edit the ECU table addresses to match the vehicle, then use **Read DTCs** /
   **Clear DTCs** per ECU. Watch the **Log** panel for raw frames.

## Notes on addresses

- Tester source address default `0x0E80` is a common external-tester value.
- Functional address default `0xE400` is a placeholder — set it to the vehicle's
  functional request address if you use functional addressing.
- ECU logical addresses in the table are placeholders. Configure them in the UI.

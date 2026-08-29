# VinFast VF8 and VF9 OpenXC USB/Bluetooth UDS Scanner

A modular **C++20 / Qt6** diagnostic application that connects to a vehicle over
an **OpenXC USB or Bluetooth** vehicle interface, reads/clears Diagnostic
Trouble Codes via **UDS (ISO 14229)**. It also includes an optional
community-reverse-engineered **connected-car cloud client** for remote
telemetry and commands.

> ⚠️ **Safety & legal note.** Clearing DTCs erases stored fault history and can
> affect vehicle behaviour. Only operate on a vehicle you are authorised to
> service, with the vehicle safely immobilised. The VinFast-specific logical
> addresses shipped in the UI are **placeholders** — they are *not* official and
> must be configured to match the real vehicle.

## Features

- **Connection settings** — OpenXC USB or Bluetooth MAC, tester source address,
  functional/physical addressing toggle, and fallback CAN parameters.
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
- **Live log** — colour-coded hex dump of every OpenXC/UDS TX/RX frame.
- Background worker thread keeps the Qt GUI responsive during network I/O.

> ⚠️ **Realistic expectations.** Reading DTCs typically works in the default
> session. **Clearing very often requires Security Access (0x27).** The VF8
> seed→key algorithm was recovered from the TBOX crypto binary
> (`vf_crypto_service`): the key is **`HMAC-SHA1(ecuKey, seed)` truncated to the
> seed length**, where `ecuKey` is a per-ECU / per-security-level secret held in
> the TBOX TPM's encrypted ECU keyset. The app can compute the key for you
> (**Derive key** button) once you supply that per-ECU secret — it is *not* in
> the firmware in cleartext, so you must extract it from your own vehicle's
> provisioning data. Likewise, most VF8 subsystems (radars, BMS, EPS, …) are CAN
> nodes **behind the XGW gateway**: you address them by logical address and the
> gateway routes onto CAN. The shipped logical addresses are **placeholders** —
> use **Probe ECU Addresses** to find the ones that actually respond.

## Firmware-derived facts (VF8 TBOX dump)

Facts reverse-engineered from the on-vehicle TBOX rootfs (`tbox-firmware/`) and
the `vf_crypto_service` binary, used to make the tool match the real vehicle:

| Fact | Source | Where it's used |
|------|--------|-----------------|
| Diagnostic CAN bus is **500 kbit/s** | `etc/init.d/init-can.sh` (`ip link set can0 type can bitrate 500000`) | Default CAN baud rate. |
| SecurityAccess key = **HMAC-SHA1(ecuKey, seed)** | `vf_crypto_service`: `Vfx::CryptoMgr::seed2Key_`, `TpmService::GenHmacSha1` ("EcuId/KeyLv"), `EcuKeyData` | **Derive key** button (Session & Security panel). |
| Per-ECU keys stored as an encrypted keyset (4 levels/ECU) in the TPM | `ProvisioningEcuKeySet` / `DecryptwtEcuKey` symbols | Documented; the secret must be user-supplied. |
| Engineering-menu unlock is **RFC 4226 HOTP / 30 s TOTP** over `SHA1(oemsymkey ‖ seed)` | `CryptoToken::authenTOTP`, `GetFotaDecryptionKey` (loads `oemsymkey`) | `tools/vf8_totp.py` + in-app TOTP generator. |

## Field-validation notes

The following is an observed result from the reference 2024 US VF8. It is kept
separate from firmware-derived facts because it does not establish a complete
vehicle diagnostic path.

| Observation | Result | Interpretation |
|---|---|---|
| OpenXC `diagnostic_request`: bus 1, ID `0x682`, UDS `0x22 F190` | The VI acknowledged the host command; no `diagnostic_response` arrived within 3 seconds. | The computer-to-VI link was working. It does **not** confirm VCI CAN transmission, the physical OBD network, XGW wake state, or that `0x682` is reachable from the connected port. |
| XGW candidates | `0x682` is the preferred Info-CAN tunnel candidate; `0x7E0` is tried as the standard OBD physical fallback. | Both are candidates until a matching response is captured on the vehicle. A timeout is not evidence that an ECU is absent. |


## Architecture

| File | Responsibility |
|------|----------------|
| `src/OpenXcClient.*` | OpenXC VI RFCOMM serial client; JSON diagnostic request/response framing. |
| `src/OpenXcTransport.*` | Transport wrapper that maps logical UDS addresses to CAN arbitration IDs and drives the OpenXC VI. |
| `src/UDSClient.*`  | UDS services 0x22 / 0x19 / 0x14 / 0x3E and DTC / NRC decoding. |
| `src/CloudData.*`  | VinFast connected-car cloud reference data (regions, telemetry map, command list) from public community sources. |
| `src/CloudClient.*`| REST/IoT client (libcurl) for the connected-car cloud back-end. |
| `src/VF8Data.*`    | VF8-specific ECU / DTC reference tables. |
| `src/Gui.*`        | Qt6 Widgets front-end (TEXA IDC6-style navigator) and worker-thread orchestration. |
| `src/Logger.*`     | Thread-safe in-memory hex/text log. |
| `src/main.cpp`     | `QApplication` bootstrap. |

### OpenXC flow recap

1. **USB connection (preferred)** — connect the OpenXC Vehicle Interface (VI)
  to the computer with a USB cable. The stock Ford/OpenXC VI uses a
  vendor-specific USB bulk interface rather than USB-CDC on macOS; the app
  connects to it through libusb using the `usb` device token. USB-serial VIs
  (for example `/dev/ttyUSB0`, `/dev/cu.usbmodem*`, or `COM3`) are also
  supported. **Bluetooth Classic SPP** is supported on macOS through a direct
  IOBluetooth RFCOMM channel selected by the paired device's MAC address, so
  it does not depend on a `/dev/cu.*` Bluetooth serial node.
2. **Connect** — the app opens the serial link to the VI and configures it to
   pass arbitrary diagnostic frames on the selected CAN bus.
3. **Diagnostic messages** — UDS requests are sent as OpenXC JSON
   `diagnostic_request` messages; the VI wraps them in CAN frames using the
   configured request/response arbitration IDs and returns the ECU reply as a
   `diagnostic_response`.

## Building from source

### Prerequisites
- CMake ≥ 3.16
- A C++20 compiler (MSVC 2022 / Clang / GCC)
- **Qt 6** (Widgets)
- **libcurl**
- **Python 3** for optional helper tools

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

1. Connect the OpenXC Vehicle Interface to the computer with a USB cable. The
  default device field is `auto`, which probes likely USB serial ports first.
  You can also enter a USB serial path (e.g. `/dev/ttyUSB0`,
  `/dev/cu.usbmodem*`, `COM3`) or a Bluetooth MAC.
2. Click **Scan USB** on the Connection page to list available USB serial ports,
   or **Scan BT** to list paired Bluetooth devices. You can also type the path
   or MAC manually.
3. Click **Connect** to open the serial link and initialise the VI for
   diagnostic traffic.
4. Edit the ECU table logical addresses to match the vehicle, then use
   **Read DTCs** / **Clear DTCs** per ECU. Watch the **Log** panel for raw frames.

## Notes on addresses

- Tester source address default `0x0E80` is a common external-tester value.
- Functional address default `0xE400` is a placeholder — set it to the vehicle's
  functional request address if you use functional addressing.
- ECU logical addresses in the table are placeholders. Configure them in the UI.
- **CAN ID mapping** controls how a logical UDS address is translated to the
  physical CAN arbitration IDs the VI transmits. The default is
  `request = 0x700 + (addr & 0xFF)` and `response = request + 0x08`. For the
  common 0x7E0/0x7E8 gateway pair, set the base to `0x700` and use address
  `0x00E0`.

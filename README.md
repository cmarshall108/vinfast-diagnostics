# VinFast VF8 DoIP/UDS Diagnostic Scanner

A minimal, modular C++20 diagnostic application that connects to a vehicle over
**DoIP (ISO 13400-2)** using a standard DoIP Ethernet interface such as the
**GODIAG GT109 DOIP ENET** adapter, discovers ECUs, and reads/clears Diagnostic
Trouble Codes via **UDS (ISO 14229)**.

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
- **Live log** — colour-coded hex dump of every DoIP/UDS TX/RX frame.
- Background worker thread keeps the GUI responsive during network I/O.

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
| `src/Gui.*`        | Dear ImGui front-end and worker-thread orchestration. |
| `src/Logger.*`     | Thread-safe in-memory hex/text log. |
| `src/main.cpp`     | GLFW + OpenGL3 + ImGui bootstrap and render loop. |

### DoIP flow recap

1. **Vehicle Identification** — UDP broadcast of payload type `0x0001`; entities
   reply with `0x0004` containing VIN, logical address, EID, GID.
2. **Routing Activation** — over TCP, payload `0x0005` carrying the tester source
   address; a `0x0006` reply with code `0x10` means activated.
3. **Diagnostic Messages** — payload `0x8001` wraps UDS bytes (source + target +
   UDS). The stack absorbs `0x8002` positive acks, answers `0x0007` alive checks,
   and waits on UDS `0x7F .. 0x78` (response pending).

## Build (Dear ImGui + GLFW are fetched automatically)

The `CMakeLists.txt` uses `FetchContent` to download **GLFW 3.4** and
**Dear ImGui v1.90.9** (including the GLFW + OpenGL3 backends), so no manual
dependency setup is required beyond a compiler, CMake, and OpenGL.

### Prerequisites
- CMake ≥ 3.16
- A C++20 compiler (MSVC 2022 / Clang / GCC)
- OpenGL development libraries
  - **Windows:** ships with the OS / GPU drivers.
  - **macOS:** provided by the system frameworks.
  - **Linux:** `sudo apt install libgl1-mesa-dev xorg-dev`

### Configure & build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

### Run
```bash
# Linux/macOS
./build/vinfast_scanner
# Windows
build\Release\vinfast_scanner.exe
```

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

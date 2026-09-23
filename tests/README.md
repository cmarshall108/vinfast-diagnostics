# Test Utilities

## Automated ELM327 serial exchange

`test_elm327.cpp` uses a pseudo-terminal ELM327 emulator to verify HS-CAN
500 kbit/s, MS-CAN 250 kbit/s, protocol-B MS-CAN 125 kbit/s, physical UDS
responses, and functional multi-ECU responses without vehicle hardware.

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target test_elm327
ctest --test-dir build -R elm327_serial_exchange --output-on-failure
```

## J2534 CAN 500 kbit/s scan

File: `tests/tests_j2534_can500k_scan.py`

A small standalone Python script that probes a Toyota Mini-VCI (or any SAE
J2534 PassThru device) on Windows at 500 kbit/s. It is useful for confirming
that the VCI driver loads and that the CAN bus is alive before relying on the
CAN backup path in the main application.

### Requirements

- Windows with a J2534 PassThru driver installed (e.g. `mvci32.dll`).
- Python 3 and `pywin32` (for loading the 32-bit DLL).

### Run

```bash
python3 tests/tests_j2534_can500k_scan.py
```

The script opens the device, connects to ISO 15765 at 500 kbit/s with 11-bit
addressing, and listens for a few seconds, printing any frames it sees.

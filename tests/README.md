# Test Utilities

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

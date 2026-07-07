# VinFast VF8 — Engineering-Menu TOTP generator
#
# Reverse-engineered from the head-unit/TBOX binary `vf_crypto_service`
# (ELF32 ARM, not stripped). Relevant symbols:
#
#   Vfx::CryptoMgr::CryptoToken::authenTOTP(otp, arg2, out)
#   Vfx::CryptoMgr::TpmService::GetFotaDecryptionKey(&out)   -> loads "oemsymkey"
#   TOTP::getOTP(long long counter, std::string key)
#   TOTP::validate(long long T, otp, key)
#
# Recovered algorithm (exact):
#
#   1. secret   = oemsymkey                       # 32 bytes, from TPM secure
#                                                 #   storage id "oemsymkey"
#                                                 #   (== the FOTA decryption key)
#   2. hmac_key = SHA1( secret || seed_ascii )    # 20-byte digest, used as the
#                                                 #   HMAC key. `seed_ascii` is
#                                                 #   the 6-digit "seed code" the
#                                                 #   car shows, as ASCII bytes.
#   3. T        = floor( unix_time / 30 )         # 30-second time step. The car
#                                                 #   uses time() (UTC seconds);
#                                                 #   the displayed timestamp is
#                                                 #   the car's current clock.
#   4. code     = HOTP-SHA1( hmac_key, T )        # RFC 4226 dynamic truncation:
#                                                 #     off = digest[19] & 0x0F
#                                                 #     bin = ((digest[off]  &0x7f)<<24)
#                                                 #         | ( digest[off+1]     <<16)
#                                                 #         | ( digest[off+2]     << 8)
#                                                 #         |   digest[off+3]
#                                                 #     code = bin % 1000000       (6 digits)
#
# The car's TOTP::validate() accepts a small window of counters around T
# (roughly T-2 .. T+1), so a code generated for T (or a neighbour) is accepted
# despite clock skew / entry delay. This script prints the whole window.
#
# ---------------------------------------------------------------------------
# IMPORTANT: `oemsymkey` is a 32-byte secret held in the vehicle's TPM/QTEE
# secure storage. It is NOT present in cleartext in the firmware dump. You must
# supply it (extracted from your own vehicle, or the OEM value if model-wide)
# via --key / --key-file. Without the correct oemsymkey the generated codes
# will not match.
# ---------------------------------------------------------------------------

import argparse
import base64
import calendar
import hashlib
import hmac
import sys
import time as _time
from datetime import datetime, timezone, timedelta

TIME_STEP = 30          # seconds  (divisor found in authenTOTP: time / 30)
DIGITS = 6              # modulo 1_000_000 found in TOTP::getOTP
OEMSYMKEY_LEN = 32      # GetFotaDecryptionKey checks the key length == 32


# --- accepted timestamp formats -------------------------------------------
# The car shows e.g.  " 07/07/2026 - 01:26"
_TS_FORMATS = [
    "%d/%m/%Y - %H:%M",   # DD/MM/YYYY  (VinFast locale default)
    "%m/%d/%Y - %H:%M",   # MM/DD/YYYY
    "%d/%m/%Y - %H:%M:%S",
    "%m/%d/%Y - %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
]


def parse_timestamp(ts: str, fmt: str | None) -> datetime:
    ts = ts.strip()
    formats = [fmt] if fmt else _TS_FORMATS
    for f in formats:
        try:
            return datetime.strptime(ts, f)
        except ValueError:
            continue
    raise ValueError(
        f"Could not parse timestamp {ts!r}. Try --ts-format, e.g. "
        f"'%d/%m/%Y - %H:%M'."
    )


def to_unix(dt: datetime, tz_offset_hours: float) -> int:
    """Interpret naive `dt` as wall-clock in a zone at tz_offset_hours from UTC."""
    dt = dt.replace(tzinfo=timezone(timedelta(hours=tz_offset_hours)))
    return int(dt.astimezone(timezone.utc).timestamp())


def load_key(args) -> bytes:
    raw = None
    if args.key_file:
        with open(args.key_file, "rb") as fh:
            data = fh.read()
        # Accept a raw 32-byte binary blob, or a hex/base64 text file.
        if len(data) == OEMSYMKEY_LEN:
            raw = data
        else:
            raw = _decode_text_key(data.decode("ascii", "ignore").strip())
    elif args.key:
        raw = _decode_text_key(args.key.strip())
    else:
        raise SystemExit(
            "error: no oemsymkey supplied. Use --key <hex/base64> or "
            "--key-file <path>. See the header of this file for what oemsymkey is."
        )
    if len(raw) != OEMSYMKEY_LEN:
        print(
            f"warning: oemsymkey is {len(raw)} bytes; the firmware expects "
            f"{OEMSYMKEY_LEN}. Continuing anyway.",
            file=sys.stderr,
        )
    return raw


def _decode_text_key(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("\n", "")
    # try hex first
    try:
        if len(s) % 2 == 0:
            return bytes.fromhex(s)
    except ValueError:
        pass
    # then base64
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise SystemExit("error: could not decode --key as hex or base64.")


def derive_hmac_key(oemsymkey: bytes, seed: str) -> bytes:
    """hmac_key = SHA1( oemsymkey || seed_ascii )   (20 bytes)."""
    return hashlib.sha1(oemsymkey + seed.encode("ascii")).digest()


def hotp(hmac_key: bytes, counter: int) -> str:
    """RFC 4226 HOTP with SHA1, 6 digits — exactly as TOTP::getOTP does it."""
    msg = counter.to_bytes(8, "big")                 # 8-byte big-endian counter
    digest = hmac.new(hmac_key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F                        # digest[19] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24
              | (digest[offset + 1] & 0xFF) << 16
              | (digest[offset + 2] & 0xFF) << 8
              | (digest[offset + 3] & 0xFF))
    return str(binary % (10 ** DIGITS)).zfill(DIGITS)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Generate the VinFast VF8 engineering-menu TOTP code.")
    ap.add_argument("seed", help="6-digit seed code shown by the car")
    ap.add_argument("timestamp", nargs="?",
                    help="timestamp shown by the car, e.g. '07/07/2026 - 01:26' "
                         "(omit to use the current UTC time)")
    ap.add_argument("--key", help="oemsymkey as hex or base64 (32 bytes)")
    ap.add_argument("--key-file", help="file containing oemsymkey (raw 32 bytes, or hex/base64 text)")
    ap.add_argument("--ts-format", help="explicit strptime format for the timestamp")
    ap.add_argument("--tz-offset", type=float, default=0.0,
                    help="hours the displayed clock is offset from UTC "
                         "(default 0 = the car clock is UTC). Vietnam local = 7.")
    ap.add_argument("--window", type=int, default=2,
                    help="how many 30s steps each side of T to print (default 2)")
    args = ap.parse_args(argv)

    oemsymkey = load_key(args)
    hmac_key = derive_hmac_key(oemsymkey, args.seed)

    if args.timestamp:
        dt = parse_timestamp(args.timestamp, args.ts_format)
        unix_t = to_unix(dt, args.tz_offset)
        src = f"{args.timestamp!r} (tz offset {args.tz_offset:+g}h)"
    else:
        unix_t = int(_time.time())
        src = "current UTC time"

    T = unix_t // TIME_STEP

    print(f"seed code     : {args.seed}")
    print(f"time source   : {src}")
    print(f"unix time     : {unix_t}")
    print(f"counter T      : {T}  (= floor(unix/{TIME_STEP}))")
    print(f"hmac key (sha1): {hmac_key.hex()}")
    print()
    print(f"Primary code (T): {hotp(hmac_key, T)}")
    if args.window > 0:
        print(f"\nValidation window (the car accepts a range around T):")
        for d in range(-args.window, args.window + 1):
            tag = "  <-- T" if d == 0 else ""
            when = datetime.fromtimestamp((T + d) * TIME_STEP, timezone.utc)
            print(f"  T{d:+d}  {hotp(hmac_key, T + d)}   "
                  f"[{when:%Y-%m-%d %H:%M:%S} UTC]{tag}")


# --------------------------------------------------------------------------
# Self-test: verifies our HOTP truncation matches RFC 4226 test vectors,
# proving the getOTP arithmetic (offset, 0x7f mask, mod 1e6) is implemented
# correctly. Run:  python3 vf8_totp.py --selftest
# --------------------------------------------------------------------------
def _selftest():
    key = b"12345678901234567890"  # RFC 4226 test key
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    ok = all(hotp(key, i) == expected[i] for i in range(10))
    print("RFC 4226 HOTP self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    main()

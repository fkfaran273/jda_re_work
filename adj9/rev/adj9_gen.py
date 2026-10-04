"""adj9_gen.py — what of the adj9 Signature can be produced offline, and what
structurally cannot.

  signature = Base64(NO_WRAP)( 192-byte envelope )  -> 256 chars
  envelope  = [ 16 B header ][ 176 B body ]

  header : srand(time(NULL)) + bionic random(), 4 XOR-pairs, BE int32.
           OFFLINE-FORGEABLE, byte-exact for any unix second (verified 60/60
           across two devices, incl. an Android-11 Fiddler capture).
  body   : sealed claims (H, canonical digests, app-cert SHA-1, trust-store
           material, apiLevel, fresh /dev/urandom nonce). NOT produceable
           offline — see BODY_IS_NOT_FORGEABLE below.

See ADJ9_VALIDATION_MODEL.md for the evidence behind every claim here.
"""
import base64, struct, time
from header_gen import make_header, Random3

ENVELOPE_LEN = 192
HEADER_LEN   = 16
BODY_LEN     = 176
BASE64_LEN   = 256          # 192 B -> Base64(NO_WRAP)

# keystore 'key2' (AndroidKeyStore, TEE): HMAC / SHA-2 256 / 256-bit key /
# 256-bit MAC / PURPOSE=SIGN / ORIGIN=GENERATED / sec_level=1 (TEE).
KEY_ALIAS       = "key2"
KEY_ALGORITHM   = "HMAC"
KEY_DIGEST      = "SHA-2 256"
KEY_SIZE_BITS   = 256
MAC_LEN_BYTES   = 32        # H = HMAC-SHA256(canonical, key2)

BODY_IS_NOT_FORGEABLE = """
The 176-byte body cannot be generated offline. Two independent, proven walls:

  A. Sealing math is unreversed: it lives in libsigner.so's O-LLVM-flattened
     native VM (the CFG reachable from nSign @0xdb1cc is ~255k instructions).
     There is no standard cipher in it (no AES S-box, no ARMv8 crypto
     extensions, no RSA OID) - it is custom, table-free math fed by a fresh
     /dev/urandom nonce, so no two calls ever produce the same body.

  B. Its payload carries material derived from key2, an AndroidKeyStore
     HMAC-SHA256 key GENERATED inside the TEE (ORIGIN=0) and never exportable.
     Nobody - including Adjust's own backend - can know it, so H cannot be
     recomputed anywhere but on the device.

A genuine 192-byte envelope can therefore only be minted on-device by the
library itself (the LSPosed oracle in adj9/module/ does exactly that: it
re-invokes nSign with chosen inputs and returns real envelopes).
"""


def make_header_for(unix_seconds=None):
    """16-byte PRNG stamp for a unix second (defaults to now)."""
    if unix_seconds is None:
        unix_seconds = int(time.time())
    return make_header(unix_seconds)


def adj_verification():
    """The one constant part of the header: XOR({'os_name':'android'}, key, i%19)."""
    plain = b'{"os_name":"android"}'
    key = b"Quoh8uafohgh7CahM2h"
    x = bytes(c ^ key[i % len(key)] for i, c in enumerate(plain))
    return base64.b64encode(x).decode()


def envelope_shape(unix_seconds=None):
    """
    Returns the offline-forgeable pieces of an envelope. The body is returned
    as None on purpose: it must come from the device (see BODY_IS_NOT_FORGEABLE).
    """
    return {
        "unix_seconds": unix_seconds or int(time.time()),
        "header": make_header_for(unix_seconds),
        "body": None,
    }


def base64_of(blob):
    """Base64(NO_WRAP), as the SDK does (256 chars for a 192 B envelope)."""
    return base64.b64encode(blob).decode()


def parse_signature(sig_b64_or_hex):
    """Accept the Signature header value (base64, 256 chars) or raw hex -> 192 B."""
    s = sig_b64_or_hex.strip()
    if len(s) == BASE64_LEN * 2 and all(c in "0123456789abcdefABCDEF" for c in s):
        blob = bytes.fromhex(s)
    else:
        blob = base64.b64decode(s)
    if len(blob) != ENVELOPE_LEN:
        raise ValueError("envelope must be %d B, got %d" % (ENVELOPE_LEN, len(blob)))
    return blob


def recover_second(blob, center_ms=None, span_s=3600):
    """
    Reverse the 16-byte stamp: which unix second did the device seed srand() with?
    Returns (unix_seconds, header_match_bool). Search window is
    [center_ms/1000 - span_s, center_ms/1000 + span_s]; if center_ms is None it
    searches the whole 2^31 space around now is NOT attempted - pass a capture
    timestamp or you will be waiting (~16384 headers/s single-threaded here).
    """
    if center_ms is None:
        raise ValueError("center_ms required (wall clock at capture time, ms)")
    c = center_ms // 1000
    for s in range(c - span_s, c + span_s + 1):
        if make_header(s) == blob[:HEADER_LEN]:
            return s, True
    return None, False


def mint(unix_seconds, body):
    """
    Assemble a 192 B envelope. `body` MUST be 176 bytes of real device output.
    Passing a synthetic body produces a well-formed but unverifiable envelope:
    the server decrypts the body and will reject it.
    """
    if body is None or len(body) != BODY_LEN:
        raise ValueError(BODY_IS_NOT_FORGEABLE.strip())
    return base64_of(make_header(unix_seconds) + body)


def describe():
    print(__doc__.strip())
    print("\nTEE key: alias=%s  algorithm=%s  digest=%s  key=%d bit  mac=%d B"
          % (KEY_ALIAS, KEY_ALGORITHM, KEY_DIGEST, KEY_SIZE_BITS, MAC_LEN_BYTES))
    print(BODY_IS_NOT_FORGEABLE)
    s = envelope_shape()
    print("header for unix second %d (now): %s" % (s["unix_seconds"], s["header"].hex()))
    print("adj_verification (constant):     %s" % adj_verification())
    print("body:                             <device-minted only>")


if __name__ == "__main__":
    describe()

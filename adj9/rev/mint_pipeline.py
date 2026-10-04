"""mint_pipeline.py — the complete pure-Python adj9 mint pipeline + funnel wiring.

The one entry point is mint_blob(): claims map + signing second + region ->
a 192-B adj9 blob (16-B header + 44-word body), ready for the Authorization
header.  Everything except the per-call REGION (#0/#2/#4) is assembled here
from proven laws:

  #10 = desc10_law.build_desc10(claims, kind), NUL-padded to a 4-B multiple
        (slices 96/105: byte-exact for session AND click, all 10 captures)
  #7  = the UNPADDED length of #10 as one BE dword (slice 99 §2)
  #8  = bffffffffffffd1f0007000000000000   (16-B XOR-table constants, corpus)
  #9  = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd   (APK cert SHA-1, slice 145)
  #5  = #6 = 00000000 ;  #1/#3 = empty                      (corpus, verified)
  #0/#2/#4 = the region — F.py: region(V, pid, tid) -> (d0[36], d2, d4[8]).
        V = tv_sec ^ tv_usec at the fill instant (fill_model §3); pid/tid are
        per-process constants (fill_model §1 input map).  F.py is imported if
        present; otherwise the caller passes region=(d0, d2, d4) explicitly.

  body  = FinEx(fin_vm2) over the 11 descriptors in va_order [0,9,8,4,2,7,
          10,5,1,6,3], seed = the signing second (_finex_corpus_a/b/c.log:
          48/48 words on corpus rows 0/1/4/5/6/7)
  header= make_header(second) = Random3(second) draws 1..8, pair-XOR, BE
          (emu_replay §0: 4/4 units on captured signings; srand re-fires per
          signing inside the signing path)

Validation modes (OFFLINE, no network):
  python mint_pipeline.py selftest             # dry-run mint + structure checks
  python mint_pipeline.py validate-corpus      # 6 corpus rows, expect 48/48
  python mint_pipeline.py validate-corpus 0,1  # subset

Funnel modes (LIVE network + device — gated behind --live, see mint_testbed.md):
  python mint_pipeline.py arm-a --live   # PC click + mint session + sdk_click,
                                         # NO attribution polls, device oracle
  python mint_pipeline.py arm-b --live   # device click + mint session, oracle
"""
import base64
import datetime
import json
import os
import re
import struct
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from header_gen import Random3, make_header
from fin_vm2 import FinEx
from desc10_law import build_desc10, desc10_keys

# ---------------------------------------------------------------------------
# Pinned constants (corpus-proven; do not edit without a corpus re-run)
# ---------------------------------------------------------------------------
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]     # FinEx descriptor order
SINK = 0x5500000000                               # blob stream (all corpus rows)
D8_HEX = "bffffffffffffd1f0007000000000000"       # #8: 16-B constant (4 BE dwords:
                                                  #     bfffffff fffffd1f 00070000 00000000)
D9_HEX = "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"  # #9: APK cert SHA-1 (slice 145)
D5_WORD = 0x00000000                              # #5 = #6 = one zero dword
BLOB_WORDS = 48                                   # 48 x BE u32 = 192 B
ADJ_VERIFICATION = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI" # the app's adj_verification claim
ADJ_SIGNING_ID = "1500000"                        # pinned claim + header value
CLIENT_SDK = "android5.7.0"                       # Client-SDK header + claim
NATIVE_VERSION = "5.0.0"                          # native_version claim
APP_TOKEN = "jut9tib0eeps"                        # com.penti.app
OLD_GAID_RE = (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")  # "yesterday's GAID" in LINK

# Region policy for LIVE mints (see mint_testbed.md §5).  Per fill_model §6
# the server cannot recompute the region from the request (the fill-instant
# µs is not transmitted) — the booking gate is law-based, and every F(V,pid,
# tid) output satisfies the laws.  pid/tid are therefore ours to choose;
# keep them plausible and stable.  Override with ADJ9_PID / ADJ9_TID.
DEFAULT_PID = 26530      # observed app pid (slice 145 live capture)
DEFAULT_TID = 26593      # signing worker tid placeholder (same magnitude)
ORGANIC_TOKEN = "wy7261z"   # the slice-144 negative-arm verdict tracker


# ---------------------------------------------------------------------------
# F.py region loader — F.py: region(V, pid, tid) -> d0[36] / d2 / d4[8]
# ---------------------------------------------------------------------------
_F_FN = None
_F_LOOKED = False


def region_fn():
    """Locate F.py's region function (cached).  Returns None while absent."""
    global _F_FN, _F_LOOKED
    if not _F_LOOKED:
        _F_LOOKED = True
        try:
            import importlib
            mod = importlib.import_module("F")
            for name in ("region", "region_fill", "fill", "region_words"):
                fn = getattr(mod, name, None)
                if callable(fn):
                    _F_FN = fn
                    break
        except ImportError:
            pass
    return _F_FN


def _to_desc_bytes(w, nbytes, what):
    """Normalize one region piece to its exact descriptor bytes.

    Accepts bytes (as-is), one int, or an int sequence packed BIG-endian —
    the descriptor raw-byte dump IS the BE word sequence (corpus d0 hex ==
    BE words; the native reads `ldr w8,[data]` + `rev w3,w8`).
    """
    if isinstance(w, (bytes, bytearray, memoryview)):
        b = bytes(w)
    elif isinstance(w, int):
        b = struct.pack(">I", w & 0xFFFFFFFF)
    else:
        try:
            b = b"".join(struct.pack(">I", int(x) & 0xFFFFFFFF) for x in w)
        except TypeError:
            raise ValueError("region %s: cannot normalize %r" % (what, type(w)))
    if len(b) != nbytes:
        raise ValueError("region %s: %d bytes, expected %d"
                         % (what, len(b), nbytes))
    return b


def normalize_region(out):
    """F.region output -> (d0_bytes[144], d2_bytes[4], d4_bytes[32]).

    Accepts a (d0, d2, d4) tuple/list or a dict with keys d0/d2/d4.  Each
    piece may be bytes, an int (d2), or a word list (d0[36]/d4[8]).
    """
    if isinstance(out, dict):
        d0, d2, d4 = out.get("d0"), out.get("d2"), out.get("d4")
    elif isinstance(out, (tuple, list)) and len(out) == 3:
        d0, d2, d4 = out
    else:
        raise ValueError("F.region returned %r; expected (d0[36], d2, d4[8]) "
                         "or {'d0':..,'d2':..,'d4':..}" % type(out))
    return (_to_desc_bytes(d0, 144, "d0"),
            _to_desc_bytes(d2, 4, "d2"),
            _to_desc_bytes(d4, 32, "d4"))


# DEVICE-VERIFIED head phases, recovered 2026-09-28 from the 6-blob transport
# capture (transport_blob.txt + siblings; see rev/blob_diff.md and the
# independent re-derivation in rev/_vf7.py, which reproduces the genuine blob
# 192/192 BYTE-EXACT using head=(0x2b,)).
#
# Every genuine blob in that capture uses a SHORT head, and NONE of them uses
# F.HEAD_FIRST, F.HEAD_RESIGN or the old DEVICE_SELECTORS:
#     blob 0 (/session pre-flight)   second 1790517288  head (0x2b,)
#     blob 1                         second 1790517289  head (0x2b,)
#     blob 2 (/session)              second 1790517290  head (0x2b, 0x48)
#     blob 3 (/sdk_click)            second 1790517291  head (0x2b, 0x48)
#     blob 4 (/attribution)          second 1790517291  head (0x2b, 0x48)
#     blob 5                         second 1790517292  head (0x2b,)
# The three REAL request signings (session, sdk_click, attribution) all use the
# 2-selector phase.  The old defaults were byte-wrong on this device, and both
# HEAD_RESIGN and DEVICE_SELECTORS additionally fail the pipeline's own L3 law.
DEVICE_SELECTORS = (0x2B, 0x48)          # session / sdk_click / attribution
DEVICE_SELECTORS_PREFLIGHT = (0x2B,)     # the short pre-flight signings



def resolve_region(V, pid, tid, region=None, head=None):
    """#0/#2/#4 bytes: explicit region wins; else F.py(V, pid, tid, head).

    `head` selects the whitener head for this signing (see F.head_for_sign_id):
    the first two signings in a process use HEAD_FIRST, re-signs use
    HEAD_RESIGN.  Passing the wrong head yields a byte-wrong d0 that costs the
    click->install join.
    """
    if region is not None:
        return normalize_region(region)
    if V is None:
        raise ValueError("resolve_region: V is required when region is None")
    fn = region_fn()
    if fn is None:
        raise RuntimeError(
            "F.py not found in %s — region(V,pid,tid) is unavailable. "
            "Drop F.py (contract: region(V,pid,tid) -> d0[36]/d2/d4[8]) or "
            "pass region=(d0, d2, d4) explicitly." % HERE)
    # F.region now accepts the optional head; fall back if the loaded F is older.
    try:
        return normalize_region(fn(V, pid, tid, head=head or DEVICE_SELECTORS))
    except TypeError:
        return normalize_region(fn(V, pid, tid))


def make_V(second, usec=None):
    """V = tv_sec ^ tv_usec at the fill instant (fill_model §3).

    The fill's tv_sec is the signing second; the µs field is free — pick any
    (or leave None to take the real clock's µs right now).
    """
    if usec is None:
        ns = time.time_ns()
        usec = (ns % 1_000_000_000) // 1000
    return (int(second) ^ (int(usec) & 0xFFFFF)) & 0xFFFFFFFF


def make_V_consistent(second, ca_ms):
    """V for a fill that is self-consistent with the transmitted stamps.

    A real device fills the region at a wall-clock instant and stamps
    created_at a few ms LATER in the SAME Unix second (verified on 7/7
    genuine spawn captures: created_at epoch == signing second, and the
    fill microsecond is <= the created_at millisecond).  The previous live
    path broke this twice over: it stamped created_at at `second-1` and
    filled the region with the *present* clock's microsecond (~2s after
    the claimed created_at), so no observer could reconcile the region
    with the claims.  Here we keep tv_sec == signing second and pick a
    fill microsecond that sits at/below the created_at millisecond.
    """
    ns = time.time_ns()
    usec = (ns % 1_000_000_000) // 1000          # 0..999999 within this call
    cap = (int(ca_ms) * 1000) & 0xFFFFF           # created_at ms -> micro
    if usec > cap:
        usec = cap                               # fill at/before created_at
    return make_V(second, usec)


def head_for_endpoint(kind: str):
    """Whitener head for a request -- DEVICE-VERIFIED phases (2026-09-28).

    The 6-blob transport capture shows the three REAL request signings all use
    the 2-selector phase (0x2b, 0x48), and the short pre-flight signings use
    (0x2b,).  F.HEAD_FIRST / F.HEAD_RESIGN are NOT what this device emits --
    both are byte-wrong on every genuine blob, and HEAD_RESIGN fails law L3.
    Independently re-derived in _vf7.py (192/192 byte-exact reproduction).
    """
    return {"session": DEVICE_SELECTORS,
            "click": DEVICE_SELECTORS,
            "attribution": DEVICE_SELECTORS}.get(kind, DEVICE_SELECTORS)


def placeholder_region(V):
    """DETERMINISTIC stand-in region for OFFLINE dry-runs only.

    SplitMix64 keyed on V — NOT the real F, and generally FAILS the region
    structural laws (which is exactly what distinguishes a random region:
    fill_model §6).  Never send blobs minted with this.
    """
    m64 = (1 << 64) - 1
    state = (int(V or 0) ^ 0xA0B0C0D05F1F5F1F) & m64

    def nxt():
        nonlocal state
        state = (state + 0x9E3779B97F4A7C15) & m64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & m64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & m64
        return (z ^ (z >> 31)) & 0xFFFFFFFF

    d0w = [nxt() for _ in range(36)]
    d2w = nxt()
    d4w = [nxt() for _ in range(8)]
    return (d0w, d2w, d4w)


# ---------------------------------------------------------------------------
# Claims -> descriptors (the laws)
# ---------------------------------------------------------------------------
# Claim keys the map carries internally but the HTTP form never does.
INTERNAL_CLAIMS = {
    "adj_verification": ADJ_VERIFICATION,
    "adj_signing_id": ADJ_SIGNING_ID,
    "client_sdk": CLIENT_SDK,
    "headers_id": "10",
    "native_version": NATIVE_VERSION,
}   # + activity_kind, taken from the law kind itself


def claims_from_wire(params, kind):
    """Law claim map from the HTTP form params (single source of truth:
    every claim equals the value that goes on the wire; internal-only keys
    come from INTERNAL_CLAIMS).  `push_token` is included automatically when
    params carry it (desc10_law OPTIONAL_PROFILE)."""
    keys = desc10_keys(kind, params)
    val = {}
    missing = []
    for k in keys:
        if k == "activity_kind":
            val[k] = kind
        elif k in INTERNAL_CLAIMS:
            val[k] = INTERNAL_CLAIMS[k]
        else:
            v = params.get(k)
            if v is None or v == "":
                missing.append(k)
            elif isinstance(v, (bytes, bytearray)):
                # bytes (e.g. adj9_full_chain.fmt() stamps) must enter the
                # claim string as their TEXT, not as "b'...'" repr — the
                # claim must equal the wire value byte-for-byte.
                val[k] = bytes(v).decode("utf-8", "replace")
            else:
                val[k] = str(v)
    if missing:
        raise KeyError("claims_from_wire(%s): params missing %s"
                       % (kind, missing))
    return val


def claims_for_law(val, kind):
    """(padded #10 bytes, unpadded length) — the adj9_forge.claims_for_law
    rule: NUL-pad the law string to a 4-byte multiple (slice 105), #7 keeps
    the UNPADDED length (slice 99 §2)."""
    raw = build_desc10(val, kind).encode("latin1")
    return raw + b"\x00" * (-len(raw) % 4), len(raw)


def build_descriptors(claims_params, kind, d0, d2, d4):
    """The 11 descriptors in VA order.  Returns (descs, meta)."""
    padded, unpadded = claims_for_law(claims_params, kind)
    if len(d0) != 144 or len(d2) != 4 or len(d4) != 32:
        raise ValueError("region sizes must be 144/4/32 bytes")
    # (len_dw, tag=0, data) — the vm_final.Ex descriptor triple
    descs_by_idx = {
        0: (36, 0, d0),                                # per-call region core
        9: (5, 0, bytes.fromhex(D9_HEX)),              # cert SHA-1
        8: (4, 0, bytes.fromhex(D8_HEX)),              # 16-B constants
        4: (8, 0, d4),                                 # region structured record
        2: (1, 0, d2),                                 # region per-call word
        7: (1, 0, struct.pack(">I", unpadded)),        # UNPADDED #10 length
        10: (len(padded) // 4, 0, padded),             # claims (padded)
        5: (1, 0, struct.pack(">I", D5_WORD)),
        6: (1, 0, struct.pack(">I", D5_WORD)),
        1: (0, 0, b""),
        3: (0, 0, b""),
    }
    descs = [descs_by_idx[i] for i in VA_ORDER]
    meta = {"desc10_unpadded": unpadded, "desc10_padded": len(padded),
            "kind": kind}
    return descs, meta


# ---------------------------------------------------------------------------
# FinEx execution -> 192-B blob
# ---------------------------------------------------------------------------
def finex_mint(descs, second, max_steps=40_000_000):
    """Run the FinEx VM (seed = signing second) and assemble the 192-B blob.

    The blob stream is located by the header law (first 4 emitted words ==
    Random3(second) pair-XOR units), preferring the canonical sink — the
    stream is NOT assumed a priori (adj9_forge.make_signature_map rule).
    Returns (blob, info).
    """
    ex = FinEx(int(second), descs)
    status = ex.run(max_steps=max_steps)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    hdr = struct.unpack(">4I", make_header(int(second)))

    def words0_3(m):
        return tuple(m.get(k, 0) for k in range(4))

    stream = None
    if SINK in bys and words0_3(bys[SINK]) == hdr:
        stream = SINK
    else:
        for sva in sorted(bys):
            if words0_3(bys[sva]) == hdr:
                stream = sva
                break
    if stream is None:
        raise RuntimeError(
            "no emission stream matched Random3(%d) — status=%s nrand=%d "
            "streams=%d" % (second, status, ex.nrand, len(bys)))
    blob = b"".join(struct.pack(">I", bys[stream].get(k, 0))
                    for k in range(BLOB_WORDS))
    if blob[:16] != make_header(int(second)):
        raise AssertionError("header law broken")
    info = {"status": status, "steps": ex.steps, "nrand": ex.nrand,
            "stream": stream, "header": blob[:16]}
    return blob, info


def mint_blob_ex(claims_params, second, V=None, pid=None, tid=None,
                 kind="session", region=None, max_steps=40_000_000, head=None):
    """Full mint with diagnostics.  Returns (blob_192B, info)."""
    if not isinstance(claims_params, dict):
        raise TypeError("claims_params must be the claims map (dict), got %r"
                        % type(claims_params))
    pid = int(pid if pid is not None else
              os.environ.get("ADJ9_PID", DEFAULT_PID))
    tid = int(tid if tid is not None else
              os.environ.get("ADJ9_TID", DEFAULT_TID))
    if V is None and region is None:
        V = make_V(second)          # live-mint default: the real clock's µs
    d0, d2, d4 = resolve_region(V, pid, tid, region, head=head)
    descs, meta = build_descriptors(claims_params, kind, d0, d2, d4)
    blob, info = finex_mint(descs, second, max_steps=max_steps)
    info.update(meta)
    info.update({"second": int(second), "V": V, "pid": pid, "tid": tid,
                 "d0": d0, "d2": d2, "d4": d4})
    return blob, info


def mint_blob(claims_params, second, V=None, pid=None, tid=None,
              kind="session", region=None, max_steps=40_000_000, head=None):
    """THE mint: claims map + signing second + region -> 192-B adj9 blob.

    region=None -> #0/#2/#4 come from F.py: region(V, pid, tid).  With F.py
    absent, V must be accompanied by region=(d0, d2, d4) (words or bytes).
    """
    blob, _ = mint_blob_ex(claims_params, second, V=V, pid=pid, tid=tid,
                           kind=kind, region=region, max_steps=max_steps,
                           head=head)
    return blob


def auth_header(blob):
    """The Authorization header — byte-exact adj9_full_chain._auth_header."""
    return ('Signature signature="%s",adj_signing_id="%s",'
            'algorithm="adj9",headers_id="10",native_version="%s",'
            'adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_SIGNING_ID,
               NATIVE_VERSION, ADJ_VERIFICATION))


# ---------------------------------------------------------------------------
# Region structural laws (advisory check — what the booking gate can test)
# ---------------------------------------------------------------------------
def region_laws(d0b, d4b):
    """Laws every real F(V,pid,tid) output satisfies (fill_model §4):
      L1 tile: some phase has U[2]^U[0] == R||R (both 16-bit halves equal)
      L2:      d4[6]>>16 == R for one of those R
      L3:      d0[1] (X) == U[3] at some phase
    A random region fails L1 with probability ~1-2^-16 per position."""
    d0 = struct.unpack(">36I", d0b)
    d4 = struct.unpack(">8I", d4b)
    hits = []
    for p in range(0, 32):            # tile windows starting at d0[2+p]; 36-word d0
        x = d0[2 + p] ^ d0[4 + p]
        if (x >> 16) == (x & 0xFFFF):
            hits.append((p, x & 0xFFFF))
    l1 = bool(hits)
    l2 = any((d4[6] >> 16) == r for (_, r) in hits)
    l3 = any(d0[1] == d0[2 + p + 3] for (p, _) in hits)
    return {"L1_tile_Rrep": l1, "L1_hits": hits[:8],
            "L2_d4_6_hi_eq_R": l2, "L3_X_eq_U3": l3}


# ---------------------------------------------------------------------------
# Synthetic claims + offline dry-run self-check (NO network)
# ---------------------------------------------------------------------------
def _iso(ts, ms, off_min=120):
    dt = (datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)
          + datetime.timedelta(minutes=off_min))
    return "%s.%03dZ+0200" % (dt.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def synthetic_claims(kind="session", second=None):
    """A complete, clearly-SYNTHETIC law map (self-test input only)."""
    val = {
        "adj_verification": ADJ_VERIFICATION,
        "android_uuid": "11111111-2222-4333-8444-555555555555",
        "api_level": "31", "app_token": APP_TOKEN, "app_version": "3.13.9",
        "created_at": _iso(second, 928),
        "device_name": "moto g42", "device_type": "phone",
        "environment": "production",
        "gps_adid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "gps_adid_src": "service", "hardware_name": "S2SE32.28-28-4",
        "installed_at": _iso(second - 170, 774),
        "os_build": "S2SE32.28-28-4", "os_name": "android", "os_version": "12",
        "package_name": "com.penti.app",
        "adj_signing_id": ADJ_SIGNING_ID,
        "client_sdk": CLIENT_SDK, "headers_id": "10",
        "native_version": NATIVE_VERSION,
    }
    if kind == "session":
        val.update({"initiating_package_name": "com.android.vending",
                    "session_count": "1", "store_name_from_system":
                    "com.android.vending", "tracking_enabled": "1",
                    "updated_at": _iso(second - 170, 774)})
    elif kind == "click":
        val.update({"google_play_instant": "0",
                    "referrer": "adjust_reftag=SYNTHETIC&utm_source=test",
                    "referrer_api": "google", "session_count": "1",
                    "session_length": "0", "source": "install_referrer",
                    "subsession_count": "1", "time_spent": "0",
                    "tracking_enabled": "1",
                    "updated_at": _iso(second - 170, 774)})
    elif kind == "attribution":
        val.update({"initiated_by": "sdk", "tracking_enabled": "1"})
    else:
        raise ValueError(kind)
    val["activity_kind"] = kind
    return val


def dry_run(second=None, kind="session"):
    """Task-4 self-check: mint at second X with placeholder region values and
    validate the blob structure OFFLINE.  Returns True iff all checks pass."""
    second = int(second if second is not None else time.time())
    fn = region_fn()
    V = make_V(second)
    if fn is not None:
        region = resolve_region(V, DEFAULT_PID, DEFAULT_TID)
        region_src = "F.py region(V=%d, pid=%d, tid=%d) [REAL]" % (
            V, DEFAULT_PID, DEFAULT_TID)
    else:
        region = placeholder_region(V)
        region_src = ("PLACEHOLDER SplitMix64 stand-in (F.py absent) — "
                      "expected to FAIL the region laws; structure only")
    val = synthetic_claims(kind, second)
    print("=== mint_pipeline dry-run (OFFLINE) ===")
    print("second      :", second)
    print("kind        :", kind)
    print("region src  :", region_src)
    print("V           : 0x%08x (= tv_sec ^ tv_usec)" % V)
    print("claims      : %d law keys, kind=%s" % (len(val), kind))

    t0 = time.time()
    blob, info = mint_blob_ex(val, second, V=V, region=region, kind=kind)
    print("mint        : status=%s steps=%d nrand=%d stream=0x%x (%.1fs)"
          % (info["status"], info["steps"], info["nrand"], info["stream"],
             time.time() - t0))

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                                (" — " + detail) if detail else ""))

    # 1. size
    check("blob is 192 bytes (48 BE words)", len(blob) == 192,
          "%d B" % len(blob))
    # 2. header law
    hdr = make_header(second)
    check("blob[:16] == make_header(second)", blob[:16] == hdr,
          hdr.hex())
    # 3. header == 4 pair-XOR units of bionic random() TYPE_3
    r3 = Random3(second)
    draws = [r3.next() for _ in range(8)]
    units = [draws[2 * i] ^ draws[2 * i + 1] for i in range(4)]
    check("header == 4 pair-XOR units of Random3(second)",
          struct.unpack(">4I", blob[:16]) == tuple(units),
          "units %s" % " ".join("%08x" % u for u in units))
    # 4. body == an independent re-run of FinEx(descs, second)
    val2 = synthetic_claims(kind, second)
    blob2, _ = mint_blob_ex(val2, second, V=V, region=region, kind=kind)
    check("body == FinEx(descs, second) re-run (byte-identical remint)",
          blob2 == blob)
    # 5. clean exit, exactly the 8 header draws consumed
    check("status exit-clean", info["status"] == "exit-clean", info["status"])
    check("nrand == 8 (srand re-seeded per signing; first 8 draws = header)",
          info["nrand"] == 8, str(info["nrand"]))
    # 6. descriptor length coupling
    check("#10 padded to a 4-byte multiple", info["desc10_padded"] % 4 == 0,
          "padded=%d unpadded=%d" % (info["desc10_padded"],
                                     info["desc10_unpadded"]))
    check("#7 carries the UNPADDED length", True, "unpadded=%d"
          % info["desc10_unpadded"])
    # 7. region laws (advisory — placeholder is expected to fail)
    laws = region_laws(info["d0"], info["d4"])
    print("  [adv] region structural laws on the region USED:")
    print("        L1 tile U[2]^U[0]==R||R : %s %s"
          % ("PASS" if laws["L1_tile_Rrep"] else "FAIL", laws["L1_hits"]))
    print("        L2 d4[6]>>16 == R       : %s"
          % ("PASS" if laws["L2_d4_6_hi_eq_R"] else "FAIL"))
    print("        L3 X == U[3]            : %s"
          % ("PASS" if laws["L3_X_eq_U3"] else "FAIL"))
    if fn is None:
        print("        (placeholder region: FAIL is EXPECTED — a real F.py "
              "region satisfies all three, fill_model §4)")
    # 8. wire-form coupling preview
    print("Authorization:", auth_header(blob)[:96] + "...")
    print("blob hex     :", blob.hex())
    print("  header(16B): %s" % blob[:16].hex())
    print("  body(176B) : %s" % blob[16:].hex())
    print("=== DRY-RUN: %s ===" % ("PASS" if ok else "FAIL"))
    return ok


# ---------------------------------------------------------------------------
# Corpus validation — 6 self-consistent rows, descriptors+seconds -> 48/48
# ---------------------------------------------------------------------------
def validate_corpus(rows=(0, 1, 4, 5, 6, 7), max_steps=60_000_000):
    """Reproduce the corpus blobs from their OWN descriptors + seconds (the
    _finex_corpus proof, re-driven through this module's assembly path).
    Rows 2/3 are the known non-self-consistent captures (excluded)."""
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    print("=== corpus validation (OFFLINE): FinEx(descs, second) vs capture ===")
    all_ok = True
    for i in rows:
        r, p = asg[i], ph3[i]
        descs = []
        for bi in VA_ORDER:
            hx = r.get("d%d" % bi, "")
            data = bytes.fromhex(hx) if hx else b""
            lendl = len(data) // 4
            descs.append((lendl, 0, data[:lendl * 4]))
        second = p["second"]
        tgt = struct.unpack(">48I", bytes.fromhex(p["blob"]))
        t0 = time.time()
        try:
            blob, info = finex_mint(descs, second, max_steps=max_steps)
            got = struct.unpack(">48I", blob)
            diff = [j for j in range(48) if got[j] != tgt[j]]
            hh = sum(1 for j in range(4) if got[j] == tgt[j])
            bb = 44 - len([j for j in diff if j >= 4])
            print("ROW %d second=%d src=%s status=%s steps=%d %.0fs nrand=%d "
                  "match=%d/48 (hdr %d/4 body %d/44) sink=0x%x"
                  % (i, second, r.get("src", "?"), info["status"],
                     info["steps"], time.time() - t0, info["nrand"],
                     48 - len(diff), hh, bb, info["stream"]))
            if diff:
                print("   diff words (%d): %s" % (len(diff), diff[:50]))
                for j in diff[:4]:
                    print("      w%-2d cap=%08x finex=%08x"
                          % (j, tgt[j], got[j]))
            all_ok &= (not diff and hh == 4)
        except Exception as e:
            print("ROW %d second=%d EXCEPTION: %s" % (i, second, e))
            all_ok = False
        sys.stdout.flush()
    print("=== CORPUS: %s (%d/%d rows at 48/48) ==="
          % ("PASS 48/48 ON ALL ROWS" if all_ok else "FAIL",
             sum(1 for _ in rows) if all_ok else 0, len(rows)))
    return all_ok


# ---------------------------------------------------------------------------
# LIVE funnel wiring (mint-signed booking + device oracle) — see testbed
# ---------------------------------------------------------------------------
def _funnel_imports():
    import adj9_full_chain as FC
    import run_funnel as RF
    from verify_funnel import adb, su, set_gaid, fiddler_up, SERIAL, PKG
    return FC, RF, adb, su, set_gaid, fiddler_up, SERIAL, PKG


def _fresh_gps_link(link):
    """Replace EVERY GAID in the tracker link (yesterday's click_id/idfa and
    the callback-url copies) with the fresh install GAID."""
    gps = str(uuid.uuid4())
    new, n = re.subn(OLD_GAID_RE, gps, link)
    print("[mint] fresh gps=%s (link GAIDs replaced: %d)" % (gps, n), flush=True)
    return gps, new


def api_session_mint(gps, auid, ins=None, V=None, pid=None, tid=None,
                     max_steps=40_000_000):
    """adj9_full_chain.api_session with the blob minted by mint_blob (law #10
    + F.py region) instead of the golden-template signer.  Wire params come
    from the same golden S1P template; the claims map is derived FROM the
    wire params, so the signature covers exactly what is sent."""
    FC, _, _, _, _, _, _, _ = _funnel_imports()
    sec = int(time.time()) + FC.MINT_SKEW
    insd = (ins or FC.fmt(sec - 170, 774)).decode()
    ca_ms, sa_ms = 928, 942
    p = dict(FC.S1P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": FC.fmt(sec, ca_ms).decode(),
              "sent_at": FC.fmt(sec, sa_ms).decode(),
              "installed_at": insd, "updated_at": insd})
    p.update(FC.DEV)
    p.pop("no_sim", None)            # helper flag, never a wire param
    # The real app never puts SIM network codes on the wire: mcc/mnc appear in
    # zero requests across both full captures (attrq.txt, attrq2.txt). They
    # ride along in FC.DEV, so drop them here as well as under no_sim.
    p.pop("mcc", None)
    p.pop("mnc", None)
    p.pop("install_version", None)   # 3.13.9 session has none (winner-proven)
    val = claims_from_wire(p, "session")
    if V is None:
        V = make_V_consistent(sec, ca_ms)
    blob, info = mint_blob_ex(val, sec, V=V, pid=pid, tid=tid,
                              kind="session", max_steps=max_steps,
                              head=head_for_endpoint("session"))
    print("[mint] session blob status=%s steps=%d sec=%d #10=%dB(padded)/%dB"
          % (info["status"], info["steps"], sec, info["desc10_padded"],
             info["desc10_unpadded"]), flush=True)
    return FC.send("https://app.adjust.com/session", p, blob)


def api_sdk_click_mint(gps, auid, referrer, t_track, t_begin=None, ins=None,
                       V=None, pid=None, tid=None, max_steps=40_000_000):
    """adj9_full_chain.api_sdk_click with a mint_blob-signed blob (same shape
    parity as the crafted winner: golden S2P template + fresh ids/times)."""
    FC, _, _, _, _, _, _, _ = _funnel_imports()
    sec = int(time.time()) + FC.MINT_SKEW
    insd = (ins or FC.fmt(sec - 170, 774)).decode()
    tb = t_begin if t_begin is not None else t_track + 5
    ca_ms, sa_ms = 961, 970
    p = dict(FC.S2P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": FC.fmt(sec, ca_ms).decode(),
              "sent_at": FC.fmt(sec, sa_ms).decode(),
              "installed_at": insd,
              "referrer": referrer, "source": "install_referrer",
              "referrer_api": "google",
              "click_time": FC.fmt(t_track, 0).decode(),
              "click_time_server": FC.fmt(t_track - 2, 0).decode(),
              "install_begin_time": FC.fmt(tb, 0).decode(),
              "install_begin_time_server": FC.fmt(tb - 2, 0).decode(),
              # the golden S2P template carries a stale updated_at; the device
              # sets updated_at = installed_at on the sdk_click too (SAZ s.2).
              "updated_at": insd})
    p.update(FC.DEV)
    p.pop("no_sim", None)
    # Never on the wire: the real app sends no SIM network codes in any capture.
    p.pop("mcc", None)
    p.pop("mnc", None)
    if FC.ADD_IDFA:
        p["idfa"] = gps
    val = claims_from_wire(p, "click")
    if V is None:
        V = make_V_consistent(sec, ca_ms)
    blob, info = mint_blob_ex(val, sec, V=V, pid=pid, tid=tid,
                              kind="click", max_steps=max_steps,
                              head=head_for_endpoint("click"))
    print("[mint] sdk_click blob status=%s steps=%d sec=%d #10=%dB(padded)/%dB"
          % (info["status"], info["steps"], sec, info["desc10_padded"],
             info["desc10_unpadded"]), flush=True)
    return FC.send("https://app.adjust.com/sdk_click", p, blob)


def api_attribution_mint(gps, auid, ptoken, initiated_by="backend",
                         V=None, pid=None, tid=None, max_steps=40_000_000):
    """GET /attribution signed by the REAL F.py mint.

    `adj9_full_chain.api_attribution` is NOT usable for a faithful run: it goes
    through `make_signature`, which patches a golden template and fills the
    region with `d0 = 144 zero bytes` and `d4 = 32 random bytes` (HRAND/ZERO0).
    That is a fabricated region, not the native transform — arms C and D used it
    for their polls.  This mirrors the same wire params exactly but mints the
    blob through `mint_blob_ex` -> `resolve_region` -> F.py.
    """
    FC, _, _, _, _, _, _, _ = _funnel_imports()
    sec = int(time.time()) + FC.MINT_SKEW
    ca_ms, sa_ms = 666, 696
    p = {"initiated_by": initiated_by, "gps_adid_attempt": "1",
         "api_level": FC.DEV["api_level"],
         "app_version": FC.DEV["app_version"], "app_token": FC.APP_TOKEN,
         "os_version": FC.DEV["os_version"],
         "created_at": FC.fmt(sec, ca_ms).decode(), "device_type": "phone",
         "gps_adid": gps, "foreground": "1",
         "android_uuid": auid, "sent_at": FC.fmt(sec, sa_ms).decode(),
         "offline_mode_enabled": "0", "device_name": FC.DEV["device_name"],
         "environment": "production", "needs_response_details": "1",
         "attribution_deeplink": "1", "package_name": "com.penti.app",
         "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
         "tracking_enabled": "1"}
    if FC.ADD_IDFA:
        p["idfa"] = gps
    val = claims_from_wire(p, "attribution")
    if V is None:
        V = make_V_consistent(sec, ca_ms)
    blob, info = mint_blob_ex(val, sec, V=V, pid=pid, tid=tid,
                              kind="attribution", max_steps=max_steps,
                              head=head_for_endpoint("attribution"))
    print("[mint] attribution blob status=%s steps=%d sec=%d #10=%dB(padded)/%dB"
          % (info["status"], info["steps"], sec, info["desc10_padded"],
             info["desc10_unpadded"]), flush=True)
    return FC.send("https://app.adjust.com/attribution", p, blob,
                   method="GET")


def device_read_verdict(res, out_path):
    """The slice-144 oracle: write GPS to the moto g42 (set_gaid), wipe app
    data, launch, then su cat AdjustAttribution — NUL-stripped, grepped for
    {"tracker_token..., polled PAST 120 s (15 x 12 s = 180 s)."""
    FC, RF, adb, su, set_gaid, fiddler_up, SERIAL, PKG = _funnel_imports()
    print("[device] backing up current AdjustAttribution...", flush=True)
    prev = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
    open(os.path.join(HERE, "mint_prev_attribution.bak"), "w").write(prev)
    print("[device] prev (first 160):",
          prev[:160].replace("\n", " ").replace("\0", " "), flush=True)

    old = set_gaid(res["gps"])
    print("[device] GAID: %s -> %s" % (old, res["gps"]), flush=True)
    res["old_gaid"] = old
    time.sleep(2)

    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs "
       "/data/data/%s/databases" % (PKG, PKG, PKG))
    time.sleep(1)
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    print("[device] app launched; polling its own attribution read "
          "(180 s window)...", flush=True)

    verdict = None
    for i in range(15):
        time.sleep(12)
        raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null "
                 "| tr -d '\\000'" % PKG)
        raw = raw.replace("\0", "")          # belt + braces
        m = re.search(r'\{"tracker_token.*?\}', raw)
        if m:
            try:
                verdict = json.loads(m.group(0) + "}")
            except Exception:
                continue
            if verdict:
                break
    print(flush=True)
    if verdict:
        tok = verdict.get("tracker_token")
        net = verdict.get("network")
        print("VERDICT (app's own read): token=%s network=%s" % (tok, net))
        print("  tracker_name=%s installed_at=%s is_reattr=%s"
              % (verdict.get("tracker_name"), verdict.get("installed_at"),
                 verdict.get("is_reattributed")))
        verdict["_success"] = bool(tok != ORGANIC_TOKEN and net != "Organic")
        print("SUCCESS CRITERION (token != %s / network != Organic, read by "
              "the APP ITSELF): %s"
              % (ORGANIC_TOKEN, "MET" if verdict["_success"] else "NOT MET"))
    else:
        print("VERDICT: none yet (app file still empty after 180 s)")
    res["verdict_device_oracle"] = verdict
    json.dump(res, open(out_path, "w"), indent=1)
    return verdict


def _funnel_env(FC, RF, fiddler_up):
    """Shared transport/profile setup: yesterday's device-data JSON, +0530,
    no idfa on the wire, direct unless Fiddler is on 8888."""
    dev = json.loads(RF.DEVICE_JSON)
    FC.DEV, FC.UA = RF.dev_from_json(dev), RF.ua_from_json(dev)
    FC.OFF_MINUTES, FC.OFF_LABEL = 330, "+0530"
    FC.ADD_IDFA = False
    if fiddler_up():
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8888"
        FC.USE_PROXY = True
        print("[mint] proxy ON (Fiddler detected on 8888)", flush=True)
    else:
        FC.USE_PROXY = False
        print("[mint] direct (no Fiddler on 8888)", flush=True)
    return dev


def run_arm_a():
    """ARM A (slice-144 shape): PC click + MINT-SIGNED session + sdk_click.
    NO crafted attribution polls (the slice-97 downgrade hazard).  Then the
    moto g42 reads its own verdict.  Parity with verify_funnel.py except the
    signer."""
    FC, RF, adb, su, set_gaid, fiddler_up, SERIAL, PKG = _funnel_imports()
    out_path = os.path.join(HERE, "mint_arm_a_result.json")
    res = {}
    gps, link = _fresh_gps_link(RF.LINK)
    auid = str(uuid.uuid4())
    dev = _funnel_env(FC, RF, fiddler_up)
    if region_fn() is None:
        raise SystemExit("F.py absent — cannot mint a real region; "
                         "drop F.py first (see mint_testbed.md §5)")

    print("[arm-a] STEP 1/3 real click (PC, chrome131 impersonation)...",
          flush=True)
    t_click = time.time()
    ref, hop = RF.click_tracker(link, gps, FC.UA, dev)
    print("[arm-a] REFERRER:", (ref or "")[:120], flush=True)
    assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
    res["referrer"] = ref
    res["reftag"] = ref.split("adjust_reftag=", 1)[1].split("&")[0]

    tb = int(t_click) + 30
    ins = FC.fmt(int(t_click) + 37, 774)
    print("[arm-a] first-open delay 25s (CTIT ~62s)...", flush=True)
    time.sleep(25)

    print("[arm-a] STEP 2/3 mint-signed session...", flush=True)
    s2, r2 = api_session_mint(gps, auid, ins)
    print("[arm-a] SESSION:", s2, r2[:200], flush=True)
    res["session"] = [s2, r2[:300]]
    json.dump(res, open(out_path, "w"), indent=1)
    time.sleep(3)

    print("[arm-a] STEP 3/3 mint-signed sdk_click...", flush=True)
    s1, r1 = api_sdk_click_mint(gps, auid, ref, int(t_click), tb, ins)
    print("[arm-a] SDK_CLICK:", s1, r1[:200], flush=True)
    res["sdk_click"] = [s1, r1[:2000]]
    # STEP 4 intentionally ABSENT: no crafted attribution polls, ever.
    print("[arm-a] no attribution polls fired (slice-92/97: crafted polls "
          "read the Organic fallback)", flush=True)
    res.update(gps=gps, auid=auid)
    json.dump(res, open(out_path, "w"), indent=1)

    device_read_verdict(res, out_path)
    print("saved", out_path, flush=True)
    return res


def run_arm_b():
    """ARM B (signer isolation): the winning fresh_click_install.py shape —
    GAID on the device FIRST, click fired FROM the device, CTIT 30 s — with
    ONE change vs slice 141: the booking session is MINT-SIGNED, not the
    app's.  No sdk_click, no polls.  Parity with verify_funnel2.py."""
    FC, RF, adb, su, set_gaid, fiddler_up, SERIAL, PKG = _funnel_imports()
    out_path = os.path.join(HERE, "mint_arm_b_result.json")
    res = {}
    gps, _ = _fresh_gps_link("x")
    auid = str(uuid.uuid4())
    _funnel_env(FC, RF, fiddler_up)
    if region_fn() is None:
        raise SystemExit("F.py absent — cannot mint a real region; "
                         "drop F.py first (see mint_testbed.md §5)")

    print("[arm-b] STEP 1/3 GAID on device FIRST...", flush=True)
    # force-stop the app FIRST: a running app re-sends its own session on the
    # new GAID and rate-limits our mint session (contaminated first run).
    adb("shell", "am", "force-stop", PKG)
    time.sleep(1)
    old = set_gaid(gps)
    print("[arm-b] GAID: %s -> %s" % (old, gps), flush=True)
    res["old_gaid"] = old
    res["gps"] = gps
    res["auid"] = auid
    time.sleep(2)

    print("[arm-b] STEP 2/3 click FROM the device...", flush=True)
    url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
           "&creative=penti_generic&click_id=%s&idfa=%s&gps_adid=%s"
           % (gps, gps, gps))
    r = adb("shell",
            "curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
            "-H 'User-Agent: Mozilla/5.0 (Linux; Android 12; moto g 42)'"
            % url, t=90)
    print("[arm-b] device click http:", r.strip()[-3:], flush=True)
    res["device_click"] = r.strip()[-3:]
    t_click = time.time()

    print("[arm-b] CTIT 30s...", flush=True)
    time.sleep(30)
    ins = FC.fmt(int(t_click) + 35, 774)
    print("[arm-b] STEP 3/3 mint-signed session (the ONE changed variable)...",
          flush=True)
    s2, r2 = api_session_mint(gps, auid, ins)
    print("[arm-b] MINT SESSION:", s2, r2[:200], flush=True)
    res["session"] = [s2, r2[:300]]
    # NO sdk_click, NO crafted attribution — win-path shape.
    json.dump(res, open(out_path, "w"), indent=1)

    device_read_verdict(res, out_path)
    print("saved", out_path, flush=True)
    return res


# ---------------------------------------------------------------------------
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if mode == "selftest":
        sec = None
        if "--second" in sys.argv:
            sec = int(sys.argv[sys.argv.index("--second") + 1])
        raise SystemExit(0 if dry_run(sec) else 1)
    if mode == "validate-corpus":
        rows = (0, 1, 4, 5, 6, 7)
        if len(sys.argv) > 2:
            rows = tuple(int(x) for x in sys.argv[2].split(","))
        raise SystemExit(0 if validate_corpus(rows) else 1)
    if mode in ("arm-a", "arm-b"):
        if "--live" not in sys.argv:
            print("REFUSING to touch the network: %s is a LIVE funnel arm.\n"
                  "Read mint_testbed.md first; run with:\n"
                  "  python mint_pipeline.py %s --live" % (mode, mode))
            raise SystemExit(2)
        raise SystemExit(0 if (run_arm_a() if mode == "arm-a"
                               else run_arm_b()) else 1)
    if mode == "mint":
        # one explicit mint; requires F.py (or --placeholder for a dry blob)
        kind = "session"
        if "--kind" in sys.argv:
            kind = sys.argv[sys.argv.index("--kind") + 1]
        sec = int(time.time())
        if "--second" in sys.argv:
            sec = int(sys.argv[sys.argv.index("--second") + 1])
        usec = None
        if "--usec" in sys.argv:
            usec = int(sys.argv[sys.argv.index("--usec") + 1])
        pid = int(os.environ.get("ADJ9_PID", DEFAULT_PID))
        tid = int(os.environ.get("ADJ9_TID", DEFAULT_TID))
        V = make_V(sec, usec)
        region = None
        if "--placeholder" in sys.argv:
            region = placeholder_region(V)
        val = synthetic_claims(kind, sec)
        blob, info = mint_blob_ex(val, sec, V=V, pid=pid, tid=tid,
                                  kind=kind, region=region)
        print(json.dumps({"second": sec, "V": "0x%08x" % V, "pid": pid,
                          "tid": tid, "kind": kind, "status": info["status"],
                          "steps": info["steps"], "nrand": info["nrand"],
                          "header": blob[:16].hex(), "blob": blob.hex(),
                          "authorization": auth_header(blob)}, indent=1))
        raise SystemExit(0)
    print(__doc__)
    raise SystemExit(2)


if __name__ == "__main__":
    main()

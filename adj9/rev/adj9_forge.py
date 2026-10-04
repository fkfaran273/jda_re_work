"""adj9_forge.py — the ONE signature generator + Adjust API client.

Reads ONLY adj9_material.json (VM slots, claims base + field offsets,
wire templates — consolidated from fin_descs / golden_saz / triples).

Contract enforced here:
 * make_signature(second, overrides) swaps every coupled field into the
   claims blob (equal length REQUIRED, slot drift asserted) and the
   caller passes the SAME overrides into wire_params() — so the
   signature's embedded claims can never drift from the HTTP form.
 * H: fresh random 32 B per call (exits clean iff #0 zeroed — full_chain).
 * #0: zeros + one random dword at 140:144.
"""
import base64
import json
import os
import random
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

M = json.load(open(os.path.join(HERE, "adj9_material.json")))
ORDER = M["va_order"]
S0 = 0x5500000000

# ---------------------------------------------------------------------------
# #4 IS NOT H (rev/WALL_A_SLICE_103.md).
#
# adj9_material.slots has NO entry for build_idx 4, and its H_policy says
# "random 32B per call" with captured_H holding two uniform MACs. So the old
# make_signature() filled slot #4 with a MAC (or random bytes). Measured effect
# of that (rev/h4_vs_H.py): a real H in #4 yields a blob 44/48 dwords different
# from the device's, while the captured structured #4 reproduces it exactly.
#
# The real #4 is a per-call, structured, NON-cryptographic 32-byte record
# (golden: 00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e).
# Until its derivation is known, the only correct value is a captured one, so we
# take the default straight from fin_descs.json (the same source
# make_signature_map already used).
# ---------------------------------------------------------------------------
try:
    _FIN = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
    FIN_DESC = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
                for d in _FIN["descs"]}
except Exception:
    FIN_DESC = {}
CAPTURED_D4 = FIN_DESC.get(4, (8, bytes(32)))[1]

CLAIM_KEYS = set(M["claims_fields"])


def claims_for(overrides):
    data = bytearray(bytes.fromhex(M["claims_base_hex"]))
    for k, val in overrides.items():
        if k not in M["claims_fields"]:
            continue
        i, j, old = M["claims_fields"][k]
        old_b, new_b = old.encode("latin1"), val.encode("latin1")
        if len(old_b) != len(new_b):
            raise ValueError("claim swap %s: %r(%d) vs %r(%d) unequal"
                             % (k, old, len(old_b), val, len(new_b)))
        if data[i:j] != old_b:
            raise AssertionError("slot drift at %s" % k)
        data[i:j] = new_b
    return bytes(data)


def make_signature(second, overrides, H=None, zero_core=True, d4=None):
    """One 192-B adj9 blob. Returns (status, blob, d4_used).

    slot #4 = the captured STRUCTURED record, never a MAC (slice 103). `H` is
    accepted for backward compatibility but is NOT a #4 value: if `H` is passed
    without `d4`, it is ignored for the slot (a warning is printed) because a
    uniform MAC in #4 produces a blob 44/48 dwords off the device's.
    """
    by = {int(k): (v["len_dw"], bytes.fromhex(v["data_hex"]))
          for k, v in M["slots"].items()}
    if zero_core:
        d0 = bytearray(144)
        d0[140:144] = struct.pack(">I", random.getrandbits(32))
        by[0] = (36, bytes(d0))
    # #4: captured structured record (see the module note above)
    if d4 is None and H is not None:
        print("  ! make_signature(H=...) ignored for slot #4: #4 is not H "
              "(slice 103); using the captured #4")
    by[4] = (8, d4 if d4 is not None else CAPTURED_D4)
    cl = claims_for(overrides)
    by[10] = (len(cl) // 4, cl)
    by[7] = (1, struct.pack(">I", (len(cl) // 4) << 2))
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    blob = b"".join(struct.pack(">I", out.get((S0, k), 0)) for k in range(48))
    assert blob[:16] == make_header(second), "header law broken"
    return status, blob, by[4][1]


def make_signature_map(val, kind="session", second=None, d4=None, d0=None,
                       H=None, h_input=None):
    """192-B adj9 blob for an ARBITRARY map — VERIFIED BYTE-EXACT recipe.

    Proven construction (rev/verify_law_blob.py, log rev/vlb.log):
      * descriptors fed to FinEx in adj9_material va_order
        [0,9,8,4,2,7,10,5,1,6,3], each as (len_dw, 0, data);
      * #10 = desc10_law.build_desc10(val, kind)   <- the LAW, byte-exact
      * #7  = struct.pack(">I", len(desc10))       <- its byte length
      * #1/#3 empty, #5/#6 = 00000000, #8/#9/#2 from the captured material;
      * the output blob stream is FOUND by matching Random3(second) — it is not
        safe to assume a fixed sink id;
      * status must be exit-clean and blob[:16] == Random3(second).

    Result on the device's own capture (map + second 1789240512): BYTE-EXACT,
    both with the captured #10 (control) and with the LAW-built #10.

    Still OPAQUE inputs (not computable from the map):
      #4 = 32 B, the VM's H input (captured 00100400041440008000c44088104c05
           0025c852...). Randomising it changes 176/192 bytes (variant C) while
           keeping the blob self-consistent — it is an input, not a MAC that can
           be read back out of the blob.
      #0 = 144 B per-call core (synthesised when d0 is None).
    """
    by = {int(k): (v["len_dw"], bytes.fromhex(v["data_hex"]))
          for k, v in M["slots"].items()}
    # #0 and #4 are not in adj9_material: take the captured template if present
    try:
        cap = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
               for d in json.load(open(os.path.join(HERE, "fin_descs.json")))
               ["descs"]}
    except Exception:
        cap = {}
    if 0 in cap:
        by.setdefault(0, cap[0])
    # #4 is NOT H (slice 103): prefer an explicit d4, then the legacy h_input
    # alias, then the captured template. A passed H is ignored, with a warning.
    if d4 is None:
        d4 = h_input
    if d4 is None and H is not None:
        print("  ! make_signature_map(H=...) ignored: #4 is not H (slice 103)")
    if d4 is None and 4 in cap:
        d4 = cap[4][1]
    if d0 is not None:
        by[0] = (36, d0)
    if 0 not in by:
        b = bytearray(144)
        b[140:144] = struct.pack(">I", random.getrandbits(32))
        by[0] = (36, bytes(b))
    if d4 is not None:
        by[4] = (8, d4)
    cl = build_desc10(val, kind)
    by[10] = (len(cl) // 4, cl)
    by[7] = (1, struct.pack(">I", len(cl)))
    for i in ORDER:
        if i not in by:
            by[i] = (0, b"")          # empty descriptors (e.g. any gap)
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    # find the blob stream by the header law (Random3 of the call second)
    hdr = struct.unpack(">4I", make_header(second))
    stream = None
    for (s, n) in out:
        if tuple(out.get((s, k), 0) for k in range(4)) == hdr:
            stream = s
            break
    if stream is None:
        raise RuntimeError("no emission stream matched Random3(second)")
    blob = b"".join(struct.pack(">I", out.get((stream, k), 0))
                    for k in range(48))
    assert blob[:16] == make_header(second), "header law broken"
    return status, blob, d4


def wire_params(endpoint, prof):
    """HTTP form from the golden wire template + the SAME profile dict
    (only fields the endpoint carries; claims-coupled ones match blob)."""
    p = dict(M["wire_templates"].get(endpoint, {}))
    p.update({k: v for k, v in prof.items() if k in p or k in CLAIM_KEYS})
    return p


def auth_header(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="%s"'
            % (base64.b64encode(blob).decode(),
               M["claims_fields"]["adj_verification"][2]))


def build_desc10(val, kind="session"):
    """desc10 claims bytes for an ARBITRARY map via the PROVEN law
    (rev/desc10_law.py, slices 96/97 — byte-exact vs the device's own
    captures for session AND click).

    val: dict of claim-key -> str. Missing or empty law keys raise KeyError
    listing them (the native can only emit what the map carries).

    Note: make_signature() above still builds slot 10 from the golden claims
    base via claims_for() (fixed offsets, equal-length swaps). build_desc10
    is the variable-length path — the exact bytes the native would pack for
    a map the golden base never held (e.g. the device-minted maps of
    slice 97, or a click on an install that never saw google_play_instant).
    """
    from desc10_law import build_desc10 as _law_build
    return _law_build(val, kind).encode("latin1")

def make_signature_law(val, kind="attribution", second=None, d4=None, d0=None,
                       d2=None):
    """192-B adj9 blob for an ARBITRARY kind-driven map using the desc10 LAW.

    This is the path for endpoints whose claim set differs from the golden
    session base — in particular `/attribution`, whose claim set is 21 values
    (slice 107) and which every earlier arm signed with the 27-key SESSION set
    (asserting 7 claims the request never carries, and omitting `initiated_by`).

    Slots:
      #10 = the law-built claim string, NUL-padded to a 4-byte multiple
      #7  = the UNPADDED length of #10            (slice 99 §2)
      #9  = cert SHA-1, #8 = constant             (verified)
      #4  = captured STRUCTURED record            (NOT H — slice 103)
      #2  = captured per-call value               (slice 104: per-call state)
      #0  = captured core, or zeros + one random dword
      #1/#3/#5/#6 = empty / zero                  (verified)

    Returns (status, blob, desc10_bytes, unpadded_len).
    """
    import time
    desc, unpadded = claims_for_law(val, kind)
    by = {int(k): (v["len_dw"], bytes.fromhex(v["data_hex"]))
          for k, v in M["slots"].items()}
    by[9] = (5, FIN_DESC.get(9, (5, FIN_DESC.get(9, (5, b""))[1]))[1])
    by[8] = (4, FIN_DESC.get(8, (4, b""))[1])
    by[4] = (8, d4 if d4 is not None else CAPTURED_D4)
    if d2 is None:
        d2 = FIN_DESC.get(2, (1, b"\x00\x00\x00\x00"))[1]
    by[2] = (1, d2)
    if d0 is not None:
        by[0] = (36, d0)
    elif 0 not in by:
        b0 = bytearray(FIN_DESC.get(0, (36, bytes(144)))[1][:144].ljust(144, b"\0"))
        by[0] = (36, bytes(b0))
    by[10] = (len(desc) // 4, desc)
    by[7] = (1, struct.pack(">I", unpadded))
    for i in (1, 3, 5, 6):
        by.setdefault(i, (0 if i in (1, 3) else 1,
                          b"" if i in (1, 3) else b"\x00\x00\x00\x00"))
    if second is None:
        second = int(time.time())
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    hdr = struct.unpack(">4I", make_header(second))
    stream = None
    for (s, n) in out:
        if tuple(out.get((s, k), 0) for k in range(4)) == hdr:
            stream = s
            break
    if stream is None:
        raise RuntimeError("no emission stream matched Random3(second) — kind=%s "
                           "len(#10)=%d" % (kind, len(desc)))
    blob = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    assert blob[:16] == make_header(second), "header law broken"
    return status, blob, desc, unpadded


def claims_for_law(val, kind="session"):
    """Law-built slot-10 for an arbitrary map, with the native's padding rule.

    Returns (desc_bytes, unpadded_len):
      * desc_bytes   = the law string PADDED with NULs to a 4-byte multiple —
                       exactly the bytes the native holds in descriptor #10
                       (slice 105: 503->504 session+push_token,
                       530->532 click+push_token, 387->388 click);
      * unpadded_len = the value for descriptor #7, which carries the UNPADDED
                       length (slice 99 §2: 0x168/360, 0x183/387, 0x1f6/502,
                       0x211/529 — all four verified against captures).

    `push_token` is handled automatically when `val` carries it: it is an
    OPTIONAL profile claim that sorts between `package_name` and the following
    key (slice 105), which is why the captured #10 comes in 360/388/504/532 B.
    Verified: rev/desc10_push_test.py reproduces all 10 captured desc10 values
    byte-exactly through this path.
    """
    raw = build_desc10(val, kind)
    return raw + b"\x00" * (-len(raw) % 4), len(raw)


DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(endpoint, path, params, blob, ua, method="POST"):
    auth = auth_header(blob)
    if method == "POST":
        req = urllib.request.Request("https://app.adjust.com" + path,
                                     data=urllib.parse.urlencode(params)
                                     .encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    else:
        req = urllib.request.Request(
            "https://app.adjust.com%s?%s" % (path,
                                             urllib.parse.urlencode(params)),
            method="GET")
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("Authorization", auth)
    req.add_header("User-Agent", ua)
    req.add_header("Accept-Encoding", "identity")
    try:
        with DIRECT.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def iso_plus0200(ts, ms=0):
    dt = datetime_ts(ts)
    return "%s.%03dZ+0200" % (dt.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def datetime_ts(ts):
    import datetime
    return (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
            + datetime.timedelta(hours=2))

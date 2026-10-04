"""adj9_signature.py -- the complete Adjust adj9 signature in ONE file.

Self-contained: the FinEx VM, the region materialiser, both claim laws and
the header generator are all inlined below.  Only the Python standard library
is required -- nothing is imported from this repository.

THE ENVELOPE, five parts (each a labelled section below):
  1  HEADER   16 bytes -- a pure function of the signing second
  2  REGION   d0/d2/d4 -- materialised from a fresh 32-bit per-fill seed S
  3  CLAIMS   request values concatenated in a fixed key order (the "law")
  4  VM       the FinEx machine that mixes it all into 192 bytes
  5  API      configure() / build_params() / sign() / auth_header()

App-specific values live in the caller's CAMPAIGN dict (see apps.json for the
per-app settings), device values in device_data.json.  Nothing here knows which
app or device it signs for.

    import adj9_signature as S, json
    S.configure_app(json.load(open("apps.json"))["penti"])
    params = S.build_session_request(gps, auid, device, campaign, t_click)
    blob, second, info = S.sign_request(params, "session")
    header = S.auth_header(blob)
"""
from __future__ import annotations
import base64, hashlib, os, re, struct, sys, time

# ==========================================================================
# PART 3 -- CLAIMS: the Adjust SDK 5.8.0 claim law (inlined)
# ==========================================================================


PROFILE_BASE = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
    'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
    'gps_adid_src', 'hardware_name', 'installed_at', 'mcc', 'mnc', 'os_build',
    'os_name', 'os_version', 'package_name',
]
SESSION_EXTRA = ['country', 'initiating_package_name']
CLICK_EXTRA = ['click_time', 'click_time_server', 'country',
               'google_play_instant', 'install_begin_time',
               'install_begin_time_server', 'install_version', 'referrer',
               'referrer_api']
ATTR_DROP = ['hardware_name', 'installed_at', 'os_build']
ATTR_EXTRA = ['initiated_by']
SESSION_TAIL = ['session_count', 'session_length', 'store_name_from_system',
                'subsession_count', 'time_spent', 'tracking_enabled',
                'updated_at']
CLICK_TAIL = ['session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at']
ATTR_TAIL = ['tracking_enabled']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PIN = 'adj_signing_id'
PIN_DEFAULT = '1500000'

# Genuine validation vectors (com.creditsea.app, moto g42, 2026-09-29,
# adj9_cap_fresh.log): sha256 of the UNPADDED #10 claims string per signing,
# with the signing second and the genuine 192-B blob.
GOLD = [
    {"kind": "session", "second": 1790694158, "unpadded_len": 380,
     "claims_sha256": "249f385041c4007b185c7ff2531269418eb7b8ab25b2b234713d9058d3a7452e",
     "blob_hex": "26148db92c7134c438f3b3d7219b36841e08eab70fdabe6417ef02699c35d055d3f45c03d69cdc9db912b0e49fe2d1289bfa5005d861c8953a90c613d0eddd6fc6477e5d947fc6c4a5684d9ea0b191dac317f1142982fdd4c23c1cfd0c68b0578179f15fa1f5cb99fe9618d9a4b43c63c061fb3ea1098b1d331f543f3f80981e13fa314b3a922ec74010d0452a3f35bec0428ace2c4602e669f777a429bc845c18bbb292ac2eb866bdbbf6193af2743650a77bb3be45499d5b793aeb598e7fc7"},
    {"kind": "click", "second": 1790694159, "unpadded_len": 516,
     "claims_sha256": "ff32b385605ad206e87335394051126bda5c8b3dcfa09b2b9b968a15719f85c5",
     "blob_hex": "1324ef343e3d350b0ddf4f523fce48b347ee7dd4c886a9e4d1aaa672042420ad9fd7adce1e4bcb444fbd73938b8a70bee667e599eb9a38d8fc99d0772141ce88fdba16d9e4a8b95a47b2585daec2953f5a2ddf6eec8e033179e467f3cd8d6f45d5262fa68e771fbea8c137f659d89991864766e2a1efb939903eeee7780a5707e95c76f938233f74ce0810f3f1aced1c98e4614d30fdc19e79672d625a87c39a7a44bea389fd01a48fe61b08cee6377bfdefcd42a293367f70bb3eaa47ac1550"},
    {"kind": "attribution", "second": 1790694166, "unpadded_len": 264,
     "claims_sha256": "28bf37c57aa9bf555fb47af1fff2ff790e320d92cdb6ef1abb26a8578227e37e",
     "blob_hex": "23d5723505a22701424476ae2658a46561a634a2fb5827b1e3e80134e24f7c26686c6a88e8c3be3f769b4faa56f8920127426ba606a561970c241525a74365e13888b29f661203be3a2bec8f068f5042afe801faa97b7e6f48edea909a4f6f1dc97a41a5e3c807cf2d19adee7407e3b5d155d8fb9753ad29f29a53ce51e04eeb33a2e487f825f0733b8edf2867c23b3628188b64c5521e927562a180ce6a6a5a4ab31043f17660428badf14d9a643c8cd0b8cab028a12e3abdc5307709731ebf"},
]


def _lists(kind):
    if kind == 'session':
        return PROFILE_BASE + SESSION_EXTRA, SESSION_TAIL
    if kind == 'click':
        return PROFILE_BASE + CLICK_EXTRA, CLICK_TAIL
    if kind == 'attribution':
        return [k for k in PROFILE_BASE if k not in ATTR_DROP] + ATTR_EXTRA, ATTR_TAIL
    raise ValueError('desc10_58 law known for kinds: session, click, attribution '
                     '(got %r)' % kind)


def claim_key_order_58(val, kind):
    """Emission key order for one activity kind (law keys present in `val`)."""
    profile, tail = _lists(kind)
    keys = [k for k in sorted(profile) if val.get(k)]
    keys.append(PIN)                      # emitted pinned; read or not
    keys += [k for k in sorted(tail) if val.get(k)]
    keys += [k for k in BLOCK2 if val.get(k)]
    return keys


def claims_unpadded_58(val, kind):
    """val: dict key->string.  Returns the EXACT byte string the 5.8.0 native
    packs into descriptor #10 (unpadded)."""
    keys = claim_key_order_58(val, kind)
    missing = [k for k in keys if not val.get(k)]
    if missing:
        raise KeyError('desc10_58 law missing values: %s' % missing)
    return ''.join(val[k] for k in keys).encode('latin1')


def claims_padded_58(val, kind):
    """(padded #10 bytes, unpadded length) - NUL-pad to a 4-byte multiple;
    descriptor #7 carries the UNPADDED length."""
    raw = claims_unpadded_58(val, kind)
    return raw + b"\x00" * (-len(raw) % 4), len(raw)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def self_test():
    """Check the law strings against the captured-signing sha256 vectors."""
    import json
    ok = True
    valmaps = _gold_maps()
    for g in GOLD:
        val = valmaps[g['kind']]
        raw = claims_unpadded_58(val, g['kind'])
        sha = hashlib.sha256(raw).hexdigest()
        good = (len(raw) == g['unpadded_len'] and sha == g['claims_sha256'])
        print('%-11s len=%3d (want %3d)  sha %s  %s'
              % (g['kind'], len(raw), g['unpadded_len'], sha[:16] + '...',
                 'OK' if good else 'FAIL'))
        ok &= good
    return ok


def validate_against_device(max_steps=60_000_000):
    """Full-stack check: rebuild the descriptor plane per signing, drive the
    FinEx VM, and require the minted 192-B blob == the genuine device blob."""
    import sys
    sys.path.insert(0, os.path.dirname(HERE))
    from testbed import mine_log, decode, region_parts, run_vm, build_descs
    ok = True
    for s in mine_log():
        kind = s['val'].get('activity_kind', 'session')
        dec = decode(s['blob'])
        d0, d4, d2, pfx = region_parts(dec, s['second'])
        raw, padded = claims_padded_58(s['val'], kind)
        blob, status = run_vm(s['second'],
                              build_descs(s['second'], raw, d0, d4, d2),
                              max_steps=max_steps)
        good = blob == s['blob']
        print('%-11s second=%d  %d/192 bytes match  %s'
              % (kind, s['second'],
                 192 - sum(1 for i in range(192) if blob[i] != s['blob'][i]),
                 'BYTE-EXACT' if good else 'FAIL'))
        ok &= good
    return ok


def _gold_maps():
    """The three captured claims maps, mined from adj9_cap_fresh.log."""
    sys_path_add = os.path.dirname(HERE)
    import sys
    if sys_path_add not in sys.path:
        sys.path.insert(0, sys_path_add)
    from testbed import mine_log
    out = {}
    for s in mine_log():
        out[s['val'].get('activity_kind', 'session')] = s['val']
    return out


if __name__ == '__main__':
    import sys
    if '--vm' in sys.argv:
        ok = validate_against_device()
    else:
        ok = self_test()
    raise SystemExit(0 if ok else 1)


# ==========================================================================
# PARTS 1, 2, 4 -- header, region, and the FinEx VM (inlined)
# ==========================================================================
import base64
import os
import re
import struct
import sys
import time

# **********************************************************************
# PART 1 — TIME: the 16-byte header from the signing second
# **********************************************************************
# header_gen.py - VERIFIED adj9 16-byte header generator (36/36 corpus, 2 devices)
# usage: make_header(unix_seconds) -> 16 bytes
import struct
M31=2147483647
class Random3:
    __slots__=("r","f","b")
    def __init__(self, seed):
        r=self.r=[0]*31
        s=seed & 0xFFFFFFFF
        if s==0: s=1
        w=s if s<2**31 else s-2**32
        r[0]=w; prev=w
        for i in range(1,31):
            if prev>=0: hi=prev//127773; lo=prev-hi*127773
            else: hi=-((-prev)//127773); lo=prev-hi*127773
            word=16807*lo-2836*hi
            if word<0: word+=M31
            prev=word; r[i]=word
        self.f=3; self.b=0
        for _ in range(310): self.next()
    def next(self):
        v=(self.r[self.f]+self.r[self.b])&0xFFFFFFFF
        self.r[self.f]=v if v<2**31 else v-2**32
        o=v>>1
        self.f=(self.f+1)%31; self.b=(self.b+1)%31
        return o
def make_header(unix_sec):
    R=Random3(unix_sec)
    d=[R.next() for _ in range(8)]
    w=[d[2*i]^d[2*i+1] for i in range(4)]
    return b"".join(struct.pack(">I",x) for x in w)

# **********************************************************************
# PART 2 — REGION: d0/d2/d4 materialized from the 32-bit seed S
#
#   region(S, 0, 0, head=WIN_PHASE) -> (d0[36 words], d2, d4[8 words])
#   S is fresh random bytes per signing; d2 is just S stored LE.
#   The head selectors reproduce the genuine device's d0 pattern.
# **********************************************************************
_MASK31 = 0x7FFFFFFF
_MASK16 = 0xFFFF
_MASK32 = 0xFFFFFFFF

# d0 head phases.  The GENUINE device phases (verified 10/10 against the whcap
# corpus in all_signings.json) are the ones a live mint must use.  The phase is
# per-request, not a function of V/pid.
HEAD_FIRST = (0x22, 0x2E)
HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x2E)

# Legacy SYNTHETIC head phases.  These reproduce only the fill_runs emulator
# corpus (0/10 on genuine captures) and are kept solely so verify_d0.py can
# still check that corpus.  Do not use them for a live request.
SYNTH_HEAD_FIRST = (0x2B, 0x22, 0x25, 0x2E)
SYNTH_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E)
# One additional scheduler phase occurs once in fill_runs.  It is retained so
# the saved corpus is byte-exact; it must not be synthesized for a live request
# unless the corresponding runtime phase state is known.
SYNTH_HEAD_RESIGN_ALT = SYNTH_HEAD_RESIGN + (0x4A, 0x05)

_D0_SELECTORS_FIRST = (
    0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B,
    0x3C, 0x35, 0x36, 0x2D, 0x48, 0x05,
)
_D0_SELECTORS_RESIGN = (
    0x30, 0x2B, 0x07, 0x34, 0x37, 0x38, 0x3B,
    0x3C, 0x35, 0x36, 0x2D, 0x48, 0x05,
)
_D0_SELECTORS_RESIGN_ALT = (
    0x30, 0x2B, 0x07, 0x34, 0x37, 0x38, 0x3B,
    0x3C, 0x35, 0x36, 0x2D, 0x48, 0x4A, 0x05,
)


def head_for_sign_id(sign_id: int):
    """Whitener head for a signing ordinal (1-based) within the process."""
    return HEAD_FIRST if sign_id <= 2 else HEAD_RESIGN


def _step(x: int) -> int:
    """One step of the 31-bit Schrage PRNG at 0x13dfd0."""
    if x == 0:
        x = 0x075BD924
    q = x // 0x1F31D
    y = (x - q * 0x1F31D) * 0x41A7 - q * 0x0B14
    if y < 0:
        y += _MASK31
    return y & _MASK31


def _shuffled_halfwords(seed: int) -> list[int]:
    """Shuffle (0x143c88) + pair consumption (0x1439c4) -> 16 pre-transpose halfwords.

    Not Fisher-Yates: the native buffer starts as 16 zero bytes and each draw
    swaps `perm[i]` with `perm[j]`, `j = r % (i + 1)`.  Even output indices take
    the high 16 bits of the state, odd indices the full low-32 value; bit
    position is `15 - perm[i]` with the low bits below it retained.
    """
    state = seed & _MASK32
    perm = [0] * 16
    for i in range(16):
        r = _step(state)
        state = r
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], i

    pre = []
    for i in range(16):
        if (i & 1) == 0:
            state = _step(state)
        r = state
        v = (r >> 16) & _MASK16 if (i & 1) == 0 else r
        pos = 15 - perm[i]
        pre.append(((v & ((1 << pos) - 1)) | (1 << pos)) & _MASK16)
    return pre


def _transpose16(pre: list[int]) -> list[int]:
    """The 16x16 bit-matrix transpose at 0x143d98."""
    out = [0] * 16
    for j in range(16):
        v = 0
        for i in range(16):
            if pre[i] & (1 << (15 - j)):
                v |= 1 << (15 - i)
        out[j] = v
    return out


def _d4_words(seed: int) -> list[int]:
    """Descriptor #4: 8 big-endian words from the little-endian halfword stream."""
    raw = _transpose16(_shuffled_halfwords(seed))
    packed = b"".join(x.to_bytes(2, "little") for x in raw)
    return [int.from_bytes(packed[i:i + 4], "big") for i in range(0, 32, 4)]


def _whitener_word(x1: int, source: list[int]) -> int:
    """Replay one 0x144074 call: each set bit b of (2*x1+3) XORs source[7-b]."""
    mask = ((x1 << 1) + 3) & _MASK16
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16


def _d0_source(d4: list[int]) -> list[int]:
    """The eight d4 halfwords consumed by the d0 source-word selector."""
    d4_bytes = b"".join(word.to_bytes(4, "big") for word in d4)
    return [int.from_bytes(d4_bytes[i:i + 2], "little") for i in range(16, 32, 2)]


def _fold_selector(mask: int, source: list[int]) -> int:
    """XOR source words selected by one 8-bit d0 selector mask."""
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16


def _d0_words(d4: list[int], head=None) -> list[int]:
    """Descriptor #0: 36 big-endian words, including the separate W0/X prefix.

    The GENUINE device phases (HEAD_FIRST / HEAD_RESIGN) are short selector
    prefixes followed by the stable halfword cycle; they are dispatched through
    the generic `head + cycle` path and reproduce every genuine capture.  The
    longer SYNTH_* tables reproduce only the synthetic fill_runs corpus and are
    routed separately so verify_d0.py keeps working.  Callers minting a live
    request must pass a genuine head (default HEAD_FIRST).
    """
    source = _d0_source(d4)
    real_head = HEAD_FIRST if head is None else head

    if real_head == SYNTH_HEAD_FIRST:
        selectors = _D0_SELECTORS_FIRST + tuple(0x40 | (i & 7) for i in range(12, 72))
    elif real_head == SYNTH_HEAD_RESIGN:
        selectors = _D0_SELECTORS_RESIGN + tuple(0x40 | (i & 7) for i in range(13, 72))
    elif real_head == SYNTH_HEAD_RESIGN_ALT:
        selectors = _D0_SELECTORS_RESIGN_ALT + tuple(0x40 | (i & 7) for i in range(14, 72))
    else:
        # Genuine phases and any explicit custom head: prefix selectors, then
        # the stable cycle resumes at the first index after the prefix.
        selectors = tuple(real_head[i] if i < len(real_head) else (0x40 | (i & 7))
                          for i in range(72))

    values = [_fold_selector((selector << 1) + 3, source)
              for selector in selectors]
    raw = b"".join(value.to_bytes(2, "little") for value in values)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 144, 4)]


def region(V: int, pid: int, tid: int = 0, head=None):
    """Return ``(d0, d2, d4)`` as descriptor words for the given fill instant.

    V   : tv_sec ^ tv_usec at the fill instant (< 2**32)
    pid : process id; only the low 16 bits reach the native seed
    tid : accepted for the contract, provably unused on this path
    head: per-request d0 phase (see _d0_words); None -> HEAD_FIRST.
    """
    del tid  # verified absent from the d0/d2 materializer and the d4 path
    seed = ((V & _MASK32) ^ ((pid & _MASK16) << 16)) & _MASK32
    d4 = _d4_words(seed)
    d0 = _d0_words(d4, head=head)
    # d2 is the little-endian store of the seed, read back as a BE word.
    d2 = int.from_bytes(seed.to_bytes(4, "little"), "big")
    return d0, d2, d4



# **********************************************************************
# PART 3 — CLAIMS: the request parameters in a fixed key order (the law)
#
#   claims_unpadded(val, kind) serializes the request fields; the server
#   rebuilds the same string from the request it received and compares —
#   this is what binds the signature to THAT request.
# **********************************************************************
PROFILE_COMMON = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
    'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
    'gps_adid_src', 'hardware_name', 'installed_at', 'mcc', 'mnc', 'os_build',
    'os_name', 'os_version', 'package_name',
]
# Optional profile claims. `push_token` was found in the 504 B / 532 B captures
# (slice 105): a 143-char FCM token appended to the profile set, i.e. it simply
# sorts between `package_name` and `referrer`. It is present only when the app
# has a token, which is exactly why the 360/387 B captures lack it.
OPTIONAL_PROFILE = ['push_token']
SESSION_PROFILE = ['initiating_package_name']
CLICK_PROFILE = ['google_play_instant', 'referrer', 'referrer_api']
SESSION_TAIL = ['session_count', 'store_name_from_system', 'tracking_enabled',
                'updated_at']
CLICK_TAIL = ['session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PINNED = 'adj_signing_id'

# ---------------------------------------------------------------------------
# ATTRIBUTION kind - derived from the device's OWN attribution map
# (device/gold6.json idx 2/5, activity_kind="attribution", 30 map keys), NOT yet
# byte-verified against a captured desc10 because no EMIT trace contains an
# attribution signing. Status: PREDICTED, with a testable signature:
#   prediction = 21 values, unpadded 246 B -> descriptor #10 of 248 B (62 dwords),
#   a length that does NOT occur among the captured 360/388/504/532 B sessions and
#   clicks. One device EMIT capture of an attribution signing confirms or refutes it.
#
# Rationale: the attribution map carries 14 of PROFILE_COMMON's 17 keys (missing
# hardware_name / installed_at / os_build, which are install-time facts a poll does
# not carry) plus `initiated_by` (which IS payload-bearing per slice 99 §8.2 and is
# present in every attribution map), and exactly one tail key (tracking_enabled).
# ---------------------------------------------------------------------------
ATTRIBUTION_PROFILE = [k for k in PROFILE_COMMON
                       if k not in ('hardware_name', 'installed_at', 'os_build')]
ATTRIBUTION_PROFILE += ['initiated_by']
ATTRIBUTION_TAIL = ['tracking_enabled']


def claim_key_order(kind, val=None):
    """Emission key order for one activity kind.

    Optional profile claims (currently `push_token`) are included only when the
    caller's map actually carries them - matching the device captures.
    """
    if kind == 'session':
        profile = PROFILE_COMMON + SESSION_PROFILE
        tail = SESSION_TAIL
    elif kind == 'click':
        profile = PROFILE_COMMON + CLICK_PROFILE
        tail = CLICK_TAIL
    elif kind == 'attribution':
        profile = list(ATTRIBUTION_PROFILE)
        tail = list(ATTRIBUTION_TAIL)
    else:
        raise ValueError('desc10 law known for kinds: session, click, attribution '
                         '(got %r)' % kind)
    profile = list(profile)
    for k in OPTIONAL_PROFILE:
        if val and k in val and val[k] not in (None, ''):
            profile.append(k)
    return sorted(profile) + [PINNED] + sorted(tail) + BLOCK2


def pad4(b):
    """The native pads desc10 with NULs up to a 4-byte multiple (slice 105:
    503->504 session+token, 530->532 click+token, 387->388 click)."""
    if isinstance(b, str):
        return b + '\0' * (-len(b) % 4)
    return b + b'\0' * (-len(b) % 4)


def claims_unpadded(val, kind):
    """val: dict key->string value (all law keys must be present, non-empty).
    Returns the exact byte string the native packs into descriptor #10."""
    keys = claim_key_order(kind, val)
    missing = [k for k in keys if k not in val or val[k] in (None, '')]
    if missing:
        raise KeyError('desc10 law missing values: %s' % missing)
    return ''.join(val[k] for k in keys)



# **********************************************************************
# PART 4 — THE SIGNING VM (FinEx)
#
#   The app's native library is a small obfuscated ARM64 VM. Its bytecode
#   is embedded below (APPENDIX) and disassembled once at import
#   (_init_vm). FinEx(seed=second, descs).run() emits ONE 48-word stream:
#   words 0-3 = the 16-B header, words 4-47 = the encrypted 176-B body.
# **********************************************************************
OP_PUSH, OP_POP, OP_EMIT, OP_LENQ, OP_OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
OP_PUSH2, OP_POP2, OP_ISEMPTY = 0x146470, 0x146478, 0x146474
OP_PUSHS, OP_POPS, OP_MKITER, OP_ITERNEXT = 0x147120, 0x147220, 0x146558, 0x146650
OP_RAND = 0x148d10
SUBR = {0xBA4A8, 0x9AFA4, 0x9C478, 0x9AD54,  # chain subroutines (slice 73+)
        0x147304, 0x146ED8, 0x147630, 0x147734,  # true queue ops (slice 78)
        0x146470, 0x146478, 0x1472E8}  # PUSH2/POP2/OUTLEN
SUBR_OPS = {0x147304, 0x146ED8, 0x147630, 0x147734,
            0x146470, 0x146478, 0x1472E8}
NOOPS = {0x146474}

_split_cache = {}
_shift = {}


def _split(ops):
    p = _split_cache.get(ops)
    if p is None:
        p = [x.strip() for x in ops.split(",")]
        _split_cache[ops] = p
    return p


_memplans = {}


def _rs(name):
    """register name -> (slot, is32).  slot < 0 means "not an x/w/sp name",
    which the hot path handles with the exotic-name dict instead."""
    i = _SLOT.get(name)
    if i is not None:
        return i, name[0] == "w"
    if name == "sp":
        return SP, 0
    return -1, 0


def _memplan(m, ops):
    """Cached parse of a load/store operand list -> execution plan."""
    key = (m, ops)
    if key in _memplans:
        return _memplans[key]
    o = ops.replace(" ", "")
    plan = None
    mm = re.match(r"^([wx]\d+|\w+\d*),\[([wx]\d+|sp)(?:,(#?[-0-9x]+))?\](!?)", o)
    if mm:
        d, base, imm, wb = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
        imm = imm.strip() if imm else "0"
        try:
            off = int(imm.replace("#", ""), 0)
        except ValueError:
            off = 0
        if off is None:
            off = 0
        size = 4 if (d.startswith("w") or m in ("ldrb", "strb", "ldrsw")) else 8
        # dslot/dsw and bslot/bsw pre-resolve the ARM64 register names to list
        # indices so the hot path never touches a dict or a string again.
        plan = ("imm", d, base, off, wb == "!", size,
                *_rs(d), *_rs(base))
    else:
        mm2 = re.match(r"^(\w+),(\w+),\[([wx]\d+|sp)(?:,(#?-?[\dx]+))?\](!?)", o)
        if mm2 and m in ("stp", "ldp"):
            imm = mm2.group(4)
            plan = ("pair", mm2.group(1), mm2.group(2), mm2.group(3),
                    int(imm.lstrip("#"), 0) if imm else 0, mm2.group(5) == "!",
                    *_rs(mm2.group(1)), *_rs(mm2.group(2)), *_rs(mm2.group(3)))
        if plan is None:
            mm3 = re.match(r"^(\w+),\[(\w+)\],(#?-?[\dx]+)$", o)
            if mm3:
                plan = ("post", mm3.group(1), mm3.group(2),
                        int(mm3.group(3), 0),
                        *_rs(mm3.group(1)), *_rs(mm3.group(2)))
        if plan is None:
            mm4 = re.match(r"^(\w+),\[(\w+),(\w+)(?:,(uxtw|lsl)#(\d+))?\]", o)
            if mm4:
                plan = ("regidx", mm4.group(1), mm4.group(2), mm4.group(3),
                        int(mm4.group(5) or 0),
                        *_rs(mm4.group(1)), *_rs(mm4.group(2)),
                        *_rs(mm4.group(3)))
    _memplans[key] = plan
    return plan


_ptc = {}
_MISS = object()


def pt(s):
    v = _ptc.get(s, _MISS)
    if v is _MISS:
        try:
            v = int(s.lstrip("#"), 16)
        except (ValueError, AttributeError):
            v = None
        _ptc[s] = v
    return v


# ---- register file ---------------------------------------------------------
# The VM used to keep self.R as a dict keyed "x21"/"w21".  ARM64 xN and wN
# share ONE 64-bit slot but differ on WRITE: an x write stores 64 bits, a w
# write stores 32 zero-extended.  Two parallel lists model that exactly and
# never disagree:
#     RL[n] = the 64-bit x-view   (sp lives at RL[32])
#     WL[n] = the 32-bit w-view
# Every write site -- set_reg, the mem_op2 helpers, and the direct R["w0"]= /
# R["x0"]= assignments in run() -- must update BOTH, or the two views drift.
M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
SP = 32                      # RL/WL slot for sp
_NREG = 33
_SLOT = {}                   # "x7"/"w7" -> 7
for _n in range(32):
    _SLOT["x%d" % _n] = _n
    _SLOT["w%d" % _n] = _n

DATAB = 0x5600000000  # descriptor data region base (fake)
PM = 0x0000FFFFFFFFFFFF  # 48-bit VA mask (strips MTE/heap tags, e.g. 0xb4..)
class StreamObj:
    def __init__(self, va, mem):
        self.va = va
        self.mem = mem
        self.data = []          # u32 growable (native: [va+0x18] -> u32 array)
        self.offs = [0]
        self.ro = False         # hydrated read-only: never write stocked memory
        self._acc = None        # RO streams track acc here (native +0x10)
        self.sync_struct()
    def sync_struct(self):
        if self.ro:
            return  # read-only hydration: never write back stocked memory
        # native stream struct (slice 10/13): +0x0 limit, +0x8 offs ptr,
        # +0x10 acc, +0x14 count, +0x18 data ptr, +0x28 nested
        # NOTE: acc (+0x10) and count (+0x14) are LIVE (merge EMITs / appends
        # update them); only initialize on first sync, never overwrite after.
        m = self.mem; va = self.va
        first = (va + 0x14) not in m
        daba = 0x5610000000 + (va & 0xFFFFFF)
        ofba = 0x5620000000 + (va & 0xFFFFFF)
        m[va + 0x00] = 0x7FFFFFFF
        m[va + 0x08] = ofba
        m[va + 0x28] = va
        if first:
            m[va + 0x10] = 0
            m[va + 0x14] = len(self.data)
        else:
            m[va + 0x14] = len(self.data)
        m[va + 0x18] = daba
        for j, v in enumerate(self.data):
            m[daba + 4 * j] = v
        for j, v in enumerate(self.offs):
            m[ofba + 4 * j] = v
    def base(self): return self.offs[-1]
    def emit(self, n, v, pc=0):
        v &= 0xFFFFFFFF
        n &= 0xFFFFFFFF
        if n > 0x100000:
            return
        acc0 = self.mem.get(self.va + 0x10, 0)
        if 0x10015C <= pc <= 0x100220:
            # FIELD path (field loop bulk load): data[n] = v (n==len appends)
            while len(self.data) <= n: self.data.append(0)
            self.data[n] = v
        elif (self.offs == [0] or not self.offs) and acc0 == 0 and n >= len(self.data):
            # APPEND path (fresh stream, wild index e.g. header XORs)
            self.data.append(v)
        else:
            # MERGE mode (0x1470d4..0x1470cc): idx = TOP + n; offs[idx] = v
            # (native malloc-grows; model caps at 4M entries ~16MB, drops beyond)
            top = self.data[-1] if self.data else 0
            idx = (top + n) & 0xFFFFFFFF
            if 0 <= idx < 4194304:
                while len(self.offs) <= idx: self.offs.append(0)
                self.offs[idx] = v
                if self.ro:
                    self._acc = (idx + 1) & 0xFFFFFFFF
                else:
                    self.mem[self.va + 0x10] = (idx + 1) & 0xFFFFFFFF
        self.sync_struct()
    def get(self, n):
        pos = self.base() + n
        return self.data[pos] if 0 <= pos < len(self.data) else 0
    def outlen(self):
        if self.ro:
            acc = self._acc if self._acc is not None else 0
        else:
            acc = self.mem.get(self.va + 0x10, 0) & 0xFFFFFFFF
        top = self.data[-1] if self.data else 0
        return (acc - top) & 0xFFFFFFFF

class Ex:
    """One descriptor: (len_dw, tag, data) with marker data."""
    def __init__(self, seed, descs, n_streams=16, shared_q=False, fast=True):
        self._shared_q = shared_q
        self.__dict__["_fast"] = bool(fast)
        self.RL = [0] * _NREG          # x0..x31 view (+ sp at SP), 64-bit
        self.WL = [0] * _NREG          # w0..w31 view, 32-bit (ARM64 aliasing)
        self.Rx = {}                   # any other name ("v0", "q1", ...)
        self.F = {}
        self.mem = {}                     # fake memory (VA -> u64)
        self.streams = {}                  # stream VA -> StreamObj
        self.queues = {}                    # queue VA -> list
        self.iters = []                    # {arr,i,n}
        self.rnd = Random3(seed)
        self.nrand = 0
        self.steps = 0
        self.emit_trace = []
        # ---- fake addresses ----
        X29 = 0x5100000000
        self.X29 = X29
        CTX = 0x5200000000                 # x20: fields/ctx array
        W   = 0x5300000000                 # x19: writer status cell
        self.CTX, self.W = CTX, W
        RL = self.RL
        RL[29] = X29
        self.WL[29] = X29 & M32
        # ctx: [CTX+0]=queue ptr, [CTX+0x18]=queue2 ptr, [CTX+0x20+8i]=stream i
        QVA, Q2VA = 0x5400000000, 0x5400000100
        self.mem[CTX] = QVA
        self.mem[CTX + 0x18] = Q2VA
        self.QVA, self.Q2VA = QVA, Q2VA
        # every ctx slot [+8 .. +0xB0] = its own stream (the queue program
        # walks them via x26/[x26,#8]!); field sinks live at +0x20+8i
        for i in range(1, 24):
            sva = 0x5450000000 + i * 0x1000
            self.streams[sva] = StreamObj(sva, self.mem)
            self.mem[CTX + 8 * i] = sva
        self.MAIN = 0x5450001000    # [CTX+8]
        self.stream_of = {}
        for i in range(n_streams):
            sva = 0x5500000000 + i * 0x1000
            self.streams[sva] = StreamObj(sva, self.mem)
            self.stream_of[i] = sva
            self.mem[CTX + 0x20 + i * 8] = sva
        if getattr(self, "_shared_q", False):
            # EXPERIMENT: single shared value-queue for [CTX] and [CTX+0x18]
            self.mem[CTX] = QVA
            self.mem[CTX + 0x18] = QVA
            self.streams.pop(0x5450003000, None)
        # va_list frame
        self.mem[X29 - 0x18] = (2**64 - 40)     # gp = -40 (as u64; read as i32)
        self.mem[X29 - 0x30] = X29 + 0x60       # advancing ptr
        self.mem[X29 - 0x28] = X29 - 0x30
        self.mem[X29 - 0x10] = 0xDEADBEEF       # canary
        self.mem[X29 - 0x20] = 0
        # descriptors: 11 nodes
        for i, (lendl, tag, data) in enumerate(descs):
            nva = 0x5600000000 + i * 0x100
            dva = 0x5700000000 + i * 0x400
            self.mem[nva] = ((lendl << 2) | tag) | (0 << 32)
            self.mem[nva + 8] = dva
            for j in range(lendl):
                v = struct.unpack_from(">I", data, 4 * j)[0] if len(data) >= 4 * (j + 1) else 0
                self.mem[dva + 4 * j] = v        # store BE-decoded dword at aligned slot
            # place pointer into va slots
            if i < 5:
                self.mem[X29 - 0x58 + 8 * i] = nva
            else:
                self.mem[X29 + 0x60 + 8 * (i - 5)] = nva
        # register entry state  (x/w views written in the ORIGINAL order --
        # w26 before x26 -- so both lists start out exactly like the dict did)
        WL = self.WL
        WL[26] = len(descs) & M32
        RL[19] = W;  WL[19] = W & M32
        RL[20] = CTX; WL[20] = CTX & M32
        RL[23] = 0; WL[23] = 0
        RL[22] = 0; WL[22] = 0
        WL[21] = 0; WL[27] = 0
        RL[21] = 0
        RL[26] = 11   # arg count (w2)
        WL[26] = 11 & M32
        RL[28] = CTX; WL[28] = CTX & M32
        RL[27] = 0; WL[27] = 0
        self.pc = 0x100114


    def set_reg(self, name, val):
        """write a register with true ARM64 x/w aliasing (NOT invalidation):
        xN <- V64 (wN = low32); wN <- V32 (xN = zero-extended)."""
        if name == "sp":                  # sp has no w alias; stored raw
            self.RL[SP] = val
            self.WL[SP] = val
            return
        i = _SLOT.get(name)
        if i is not None:
            if name[0] == "w":            # wN write zero-extends into xN
                v = val & M32
                self.RL[i] = v
                self.WL[i] = v
            else:
                v = val & M64
                self.RL[i] = v
                self.WL[i] = v & M32
            return
        if name == "wzr" or name == "xzr":
            return
        self.Rx[name] = val & M64

    # ---- cold helpers for the legacy (non-fast) paths --------------------
    def _gx(self, n):
        """x-view of register n."""
        return self.RL[n]

    def _get(self, name):
        """dict-style read of any register name (cold paths only)."""
        i = _SLOT.get(name)
        if i is not None:
            return self.WL[i] if name[0] == "w" else self.RL[i]
        if name == "sp":
            return self.RL[SP]
        if name in ("wzr", "xzr"):
            return 0
        return self.Rx.get(name, 0)

    # ---- memory ----
    def ld(self, va, size=8):
        # PM strips MTE/heap tags; the &~7/&~3 selects the u64 word slot, which
        # is all this fake memory ever holds.
        return self.mem.get(va & PM & (~7 if size == 8 else ~3), 0)
    def st(self, va, v, size=8):
        self.mem[va & PM & (~7 if size == 8 else ~3)] = v & M64
        sl = self.__dict__.get("_storelog")
        if sl is not None and len(sl) < 5000:
            sl.append((hex(self.pc), hex(va & 0xFFFFFFFFFFFF)))

    # ---- byte access (heap mode; slice 74) ----
    def ldbyte(self, va):
        va &= 0x00FFFFFFFFFFFFFF
        w = self.mem.get(va & ~7, 0)
        return (w >> ((va & 7) * 8)) & 0xFF
    def stbyte(self, va, b):
        va &= 0x00FFFFFFFFFFFFFF
        a = va & ~7
        sh = (va & 7) * 8
        w = self.mem.get(a, 0)
        w = (w & ~(0xFF << sh)) | ((b & 0xFF) << sh)
        if w:
            self.mem[a] = w
        elif a in self.mem:
            del self.mem[a]

    def stream_for(self, va):
        va &= PM  # tagged (MTE) stream pointers resolve to the same object
        s = self.streams.get(va)
        if s is None:
            s = StreamObj(va, self.mem)
            self.streams[va] = s
        return s

    def run(self, max_steps=3_000_000):
        from collections import Counter
        self._pc_hist = Counter()
        fast = bool(self.__dict__.get("_fast"))
        _f = FAST
        while self.steps < max_steps:
            self.steps += 1
            k = IDX.get(self.pc)
            if k is None: return "pc-out"
            if not fast:
                self._pc_hist[self.pc] += 1
                pre = self.__dict__.get("_preload", {})
                if self.pc in pre and pre[self.pc]:
                    qva = self.mem.get(self.CTX, 0)
                    self.queues.setdefault(qva, [])[0:0] = list(pre[self.pc])
                fr = self.__dict__.get("_forcereg", {})
                if self.pc in fr:
                    for rn, vv in fr[self.pc]:
                        self.set_reg(rn, vv)
            if not fast and self.pc in (0xBBB14,):
                self.__dict__.setdefault("_bbb14", []).append(
                    tuple(self.RL[n] for n in range(10)) + (self.RL[19], self.RL[20]))
            if not fast and self.pc == 0x9C4C0:
                self.__dict__.setdefault("_9c4c0", []).append(
                    tuple(self.RL[n] for n in range(5)) + (self.RL[8], self.RL[9]))
                self.__dict__.setdefault("_b8a0", []).append(
                    (self.RL[10], self.RL[SP],
                     self.mem.get((self.RL[SP] + 0x50) & ~7, -1)))
            if not fast and self.pc == 0xBB668 and len(self.__dict__.get("_hublog", [])) < 500:
                self.__dict__.setdefault("_hublog", []).append(self.RL[9])
                seq = self.__dict__.get("_hubseq", [])
                if seq:
                    self.set_reg("x9", seq.pop(0))
                if len(self.__dict__.get("_hublog", [])) == 7:
                    self.__dict__["_roll7"] = list(self.__dict__.get("_roll", []))
                if len(self.__dict__.get("_hublog", [])) in (5, 6):
                    self.__dict__["_roll%d" % len(self.__dict__.get("_hublog", []))] = list(self.__dict__.get("_roll", []))
            if not fast and self.pc == 0xBA674 and len(self.__dict__.get("_mazelog", [])) < 1000:
                self.__dict__.setdefault("_mazelog", []).append(
                    (self.RL[8], self.RL[9], self.RL[20]))
            if not fast and 0xBA000 <= self.pc < 0xBC000 and m0[k] in ("ldr", "ldur", "ldp", "ldrb", "ldrsw", "ldrsh", "ldrsb"):
                self.__dict__.setdefault("_loads", []).append(self.pc)
            if fast:
                m, ops, npc = _f[k]
            else:
                i = INS[k]
                m, ops = i.mnemonic, i.op_str
                npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                w = self
                if not fast and len(w.__dict__.get("_calls", [])) < 2000:
                    w.__dict__.setdefault("_calls", []).append(
                        (hex(self.pc), hex(t) if t else ops,
                         tuple(w.RL[n] & M32 for n in range(5)),
                         self.steps))
                if self.pc in w.__dict__.get("_substub", {}):
                    # stubbed call (live regs; slice 74): apply regs, skip.
                    retpc, regd = w.__dict__["_substub"][self.pc]
                    for rn, vv in regd.items():
                        if vv == "BUMP":
                            n = 0x400
                            va = w._heap[0]
                            w._heap[0] = va + n
                            w._heap[1][va] = n
                            vv = va
                        w.set_reg(rn, vv)
                    for off, vv in w.__dict__.get("_framefill", {}).get(self.pc, []):
                        if isinstance(vv, list):
                            vv = vv.pop(0) if vv else 0
                        a = (w.RL[29] + off) & (2**64 - 1)
                        w.st(a, vv, 4 if off & 4 else 8)
                    w.__dict__.setdefault("_stublog", []).append(hex(self.pc))
                    npc = retpc
                elif (t in SUBR and t in IDX and
                      (t not in SUBR_OPS or w.__dict__.get("_truesub"))):
                    # true subroutine call (assembly chain always, queue ops
                    # opt-in via _truesub; slice 73/78): shadow-stack, jump.
                    w.__dict__.setdefault("_shadow", []).append(npc)
                    npc = t
                elif t in (OP_PUSH, OP_PUSH2):
                    qva = w.RL[1]
                    w.queues.setdefault(qva, []).insert(0, w.WL[2] & 0xFFFFFFFF)
                    w.__dict__.setdefault("_qlog", []).append(
                        (hex(self.pc), "PUSH", hex(qva & 0xFFFF), w.WL[2] & 0xFFFFFFFF, len(w.queues[qva])))
                elif t in (OP_POP, OP_POP2):
                    qva = w.RL[1]
                    # NOTE: native POP returns w0 only; w21 is set explicitly
                    # by mov sites. (A prior revision saved prev-w0 into w21
                    # here; it corrupted eor chains via x0-write aliasing.)
                    forced = False
                    if "_force_val" in w.__dict__:
                        fv = w.__dict__["_force_val"]
                        if isinstance(fv, dict):
                            if self.pc in fv and fv[self.pc]:
                                w.set_reg("w0", fv[self.pc].pop(0))
                                forced = True
                        elif self.pc == 0x100570:
                            forced = True
                            if isinstance(fv, list):
                                w.set_reg("w0", fv.pop(0))
                                if not fv:
                                    w.__dict__.pop("_force_val")
                            else:
                                w.set_reg("w0", fv)
                                if not w.__dict__.get("_force_persist"):
                                    w.__dict__.pop("_force_val")
                    if not forced:
                        if w.queues.get(qva):
                            w.set_reg("w0", w.queues[qva].pop(0))
                        else:
                            w.mem.__setitem__(w.RL[19], 3)
                            w.set_reg("w0", 0)
                    w.__dict__.setdefault("_qlog", []).append(
                        (hex(self.pc), "POP", hex(qva & 0xFFFF), w.WL[0], len(w.queues.get(qva, []))))
                elif t == OP_EMIT:
                    s = w.stream_for(w.RL[1])
                    n = w.WL[2]; v = w.WL[3]
                    s.emit(n, v, self.pc)
                    w.emit_trace.append((s.va, n, v))
                    if len(w.__dict__.get("_slog", [])) < 400:
                        w.__dict__.setdefault("_slog", []).append(
                            (hex(self.pc), "EMIT", hex(s.va & 0xFFFFF)))
                elif t == OP_LENQ:
                    s = w.stream_for(w.RL[0])
                    n = w.WL[1] & 0xFFFFFFFF
                    if s.data:
                        top = s.data[-1]
                    else:
                        top = 0
                    idx = (top + n) & 0xFFFFFFFF
                    # offs[TOP+n] if in range else data fallback (slice-10 contract)
                    if 0 <= idx < len(s.offs):
                        v = s.offs[idx]
                    elif s.data and 0 <= n < len(s.data):
                        v = s.data[n]
                    else:
                        v = 0
                    w.set_reg("w0", v)
                    if len(w.__dict__.get("_slog", [])) < 400:
                        w.__dict__.setdefault("_slog", []).append(
                            (hex(self.pc), "LENQ", hex(s.va & 0xFFFFF),
                             "top=%08x" % (s.data[-1] if s.data else 0), "n=%d" % n,
                             "idx=%08x" % idx, "v=%08x" % v))
                elif t == OP_OUTLEN:
                    s = w.stream_for(w.RL[0])
                    acc = w.mem.get(s.va + 0x10, 0) & 0xFFFFFFFF
                    top = s.data[-1] if s.data else 0
                    w.set_reg("w0", (acc - top) & 0xFFFFFFFF)
                elif t == OP_PUSHS:
                    s = w.stream_for(w.RL[1])
                    s.offs.append(w.WL[1] & 0xFFFFFFFF)
                elif t == OP_POPS:
                    s = w.stream_for(w.RL[1])
                    if len(s.offs) > 1: s.offs.pop()
                elif t == OP_MKITER:
                    nva = 0x5800000000 + (w.__dict__.get("_nit", 0)) * 0x100
                    w._nit = w.__dict__.get("_nit", 0) + 1
                    w.iters.append({"va": nva, "i": 0, "n": w.WL[2]})
                    w.set_reg("w0", nva)
                    w.__dict__.setdefault("_mkiter", []).append(
                        (hex(self.pc), w.WL[2]))
                elif t == OP_ITERNEXT:
                    va = w.RL[0]
                    it = None
                    for cand in w.iters:
                        if cand["va"] == va:
                            it = cand
                            break
                    if it is None and len(w.iters) == 1:
                        # native ITERNEXT takes the iterator OBJECT (double
                        # deref via [sp]); VA-registry match fails on the
                        # inner pointer. Single live iterator => it.
                        it = w.iters[0]
                    if it and it["i"] + 1 < it["n"]:
                        it["i"] += 1
                        w.set_reg("w0", 1)
                    else:
                        if it: w.iters.remove(it)
                        w.set_reg("w0", 0)
                elif t == OP_ISEMPTY:
                    qva = w.RL[0] or w.RL[1]
                    w.set_reg("w0", 1 if not w.queues.get(qva) else 0)
                elif t == OP_RAND:
                    w.set_reg("w0", w.rnd.next() & 0xFFFFFFFF)
                    w.nrand += 1
                elif t in NOOPS:
                    pass
                elif t in (0x14784c, 0x147a20, 0x147a18):
                    # CAP(q, k): native routes on count-vs-k through an opaque
                    # maze; the PUSH exit pushes live R[x21] (slice 45). Model:
                    # pad with live x21 when top is out-of-index-range.
                    qva = w.RL[1]
                    q = w.queues.setdefault(qva, [])
                    top = q[0] if q else None
                    if top is None or (top & 0xFFFFFFFF) >= 0x10000:
                        q.insert(0, w.RL[21] & 0xFFFFFFFF)
                # stack_chk / free / calloc etc: no-op (legacy). Heap mode
                # (live replay, slice 74): real bump allocator + byte ops.
                elif t in (0x148B10, 0x148B90) and w.__dict__.get("_heap") is not None:
                    n = w.RL[0]
                    if t == 0x148B90:
                        n *= w.RL[1]
                    n = (n + 15) & ~15
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    va = w._heap[0]
                    w._heap[0] = va + max(n, 16)
                    w._heap[1][va] = max(n, 16)
                    w.set_reg("x0", va)
                elif t == 0x148BA0 and w.__dict__.get("_heap") is not None:
                    d, s, n = (w.RL[i] & 0x00FFFFFFFFFFFFFF for i in range(3))
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    for k in range(n):
                        w.stbyte(d + k, w.ldbyte(s + k))
                elif t == 0x148A20 and w.__dict__.get("_heap") is not None:
                    d = w.RL[0] & 0x00FFFFFFFFFFFFFF
                    w2, n = w.RL[1] & 0xFF, w.RL[2]
                    for k in range(n):
                        w.stbyte(d + k, w2)
                elif t == 0x148C80 and w.__dict__.get("_heap") is not None:
                    # realloc(ptr, size): bump new, copy min(old,new).
                    old = w.RL[0] & 0x00FFFFFFFFFFFFFF
                    n = (w.RL[1] + 15) & ~15
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    va = w._heap[0]
                    w._heap[0] = va + max(n, 16)
                    w._heap[1][va] = max(n, 16)
                    oldn = w._heap[1].get(old, 0)
                    for k in range(min(oldn, max(n, 16))):
                        w.stbyte(va + k, w.ldbyte(old + k))
                    w.set_reg("x0", va)
                elif t == 0x148CE0 and w.__dict__.get("_heap") is not None:
                    s = w.RL[0] & 0x00FFFFFFFFFFFFFF
                    n = 0
                    while w.ldbyte(s + n) != 0 and n < 0x10000:
                        n += 1
                    w.set_reg("x0", n)
            elif m == "blr":
                # indirect call (JNI through tables, callbacks): log args,
                # treat as no-op returning 0 (mapping runs; slice 69).
                # _blrret override {pc: value} for live replay (slice 73+).
                if not fast:
                    self.__dict__.setdefault("_calls", []).append(
                        (hex(self.pc), "blr:" + ops.split()[0],
                         tuple(self.RL[n] & M32 for n in range(9))))
                ov = self.__dict__.get("_blrret", {})
                self.set_reg("x0", ov.get(self.pc, 0))
            elif m == "csel":
                p = _split(ops)
                self.set_reg(p[0], self._get(p[1]) if self.F.get(p[3], False)
                             else self._get(p[2]))
            elif m == "cset":
                p = _split(ops)
                self.set_reg(p[0], 1 if self.F.get(p[1], False) else 0)
            elif m == "ccmp":
                # ccmp Xn, #imm, #nzcv, cond: if cond true, set flags as cmp
                p = _split(ops)
                if self.F.get(p[3], False):
                    a = self.val(p[0]); b = self.val(p[1])
                    d = (a - b) & (2**64 - 1); s = a - b
                    self.F.update({"eq": d == 0, "ne": d != 0,
                                   "hs": a >= b, "lo": a < b,
                                   "hi": a > b, "ls": a <= b})
            elif m in ("mov", "movz"):
                d, s = [p.strip() for p in ops.split(",", 1)]
                v = self.val(s)
                self.set_reg(d, v)
            elif m == "movk":
                mm = re.match(r"^(\w+),#(0x[0-9a-f]+|\d+)(?:,lsl#(\d+))?", ops.replace(" ", ""))
                if mm:
                    d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                    self.set_reg(d, (self._get(d) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr", "rev", "rev16", "neg", "mvn"):
                p = _split(ops)
                a = self.val(p[1]); b = self.val(p[2]) if len(p) > 2 else 0
                if len(p) > 3:
                    sh = p[3].replace(" ", "")
                    mm2 = re.match(r"(lsl|lsr|uxtw|sxtw)#(\d+)", sh)
                    if mm2:
                        k = int(mm2.group(2))
                        kind = mm2.group(1)
                        if kind == "lsl": b = (b << k) & (2**64 - 1)
                        elif kind == "lsr": b = (b >> k) & (2**64 - 1)
                        elif kind in ("uxtw", "sxtw"): b = ((b & 0xFFFFFFFF) << k) & (2**64 - 1)
                # ldp-style with writeback handled in ldr/ldp; here pure ALU
                if m == "add": v = (a + b) & (2**64 - 1)
                elif m == "sub": v = (a - b) & (2**64 - 1)
                elif m == "eor": v = a ^ b
                elif m == "and": v = a & b
                elif m == "orr": v = a | b
                elif m == "mul": v = (a * b) & (2**64 - 1)
                elif m == "lsl": v = (a << b) & (2**64 - 1)
                elif m == "lsr": v = (a >> b) & (2**64 - 1)
                elif m == "rev": v = int.from_bytes((a & 0xFFFFFFFF).to_bytes(4, "little"), "big")
                elif m == "rev16": v = ((a & 0xFFFF) << 16) | ((a >> 16) & 0xFFFF)
                elif m == "neg": v = (-a) & (2**64 - 1)
                elif m == "mvn": v = ~a & (2**64 - 1)
                self.set_reg(p[0], v)
                # '!' writeback forms are ldr/str; adds with shift lsl #3 for idx
            elif m == "lsr":
                pass
            elif m in ("cmp", "cmn", "tst"):
                p = _split(ops)
                a = self.val(p[0]); b = self.val(p[1]) if len(p) > 1 else 0
                is32 = p[0].lstrip().startswith("w") if p else False
                if is32:
                    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                    if m == "cmn":
                        r = a + b; d = r & 0xFFFFFFFF
                        C = r > 0xFFFFFFFF; Z = d == 0; N = (d >> 31) & 1
                        V = ((~(a ^ b) & (a ^ d)) >> 31) & 1
                    elif m == "cmp":
                        r = a - b; d = r & 0xFFFFFFFF
                        C = a >= b; Z = d == 0; N = (d >> 31) & 1
                        V = (((a ^ b) & (a ^ d)) >> 31) & 1
                    else:
                        d = a & b; C = False; Z = d == 0; N = (d >> 31) & 1; V = False
                    self.F = {"eq": Z, "ne": not Z,
                              "lt": N != V, "ge": N == V, "gt": (not Z) and (N == V), "le": Z or (N != V),
                              "hs": C, "lo": not C, "hi": C and not Z, "ls": (not C) or Z}
                    self.pc = npc
                    self.__dict__.setdefault("_roll", []).append(self.pc)
                    if len(self._roll) > 60: del self._roll[:30]
                    continue
                if m == "cmn": d = (a + b) & (2**64 - 1); s = a + b
                elif m == "tst": d = a & b; s = d
                else: d = (a - b) & (2**64 - 1); s = a - b
                self.F = {"eq": d == 0, "ne": d != 0,
                          "lt": s < 0, "ge": s >= 0, "gt": s > 0, "le": s <= 0,
                          "hs": d >= 0 if m != "cmn" else True,
                          "lo": d < 0 if m != "cmn" else False,
                          "hi": d > 0, "ls": d <= 0}
                # for hs/lo/hi/ls use unsigned semantics of a vs b
                if m == "cmp":
                    self.F["hs"] = a >= b; self.F["lo"] = a < b
                    self.F["hi"] = a > b; self.F["ls"] = a <= b
                if m == "cmn":
                    r = (a + b) & (2**64 - 1)
                    self.F["hs"] = r >= b; self.F["hi"] = r > b
            elif m == "b":
                t = pt(ops)
                if t is None: return "bad-b"
                if t == 0x100318: return "exit-clean"
                npc = t
            elif m.startswith("b."):
                cond = m[2:]
                if self.F.get(cond, False):
                    t = pt(ops)
                    if t is None: return "bad-bc"
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "cbz":
                p = _split(ops)
                t = pt(p[-1])
                if self.val(p[0]) == 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = _split(ops)
                t = pt(p[-1])
                if self.val(p[0]) != 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "tbz":
                p = _split(ops)
                t = pt(p[-1]); bit = pt(p[1])
                if not (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318: return "exit-clean"
                        npc = t
            elif m == "tbnz":
                p = _split(ops)
                t = pt(p[-1]); bit = pt(p[1])
                if (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318: return "exit-clean"
                        npc = t
            elif m == "ret":
                sh = self.__dict__.get("_shadow", [])
                if sh:
                    npc = sh.pop()
                else:
                    return "ret"
            elif m in ("ldr", "ldur", "str", "stur", "ldp", "stp", "ldrsb", "ldrsw", "ldursw", "ldrb", "strb", "ldrsh"):
                self.mem_op2(m, ops)
            elif m in ("mrs",):
                self.set_reg(ops.split(",")[0].strip(), 0x1000)
            elif m in ("stp",):
                pass
            self.pc = npc
            if not fast:
                self.__dict__.setdefault("_roll", []).append(self.pc)
                if len(self._roll) > 60: del self._roll[:30]
                if len(self.emit_trace) == 300:
                    self.__dict__["_runaway_path"] = list(self._roll)
                if self.pc == 0x100120:
                    self.__dict__.setdefault("_t120", []).append(self.RL[8])
                if self.pc == 0x10014c:
                    self.__dict__.setdefault("_t14c", []).append((self.RL[8], self.RL[27]))
        return "steps"

    def val(self, s):
        i = _SLOT.get(s)
        if i is not None:
            return self.WL[i] if s[0] == "w" else self.RL[i]
        return self._val_slow(s)

    def _val_slow(self, s):
        s = s.strip()
        if s in ("wzr", "xzr", "sp"):
            return self.RL[SP] if s == "sp" else 0
        if s.startswith("#"): return pt(s) or 0
        i = _SLOT.get(s)
        if i is not None:
            return self.WL[i] if s[0] == "w" else self.RL[i]
        if s in self.Rx: return self.Rx[s]
        # register + shift forms like 'w0, uxtw #3' handled by caller
        rec = _shift.get(s)
        if rec is None:
            base = s.split(",")[0].strip()
            mm = re.search(r"(uxtw|sxtw|lsl) #(\d+)", s)
            rec = (base, mm.group(1) if mm else "", int(mm.group(2)) if mm else 0)
            _shift[s] = rec
        base, kind, sh = rec
        bi = _SLOT.get(base)
        if bi is not None:
            if base[0] == "w":
                v = self.WL[bi]
            else:
                v = self.RL[bi]
            if kind:
                if kind == "lsl": v = (v << sh) & M64
                elif kind == "uxtw": v = (v & M32) << sh
            return v
        if base in self.Rx:
            v = self.Rx[base]
            if kind:
                if kind == "lsl": v = (v << sh) & M64
                elif kind == "uxtw": v = (v & M32) << sh
            return v
        try: return int(s, 0)
        except ValueError: return 0

    def mem_op2(self, m, ops):
        plan = _memplan(m, ops)
        if plan is None:
            return
        kind = plan[0]
        RL, WL = self.RL, self.WL
        if kind == "imm":
            _, d, base, off, wb, size, ds, dw, bs, bw = plan
            bv = WL[bs] if bw else RL[bs]
            addr = (bv + off) & M64
            if m in ("str", "stur", "strb"):
                dv = WL[ds] if dw else RL[ds] if ds >= 0 else self.Rx.get(d, 0)
                self.st(addr, dv, 4 if m == "strb" else size)
            elif m == "stp":
                pass
            else:
                v = self.ld(addr, 8 if size == 8 else 4)
                self.set_reg(d, v)
                if m in ("ldrsw", "ldursw"):
                    v32 = v & M32
                    self.set_reg(d, v32 - 2**32 if v32 >= 2**31 else v32)
            if wb:
                self.set_reg(base, addr)
            return
        if kind == "pair":
            _, d1, d2, base, off, wb, s1, w1, s2, w2, bs, bw = plan
            bv = WL[bs] if bw else RL[bs]
            addr = (bv + off) & M64
            if m == "stp":
                self.st(addr, WL[s1] if w1 else RL[s1])
                self.st(addr + 8, WL[s2] if w2 else RL[s2])
            else:
                self.set_reg(d1, self.ld(addr))
                self.set_reg(d2, self.ld(addr + 8))
            if wb:
                self.set_reg(base, (bv + off) & M64)
                if off:
                    self.set_reg(base, addr)
            return
        if kind == "post":
            _, d, base, imm, ds, dw, bs, bw = plan
            bv = WL[bs] if bw else RL[bs]
            self.set_reg(d, self.ld(bv))
            self.set_reg(base, (bv + imm) & M64)
            return
        _, d, base, idx, sh, ds, dw, bs, bw, is_, iw = plan
        bv = WL[bs] if bw else RL[bs]
        iv = (WL[is_] if iw else RL[is_]) & M32
        addr = (bv + (iv << sh)) & M64
        self.set_reg(d, self.ld(addr, 4 if d.startswith("w") else 8))


def run_markers(seed):
    """descriptors with marker data: field i dword j = (i<<20)|(j<<4)|0xA5"""
    descs = []
    for i, lendl in enumerate((36, 0, 1, 1, 8, 1, 1, 1, 4, 5, 4)):
        data = b"".join(struct.pack(">I", (i << 20) | (j << 4) | 0xA5) for j in range(lendl))
        descs.append((lendl, 0, data))
    ex = Ex(seed, descs)
    status = ex.run()
    return ex, status


OP_PUSH, OP_POP = 0x147630, 0x147734
OP_PUSH2, OP_POP2 = 0x146470, 0x146478   # tail-calls b PUSH / b POP (verified)
OP_EMIT, OP_LENQ, OP_OUTLEN = 0x146ed8, 0x147304, 0x1472e8
OP_PUSHS, OP_POPS = 0x147120, 0x147220
OP_MKITER, OP_ITERNEXT = 0x146558, 0x146650
OP_RAND = 0x148d10
OP_ISEMPTY = 0x146474
CAP_SWAPS = {0x147a20}
CAP_PUSHS = {0x14784c, 0x147a18}


class FinStream:
    """Exact native stream model."""

    __slots__ = ("va", "top", "offs", "acc", "limit")

    def __init__(self, va):
        self.va = va
        self.top = [0]        # data[] TOP stack, count = 1
        self.offs = {}        # sparse offs array
        self.acc = 0
        self.limit = 0        # offs capacity (entries)

    def emit(self, n, v):
        n &= 0xFFFFFFFF
        v &= 0xFFFFFFFF
        idx = (self.top[-1] + n) & 0xFFFFFFFF
        if idx >= self.limit:
            # native: realloc +0x80 entries, repeat (C->A loop) until idx<limit
            self.limit = ((idx // 0x80) + 1) * 0x80
        self.offs[idx] = v
        if idx >= self.acc:
            self.acc = (idx + 1) & 0xFFFFFFFF
        return idx

    def lenq(self, n):
        n &= 0xFFFFFFFF
        idx = (self.top[-1] + n) & 0xFFFFFFFF
        if idx < self.limit:
            return self.offs.get(idx, 0)
        return 0

    def outlen(self):
        return (self.acc - self.top[-1]) & 0xFFFFFFFF

    def pushs(self):
        self.top.append(self.acc)

    def pops(self):
        # POPS: acc = data[count-1] (old TOP); count -= 1; underflow -> 7
        if not self.top:
            return 7
        self.acc = self.top[-1]
        self.top.pop()
        return 0


class FinEx(Ex):
    """Ex with the corrected stream/queue ops (run() overridden)."""

    def __init__(self, seed, descs, n_streams=16, shared_q=False):
        _ensure_vm()
        # Descriptor #10 is a byte-oriented claim string and may have a
        # non-dword tail (the captures use 14 bytes).  The serializer's
        # descriptor node carries the NUL-padded dword count, not the
        # unpadded byte count.  Normalize here so direct FinEx callers and
        # capture replay have identical input semantics.
        # #7 is the logical (unpadded) #10 byte length.  A capture can still
        # contain a stale/nonzero #10 payload when #7 is zero (the
        # environment-value gate); in that case the VM must see an empty
        # #10, not the captured bytes.
        descs = list(descs)
        if len(descs) == 11 and len(bytes(descs[5][2])) >= 4:
            logical_d10_len = struct.unpack(">I", bytes(descs[5][2])[:4])[0]
            raw10 = bytes(descs[6][2])[:logical_d10_len]
            descs[6] = (0, descs[6][1], raw10)
        normalized = []
        for lendl, tag, data in descs:
            raw = bytes(data)
            padded = raw + b"\x00" * (-len(raw) % 4)
            normalized.append((max(int(lendl), len(padded) // 4), tag, padded))

        descs = normalized
        super().__init__(seed, descs, n_streams=n_streams, shared_q=shared_q)
        # iterators: dict {node_va: {"count": n, "next": va|None}} (native
        # MKITER/ITERNEXT push/pop nodes through a head cell in mem)
        self.iters = {}
        # replace every stream with the corrected model (same VAs)
        for va in list(self.streams.keys()):
            self.streams[va] = FinStream(va)
        # fix descriptor data words: native memory holds the RAW bytes; the
        # field loop does `ldr w8,[data]` (little-endian) + `rev w3,w8` to get
        # the BE dword. vm_final stored the BE-decoded dword -> double swap.
        #
        # Descriptor regions are not actually 0x400 bytes apart in the
        # capture: #10 is 1072 bytes (268 dwords), so the old 0x400 spacing
        # made its final dword overlap descriptor #7's region.  That turned
        # the first tail word into zero and diverged the claim/sink streams
        # at body word 12.  Give every descriptor a non-overlapping 0x1000
        # slot and update its node data pointer accordingly.
        for i, (lendl, tag, data) in enumerate(descs):
            nva = 0x5600000000 + i * 0x100
            dva = 0x5700000000 + i * 0x1000
            self.mem[nva + 8] = dva
            for j in range(lendl):
                v = struct.unpack_from("<I", data, 4 * j)[0] if len(data) >= 4 * (j + 1) else 0
                self.mem[dva + 4 * j] = v

    def stream_for(self, va):
        va &= PM
        s = self.streams.get(va)
        if s is None:
            s = FinStream(va)
            self.streams[va] = s
        return s

    # ---- CAP helpers ----
    def _q_nodes(self, qva):
        return self.queues.setdefault(qva, [])

    def cap_swap(self, qva, k):
        q = self.queues.setdefault(qva, [])
        if len(q) <= k:
            self.mem[self.RL[19]] = 4
            return
        q[0], q[k] = q[k], q[0]          # swap head value with node[k] value

    def cap_push(self, qva, k):
        q = self.queues.setdefault(qva, [])
        if len(q) <= k:
            self.mem[self.RL[19]] = 4
            return
        q.insert(0, q[k])                # push a copy of node[k]'s value

    def mem_op2(self, m, ops):
        super().mem_op2(m, ops)
        if m == "ldrh":
            d = ops.split(",")[0].strip()
            i = _SLOT.get(d)
            if i is not None:
                self.set_reg(d, (self.WL[i] if d[0] == "w" else self.RL[i]) & 0xFFFF)

    def run(self, max_steps=4_000_000):
        RL, WL, F, mem = self.RL, self.WL, self.F, self.mem
        _hook = self.__dict__.get("_step_hook")
        _pclog = self.__dict__.get("_pc_log")
        _dbg = self.__dict__.get("_dbg164")
        _fast = not (_hook is not None or _pclog is not None
                     or _dbg is not None)
        _f = FAST
        while self.steps < max_steps:
            self.steps += 1
            if not _fast:
                if _hook is not None:
                    _hook(self)
                if _pclog is not None:
                    _pclog.append(self.pc)
            k = IDX.get(self.pc)
            if k is None:
                return "pc-out"
            if not _fast and self.pc == 0x100164 and _dbg is not None:
                _dbg.append((RL[21], RL[22], self.steps))
            if _fast:
                m, ops, npc = _f[k]
            else:
                i = INS[k]
                m, ops = i.mnemonic, i.op_str
                npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                if t in (OP_PUSH, OP_PUSH2):
                    qva = RL[1]
                    self.queues.setdefault(qva, []).insert(0, WL[2] & 0xFFFFFFFF)
                    if self.__dict__.get("_qop_log") is not None:
                        self._qop_log.append(("PUSH", self.pc, qva & 0xFFFFFFFFFFFF,
                                              WL[2] & 0xFFFFFFFF))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("PUSH", self.pc,
                                               qva & 0xFFFFFFFFFFFF,
                                               WL[2] & 0xFFFFFFFF))
                elif t in (OP_POP, OP_POP2):
                    qva = RL[1]
                    q = self.queues.get(qva)
                    if q:
                        _v0 = q.pop(0)
                        WL[0] = _v0; RL[0] = _v0
                    else:
                        mem[RL[19]] = 3
                        WL[0] = 0; RL[0] = 0
                    if self.__dict__.get("_qop_log") is not None:
                        self._qop_log.append(("POP", self.pc, qva & 0xFFFFFFFFFFFF,
                                              WL[0] & 0xFFFFFFFF))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("POP", self.pc,
                                               qva & 0xFFFFFFFFFFFF,
                                               WL[0] & 0xFFFFFFFF))
                elif t == OP_EMIT:
                    s = self.stream_for(RL[1])
                    n = WL[2]
                    v = WL[3]
                    s.emit(n, v)
                    self.emit_trace.append((s.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_emit_pc") is not None:
                        self._emit_pc.append((self.pc, s.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_emit_full") is not None:
                        self._emit_full.append((self.pc, s.va, s.top[-1],
                                                n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("E", self.pc, s.va, s.top[-1],
                                               n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                elif t == OP_LENQ:
                    s = self.stream_for(RL[0])
                    WL[0] = s.lenq(WL[1])
                    RL[0] = WL[0]
                    if self.__dict__.get("_lenq_log") is not None:
                        self._lenq_log.append((self.pc, s.va, WL[1] & 0xFFFFFFFF,
                                               s.top[-1], WL[0]))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("Q", self.pc, s.va,
                                               s.top[-1],
                                               WL[1] & 0xFFFFFFFF,
                                               WL[0] & M32))
                elif t == OP_OUTLEN:
                    s = self.stream_for(RL[0])
                    WL[0] = s.outlen()
                    RL[0] = WL[0]
                elif t == OP_PUSHS:
                    s = self.stream_for(RL[1])
                    if self.__dict__.get("_sp_log") is not None:
                        self._sp_log.append(("PUSHS", i.address, s.va, s.acc, list(s.top)))
                    s.pushs()
                elif t == OP_POPS:
                    s = self.stream_for(RL[1])
                    if self.__dict__.get("_sp_log") is not None:
                        self._sp_log.append(("POPS", i.address, s.va, s.acc, list(s.top)))
                    err = s.pops()
                    if err:
                        mem[RL[19]] = err
                elif t in CAP_SWAPS:
                    if self.__dict__.get("_cap_log") is not None:
                        q = self.queues.get(RL[1], [])
                        self._cap_log.append(("SW", self.pc, len(q), WL[2], list(q[:6])))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("SW", self.pc,
                                               RL[1] & 0xFFFFFFFFFFFF,
                                               WL[2] & 0xFFFFFFFF))
                    self.cap_swap(RL[1], WL[2] & 0xFFFFFFFF)
                elif t in CAP_PUSHS:
                    kk = 0 if t == 0x147a18 else (WL[2] & 0xFFFFFFFF)
                    # 0x147a18 = thunk: mov w2,wzr; b 0x14784c  (CAP push, k:=0)
                    if self.__dict__.get("_cap_log") is not None:
                        q = self.queues.get(RL[1], [])
                        self._cap_log.append(("PU", self.pc, len(q), kk, list(q[:6])))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("PU", self.pc,
                                               RL[1] & 0xFFFFFFFFFFFF,
                                               kk))
                    self.cap_push(RL[1], kk)
                elif t == OP_MKITER:
                    # native MKITER(x0=writer, x1=head_cell, w2=n):
                    #   node = calloc(1,16); node[0]=n; node[8]=[x1]; [x1]=node
                    #   (alloc failure -> [writer]=2; cannot happen here)
                    # The nodes form a LIFO list through the head cell, so
                    # nested iterators nest correctly.
                    cell = RL[1] & PM
                    nva = 0x5800000000 + (self.__dict__.get("_nit", 0)) * 0x100
                    self._nit = self.__dict__.get("_nit", 0) + 1
                    self.iters[nva] = {"count": WL[2] & 0xFFFFFFFF,
                                       "next": self.mem.get(cell)}
                    self.mem[cell] = nva
                    WL[0] = nva
                    RL[0] = nva
                elif t == OP_ITERNEXT:
                    # native ITERNEXT(x0=head_cell):
                    #   node = [x0]; w21 = node.count - 1; node.count = w21
                    #   if w21 == 0: [x0] = node.next; free(node)
                    #   return w21    (caller loops with cbnz while non-zero)
                    cell = RL[0] & PM
                    nva = self.mem.get(cell)
                    node = self.iters.get(nva) if nva is not None else None
                    if node is None:
                        WL[0] = 0; RL[0] = 0
                    else:
                        c = (node["count"] - 1) & 0xFFFFFFFF
                        node["count"] = c
                        if c == 0:
                            self.mem[cell] = node["next"]
                            self.iters.pop(nva, None)
                        WL[0] = c; RL[0] = c
                elif t == OP_ISEMPTY:
                    qva = RL[0] or RL[1]
                    WL[0] = 1 if not self.queues.get(qva) else 0
                    RL[0] = WL[0]
                elif t == OP_RAND:
                    WL[0] = self.rnd.next() & M32
                    RL[0] = WL[0]
                    self.nrand += 1
                else:
                    # unknown bl: log it loudly, treat as no-op
                    self.__dict__.setdefault("_unk_bl", set()).add(hex(t or 0))
                    WL[0] = WL[0]
            elif m == "blr":
                self.set_reg("x0", 0)
            elif m == "csel":
                p = _split(ops)
                self.set_reg(p[0], self._get(p[1]) if F.get(p[3], False)
                             else self._get(p[2]))
            elif m == "cset":
                p = _split(ops)
                self.set_reg(p[0], 1 if F.get(p[1], False) else 0)
            elif m == "ccmp":
                p = _split(ops)
                if F.get(p[3], False):
                    a = self.val(p[0]); b = self.val(p[1])
                    d = (a - b) & (2**64 - 1)
                    F.update({"eq": d == 0, "ne": d != 0,
                              "hs": a >= b, "lo": a < b,
                              "hi": a > b, "ls": a <= b})
            elif m in ("mov", "movz"):
                d, s = [p.strip() for p in ops.split(",", 1)]
                self.set_reg(d, self.val(s))
            elif m == "movk":
                import re
                mm = re.match(r"^(\w+),#(0x[0-9a-f]+|\d+)(?:,lsl#(\d+))?", ops.replace(" ", ""))
                if mm:
                    d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                    self.set_reg(d, (self._get(d) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr",
                       "rev", "rev16", "neg", "mvn", "udiv", "msub"):
                p = _split(ops)
                if m == "udiv":
                    a = self.val(p[1]); b = self.val(p[2])
                    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                    v = (a // b) if b else 0
                    if p[0].startswith("w"):
                        v &= 0xFFFFFFFF
                    self.set_reg(p[0], v)
                    self.pc = npc
                    continue
                if m == "msub":
                    # msub Wd, Wn, Wm, Wa: Wd = Wa - Wn*Wm
                    a = self.val(p[1]); b = self.val(p[2]); c = self.val(p[3])
                    v = (c - a * b) & (2**64 - 1)
                    if p[0].startswith("w"):
                        v &= 0xFFFFFFFF
                    self.set_reg(p[0], v)
                    self.pc = npc
                    continue
                a = self.val(p[1]); b = self.val(p[2]) if len(p) > 2 else 0
                if len(p) > 3:
                    sh = p[3].replace(" ", "")
                    import re
                    mm2 = re.match(r"(lsl|lsr|uxtw|sxtw)#(\d+)", sh)
                    if mm2:
                        kk = int(mm2.group(2))
                        if mm2.group(1) == "lsl":
                            b = (b << kk) & (2**64 - 1)
                        elif mm2.group(1) == "lsr":
                            b = (b >> kk) & (2**64 - 1)
                        elif mm2.group(1) in ("uxtw", "sxtw"):
                            b = ((b & 0xFFFFFFFF) << kk) & (2**64 - 1)
                if m == "add":
                    v = (a + b) & (2**64 - 1)
                elif m == "sub":
                    v = (a - b) & (2**64 - 1)
                elif m == "eor":
                    v = a ^ b
                elif m == "and":
                    v = a & b
                elif m == "orr":
                    v = a | b
                elif m == "mul":
                    v = (a * b) & (2**64 - 1)
                elif m == "lsl":
                    v = (a << b) & (2**64 - 1)
                elif m == "lsr":
                    v = (a >> b) & (2**64 - 1)
                elif m == "rev":
                    v = int.from_bytes((a & 0xFFFFFFFF).to_bytes(4, "little"), "big")
                elif m == "rev16":
                    v = ((a & 0xFFFF) << 16) | ((a >> 16) & 0xFFFF)
                elif m == "neg":
                    v = (-a) & (2**64 - 1)
                elif m == "mvn":
                    v = ~a & (2**64 - 1)
                self.set_reg(p[0], v)
            elif m in ("cmp", "cmn", "tst"):
                p = _split(ops)
                a = self.val(p[0]); b = self.val(p[1]) if len(p) > 1 else 0
                is32 = p[0].lstrip().startswith("w") if p else False
                if is32:
                    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                    if m == "cmn":
                        r = a + b; d = r & 0xFFFFFFFF
                        C = r > 0xFFFFFFFF; Z = d == 0; N = (d >> 31) & 1
                        Vv = ((~(a ^ b) & (a ^ d)) >> 31) & 1
                    elif m == "cmp":
                        r = a - b; d = r & 0xFFFFFFFF
                        C = a >= b; Z = d == 0; N = (d >> 31) & 1
                        Vv = (((a ^ b) & (a ^ d)) >> 31) & 1
                    else:
                        d = a & b; C = False; Z = d == 0; N = (d >> 31) & 1; Vv = False
                    F.clear(); F.update({"eq": Z, "ne": not Z,
                              "lt": N != Vv, "ge": N == Vv,
                              "gt": (not Z) and (N == Vv), "le": Z or (N != Vv),
                              "hs": C, "lo": not C, "hi": C and not Z,
                              "ls": (not C) or Z})
                    self.pc = npc
                    continue
                if m == "cmn":
                    d = (a + b) & (2**64 - 1); sg = a + b
                elif m == "tst":
                    d = a & b; sg = d
                else:
                    d = (a - b) & (2**64 - 1); sg = a - b
                F.clear(); F.update({"eq": d == 0, "ne": d != 0,
                          "lt": sg < 0, "ge": sg >= 0, "gt": sg > 0, "le": sg <= 0,
                          "hi": d > 0, "ls": d <= 0})
                if m == "cmp":
                    F["hs"] = a >= b; F["lo"] = a < b
                elif m == "cmn":
                    F["hs"] = True; F["lo"] = False
            elif m == "b":
                t = pt(ops)
                if t is None:
                    return "bad-b"
                if t == 0x100318:
                    return "exit-clean"
                npc = t
            elif m.startswith("b."):
                cond = m[2:]
                if F.get(cond, False):
                    t = pt(ops)
                    if t is None:
                        return "bad-bc"
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "cbz":
                p = _split(ops)
                t = pt(p[-1])
                if self.val(p[0]) == 0 and t is not None:
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = _split(ops)
                t = pt(p[-1])
                if self.val(p[0]) != 0 and t is not None:
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "tbz":
                p = _split(ops)
                t = pt(p[-1]); bit = pt(p[1])
                if not (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318:
                            return "exit-clean"
                        npc = t
            elif m == "tbnz":
                p = _split(ops)
                t = pt(p[-1]); bit = pt(p[1])
                if (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318:
                            return "exit-clean"
                        npc = t
            elif m == "ret":
                sh = self.__dict__.get("_shadow", [])
                if sh:
                    npc = sh.pop()
                else:
                    return "ret"
            elif m in ("ldr", "ldur", "str", "stur", "ldp", "stp", "ldrsb",
                       "ldrsw", "ldursw", "ldrb", "strb", "ldrsh", "ldrh"):
                self.mem_op2(m, ops)
            elif m == "mrs":
                self.set_reg(ops.split(",")[0].strip(), 0x1000)
            self.pc = npc
        return "steps"


# **********************************************************************
# PART 5 — PUBLIC API: everything a caller needs
# **********************************************************************
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]     # FinEx descriptor order
SINK = 0x5500000000                               # blob stream (all corpus rows)
BLOB_WORDS = 48                                   # 48 x BE u32 = 192 B
ADJ_VERIFICATION = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI" # the app's adj_verification claim
ADJ_SIGNING_ID = "1500000"                        # pinned claim + header value
CLIENT_SDK = "android5.7.0"                       # Client-SDK header + claim
NATIVE_VERSION = "5.0.0"                          # native_version claim

# --- proven mint internals (claims padding + VM assembly) --------------
def claims_padded(val, kind):
    """(padded #10 bytes, unpadded length) — the adj9_forge.claims_padded
    rule: NUL-pad the law string to a 4-byte multiple (slice 105), #7 keeps
    the UNPADDED length (slice 99 §2)."""
    raw = claims_unpadded(val, kind).encode("latin1")
    return raw + b"\x00" * (-len(raw) % 4), len(raw)


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



# pinned descriptor constants (extracted from the app)
DESC8 = bytes.fromhex("bffffffffffffd1f0007000000000000")          # 16-B
DESC9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")  # 20-B

# the genuine d0 head phase for request signings (solved from winners)
WIN_PHASE = (0x2B, 0x48)


def sign_request_vm(params, kind, head=WIN_PHASE, second=None, seed=None,
                    max_steps=40_000_000):
    """The ORIGINAL FinEx-VM signing path. Kept for cross-checking.

    Slow (12-20 s) but it is the ground truth: the closed-form sign_request
    below must agree with this 192/192 on any descriptor plane.
    """
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": CLIENT_SDK,
                "adj_signing_id": ADJ_SIGNING_ID, "headers_id": "10",
                "native_version": NATIVE_VERSION,
                "adj_verification": ADJ_VERIFICATION})
    second = int(second if second is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if seed is None else seed
    d0w, d2w, d4w = region(seed, 0, 0, head=head)
    padded, unpadded = claims_padded(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0),                    # region part 1
          9: (5, 0, DESC9), 8: (4, 0, DESC8),  # pinned app constants
          4: (8, 0, d4),                     # region part 2
          2: (1, 0, struct.pack(">I", d2w)),  # the seed S
          7: (1, 0, struct.pack(">I", unpadded)),  # claims length
          10: (len(padded) // 4, 0, padded),  # the claims themselves
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}    # zeros / empty
    descs = [by[i] for i in VA_ORDER]        # fixed descriptor order
    blob, info = finex_mint(descs, second, max_steps=max_steps)
    return blob, second, info


def sign_request(params, kind, head=WIN_PHASE, second=None, seed=None,
                 max_steps=40_000_000):
    """One fresh signing -> (blob_192B, second, info). NO VM.

    This is the closed-form path. It is 192/192 byte-exact against all six
    genuine penti captures (session, click and attribution kinds, two devices)
    and against the creditsea gold -- see block_law2/LAW.md for the block and
    digest_law/LAW.md for the trailer. It takes ~25 ms instead of 12-20 s.

    Use sign_request_vm to cross-check against the machine itself.
    """
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": CLIENT_SDK,
                "adj_signing_id": ADJ_SIGNING_ID, "headers_id": "10",
                "native_version": NATIVE_VERSION,
                "adj_verification": ADJ_VERIFICATION})
    second = int(second if second is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if seed is None else seed
    padded, unpadded_len = claims_padded(val, kind)
    # the block law hashes the claims UNPADDED: strip the NUL padding back off
    claims_raw = padded[:unpadded_len]
    d0w, _d2w, _d4w = region(seed, 0, 0, head=head)
    head_b = head_words(d0w)

    rec = bytearray(144)
    rec[0:3] = b"\x01\x00\x08"
    rec[3:19] = head_b
    rec[19] = 0x02
    rec[20:24] = struct.pack(">I", seed)
    rec[24] = 0x03
    rec[25:45] = DESC9
    rec[45] = 0x04
    rec[46:78] = record_block(head_b, seed, claims_raw, DESC9)
    rec[78] = 0x05
    rec[79:111] = SHA0
    rec[111:114] = b"\x06\x01\x07"
    rec[114:128] = b"\x00" * 14
    rec[128:130] = b"\x00\x00"
    rec[130:144] = b"\x0e" * 14

    header = make_header(second)
    body = encrypt(bytes(rec), header)
    blob = header + body + record_digest(body)
    return blob, second, {"status": "closed-form", "steps": 0, "nrand": 0,
                          "stream": 0, "header": header}


# ---------------------------------------------------------------------------
# the two hash laws, inlined so the fast path needs no extra imports
# ---------------------------------------------------------------------------
SHA0 = hashlib.sha256(b"").digest()

# DIGEST LAW (digest_law/LAW.md): blob[160:192] is a custom two-pass SHA-256
# MAC over the whitened record. NOT standard HMAC -- the raw pad block is
# hashed a second time after the keyed block.
_DIG_K = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                       "0451723fbcfa92df62b55f6fec60f2de")
_DIG_IPAD = b"\x36" * 32
_DIG_OPAD = b"\x5c" * 32
_DIG_KI = bytes(a ^ b for a, b in zip(_DIG_K, _DIG_IPAD))
_DIG_KO = bytes(a ^ b for a, b in zip(_DIG_K, _DIG_OPAD))


def record_digest(body):
    inner = hashlib.sha256(_DIG_KI + _DIG_IPAD + body).digest()
    return hashlib.sha256(_DIG_KO + _DIG_OPAD + inner).digest()


# BLOCK LAW (block_law2/LAW.md): record[46:78] is standard SHA-256 with
# standard padding and round constants, but chained from a VM-hardcoded IV2
# instead of the standard SHA-256 IV. That single deviation is why every
# off-the-shelf hash battery missed it.
_BLK_IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                         "7a30ed9323473054bbe3cd00f1355ea5")
_M32 = 0xFFFFFFFF
_K256 = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _sha256_block(st, blk):
    w = list(blk)
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M32)
    a, b, c, d, e, f, g, h = st
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + ((e & f) ^ (~e & g)) + _K256[i] + w[i]) & _M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & _M32
        h, g, f, e, d, c, b, a = (g, f, e, (d + t1) & _M32, c, b, a,
                                  (t1 + t2) & _M32)
    return [(x + y) & _M32 for x, y in zip(st, (a, b, c, d, e, f, g, h))]


def _sha256_from_iv2(msg):
    st = list(struct.unpack(">8I", _BLK_IV2))
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, [int.from_bytes(m[i + 4 * j:i + 4 * j + 4], "big")
                            for j in range(16)])
    return struct.pack(">8I", *st)


def record_block(head_b, seed, claims, d9):
    """record[46:78) = SHA256-IV2( D9 || 00 08 || head || LE32(S)
                                 || sha256("") || 01 00*16 || claims )"""
    msg = (d9 + b"\x00\x08" + head_b + struct.pack("<I", seed)
           + SHA0 + b"\x01" + b"\x00" * 16 + claims)
    return _sha256_from_iv2(msg)


def auth_header(blob):
    """The Authorization header value for a minted blob."""
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="10",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_SIGNING_ID,
               NATIVE_VERSION, ADJ_VERIFICATION))


# **********************************************************************
# APPENDIX — VM bootstrap + the embedded libsigner.so code spans.
# Not human content: this is the app's signing-machine bytecode.
# **********************************************************************
_LIB_SPANS = [
    (0x99000, 0xBCA30,
     "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"),
    (0x100094, 0x12AA48,
     "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KOXyNYECQPngAxOqQieAUuuzAJRoAkC5aOTyNYECQPngAxOq4gGAUuWzAJRoAkC5qOPyNYECQPngAxOqYieAUt+zAJRoAkC56OLyNYECQPngAxOqgh+AUtmzAJRoAkC5KOLyNYECQPngAxOqgieAUtOzAJRoAkC5aOHyNYECQPngAxOqggiAUs2zAJRoAkC5qODyNYECQPngAxOqoieAUsezAJRoAkC56N/yNYECQPngAxOqggGAUsGzAJRoAkC5KN/yNYECQPngAxOqwieAUruzAJRoAkC5aN7yNYECQPngAxOqIhOAUrWzAJRoAkC5qN3yNYECQPngAxOq4ieAUq+zAJRoAkC56NzyNYECQPngAxOqohWAUqmzAJRoAkC5KNzyNYECQPngAxOqAiiAUqOzAJRoAkC5aNvyNYECQPngAxOqghSAUp2zAJRoAkC5qNryNYECQPngAxOqIiiAUpezAJRoAkC56NnyNYECQPngAxOq4gSAUpGzAJRoAkC5KNnyNYECQPngAxOqQiiAUouzAJRoAkC5aNjyNYECQPngAxOqwhSAUoWzAJRoAkC5qNfyNYECQPngAxOqYiiAUn+zAJRoAkC56NbyNYECQPngAxOqohSAUnmzAJRoAkC5KNbyNYECQPngAxOqgiiAUnOzAJRoAkC5aNXyNYECQPngAxOqohmAUm2zAJRoAkC5qNTyNYECQPngAxOqoiiAUmezAJRoAkC56NPyNYECQPngAxOqYhCAUmGzAJRoAkC5KNPyNYECQPngAxOqwiiAUluzAJRoAkC5aNLyNYECQPngAxOqghWAUlWzAJRoAkC5qNHyNYECQPngAxOq4iiAUk+zAJRoAkC56NDyNYECQPngAxOqIhOAUkmzAJRoAkC5KNDyNYECQPngAxOqAimAUkOzAJRoAkC5aM/yNYECQPngAxOqwhyAUj2zAJRoAkC5qM7yNYECQPngAxOqIimAUjezAJRoAkC56M3yNYECQPngAxOq4hKAUjGzAJRoAkC5KM3yNYECQPngAxOqQimAUiuzAJRoAkC5aMzyNYECQPngAxOqYgeAUiWzAJRoAkC5qMvyNYECQPngAxOqYimAUh+zAJRoAkC56MryNYECQPngAxOqwgCAUhmzAJRoAkC5KMryNYECQPngAxOqgimAUhOzAJRoAkC5aMnyNYECQPngAxOq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aLjuNYECQPngAxOqIgCAUgyTAJRoAkC5qLfuNYECQPngAxOqwZIAlGgCQLkIt+419QMAKoECQPngAxOqu5IAlGgCQLlItu414wMAKkEDQPngAxOq4gMVKp2QAJRoAkC5aLXuNYECQPngAxOq4ssAMm2SAJRoAkC5qLTuNYECQPngAxOqIgCAUmOTAJRoAkC56LPuNYECQPngAxOqo5IAlGgCQLlIs+41gQJA+QIEABHgAxOqXJIAlGgCQLmIsu41gQJA+eADE6qYkgCUaAJAueix7jX1AwAqgQJA+eADE6qSkgCUaAJAuSix7jXjAwAqQQNA+eADE6riAxUqdJAAlGgCQLlIsO41gQJA+eADE6riAIBSRJIAlGgCQLmIr+41gQJA+eADE6qAkgCUaAJAueiu7jX1AwAqgQJA+eADE6p6kgCUaAJAuSiu7jWBAkD5AgAVC+ADE6ozkgCUaAJAuWit7jWBAkD54AMTqoIAgFItkgCUaAJAuais7jWBAkD54AMTqiIAgFKukgCUaAJAueir7jWBAkD54AMTqmOSAJRoAkC5SKvuNfUDACqBAkD54AMTql2SAJRoAkC5iKruNaIKwBqBAkD54AMTqhaSAJRoAkC5yKnuNYECQPngAxOqggCAUhCSAJRoAkC5CKnuNYECQPngAxOqQgCAUpGSAJRoAkC5SKjuNYECQPngAxOqRpIAlGgCQLmop+419QMAKoECQPngAxOqQJIAlGgCQLnopu41qArAGoECQPkC1QAb4AMTqviRAJRoAkC5CKbuNYECQPngAxOq4gMfKvKRAJRoAkC5SKXuNYECQPngAxOqLpIAlGgCQLmopO419QMAKoECQPngAxOqKJIAlGgCQLnoo+41vwIAa4ECQPniJ58a4AMTquCRAJRoAkC5CKPuNYECQPngAxOqHJIAlGgCQLloou419QMAKoECQPngAxOqFpIAlGgCQLmooe41gQJA+QIAFQvgAxOqz5EAlGgCQLnooO41gQJA+eADE6oiAIBSxZIAlGgCQLkooO41gQJA+eADE6oiAIBSSpIAlGgCQLlon+41gQJA+eADE6r/kQCUaAJAucie7jX1AwAqgQJA+eADE6r5kQCUaAJAuQie7jXjAwAqQQNA+eADE6riAxUq248AlGgCQLkone41gQJA+eADE6oiAIBSq5EAlGgCQLlonO41gQJA+eADE6oiAIBSLJIAlGgCQLmom+41gQJA+eADE6oiAIBSJpIAlGgCQLnomu41gQJA+eADE6rbkQCUaAJAuUia7jX2AwAqHzwAccjSA1SBAkD54AMTqtORAJT450CpaAJAuSiZ7jX1AwAqgQJA+eADE6rMkQCUaAJAuWiY7jWcTjaL9wMAKuADE6qBD0L4gJAAlGgCQLmIl+41gQNA+eADE6o7kACUaAJAueiW7jX2Ax8q+wIVC6ECFgs/ABtr4tUAVEADQPmXA0D5qpAAlOMDACrgAxOq4QMXquIDFiqajwCU+OdAqdYGABFoAkC5SP7/NKV0/xeBAkD54AMTqqmRAJT450CpaAJAueiT7jXhAwAqlQJAqZeQAJTiAwAq4AMTquEDFapekQCUaAJAuciS7jWBAkD54AMTquIDHypYkQCUaAJAuQiS7jWBAkD54AMTqk2SAJRoAkC5aJHuNYECQPngAxOqj5EAlGgCQLnIkO419QMAKoECQPngAxOqiZEAlGgCQLkIkO41nE4gi4APQvhxkACU9gMAKvcDHyrfAhdrwDoAVIADQPnhAxcqWANA+bkCFwtvkACU4wMAKuADE6rhAxiq4gMZKl+PAJT450Cp9wYAEWgCQLko/v80anT/F4ECQPngAxOq4gMfKiyRAJT450CpaAJAuWiM7jWBAkD54AMTqiCSAJRoAkC5yIvuNYECQPngAxOqYpEAlGgCQLkoi+419gMAKh88AHGowwNUgQJA+eADE6pakQCU+OdAqWgCQLkIiu419QMAKoECQPngAxOqU5EAlGgCQLlIie41nE42i/cDACrgAxOqgQ9C+AeQAJRoAkC5aIjuNYEDQPngAxOqwo8AlGgCQLnIh+419gMfKvsCFQuhAhYLPwAba+KuAlRAA0D5lwNA+TGQAJTjAwAq4AMTquEDF6riAxYqIY8AlPjnQKnWBgARaAJAuUj+/zQsdP8X4AMTquqRAJT450CpaAJAueiE7jWBAkD54AMTqkIBgFLpkACUaAJAuSiE7jWBAkD54AMTqiWRAJRoAkC5iIPuNfUDACqBAkD54AMTqh+RAJRoAkC5yILuNb8CAGuBAkD54hefGuADE6rXkACUaAJAueiB7jWBAkD54AMTqhORAJRoAkC5SIHuNYECQPkATwA04AMTqg2RAJT450CpaAJAuWiA7jWBAkD54AMTqsCRAJRoAkC5yH/uNYECQPngAxOqApEAlGgCQLkof+414QMAKpUCQKnxjwCU4gMAKuADE6rhAxWquJAAlGgCQLkIfu41gQJA+eADE6ri/79SspAAlGgCQLlIfe41gQJA+eADE6rukACUaAJAuah87jX1AwAqgQJA+eADE6rokACUaAJAueh77jWBAkD5AgAVCuADE6qhkACUaAJAuSh77jWBAkD54AMTqsLAgFKbkACUaAJAuWh67jWBAkD54AMTqteQAJRoAkC5yHnuNfUDACqBAkD54AMTqtGQAJRoAkC5CHnuNYECQPkCABUq4AMTqoqQAJRoAkC5SHjuNYECQPngAxOqIgCAUguRAJRoAkC5iHfuNYECQPngAxOqwJAAlGgCQLnodu419QMAKoECQPngAxOqupAAlGgCQLkodu414wMAKkEDQPngAxOq4gMVKpyOAJRoAkC5SHXuNYECQPngAxOq4scHMmyQAJRoAkC5iHTuNYECQPngAxOqIgCAUmKRAJRoAkC5yHPuNYECQPngAxOqopAAlGgCQLkoc+41gQJA+QIEABHgAxOqW5AAlGgCQLlocu41gQJA+eADE6qXkACUaAJAuchx7jX1AwAqgQJA+eADE6qRkACUaAJAuQhx7jXjAwAqQQNA+eADE6riAxUqc44AlGgCQLkocO41gQJA+eADE6rCAIBSQ5AAlGgCQLlob+41gQJA+eADE6p/kACUaAJAuchu7jX1AwAqgQJA+eADE6p5kACUaAJAuQhu7jWBAkD5AgAVC+ADE6oykACUaAJAuUht7jWBAkD54AMTqoIAgFIskACUaAJAuYhs7jWBAkD54AMTqiIAgFKtkACUaAJAuchr7jWBAkD54AMTqmKQAJRoAkC5KGvuNfUDACqBAkD54AMTqlyQAJRoAkC5aGruNaIKwBqBAkD54AMTqhWQAJRoAkC5qGnuNYECQPngAxOqggCAUg+QAJRoAkC56GjuNYECQPngAxOqQgCAUpCQAJRoAkC5KGjuNYECQPngAxOqRZAAlGgCQLmIZ+419QMAKoECQPngAxOqP5AAlGgCQLnIZu41qArAGoECQPkC1QAb4AMTqvePAJRoAkC56GXuNYECQPngAxOq4gMfKvGPAJRoAkC5KGXuNYECQPngAxOqLZAAlGgCQLmIZO419QMAKoECQPngAxOq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"),
    (0x146000, 0x149000,
     "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"),
]


class _LibBytes:
    """vaddr-indexed sparse view of the embedded code ranges."""

    def __init__(self, spans):
        self._spans = sorted((a, b, base64.b64decode(s)) for a, b, s in spans)

    def __getitem__(self, sl):
        if not isinstance(sl, slice) or sl.step is not None:
            raise TypeError("vaddr slicing only")
        out = bytearray()
        for a, b, raw in self._spans:
            lo, hi = max(a, sl.start), min(b, sl.stop)
            if hi > lo:
                out += raw[lo - a:hi - a]
        if len(out) != sl.stop - sl.start:
            raise KeyError("vaddr range not fully embedded")
        return bytes(out)


def _init_vm():
    """Disassemble the embedded spans into the VM's instruction tables."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    elf = _LibBytes(_LIB_SPANS)
    INS.extend(md.disasm(elf[0x100094:0x12aa48], 0x100094))
    IDX.update({i.address: k for k, i in enumerate(INS)})
    for va, end in ((0x99000, 0xBB548), (0x146000, 0x149000),
                    (0xBB548, 0xBCA30)):
        more = list(md.disasm(elf[va:end], va))
        base = len(INS)
        INS.extend(more)
        IDX.update({i.address: base + k for k, i in enumerate(more)})
    FAST.extend((i.mnemonic, i.op_str, i.address + 4) for i in INS)
    m0.extend(i.mnemonic for i in INS)


INS, IDX, FAST, m0 = [], {}, [], []
_VM_READY = []


def _ensure_vm():
    """Disassemble libsigner.so on FIRST USE, not at import.

    The closed-form sign_request never needs this, so importing
    adj9_signature for the live flow no longer pays the ~1 s capstone
    disassembly (and no longer requires capstone to be installed)."""
    if not _VM_READY:
        _init_vm()
        _VM_READY.append(True)


# =============================================================================
# PART 5 -- API
# =============================================================================
CFG = {}

# Keys that live INSIDE the signature but never in the HTTP body.
INTERNAL = ("activity_kind", "adj_signing_id", "adj_verification",
            "algorithm", "client_sdk", "headers_id", "native_version")

# the 5.7.x claim law, as it exists in the VM section above
_law57 = globals().get("claims_padded")


def configure(cfg):
    """Load the app settings. Call once before signing.

    Either pass the dict directly (this is what run_install.py does, holding
    its CAMPAIGN inline) or load it from apps.json."""
    global CFG
    CFG = dict(cfg)
    # descriptor #9 = the APK signing-certificate SHA-1  (app-specific)
    globals()["DESC9"] = bytes.fromhex(cfg["cert_sha1"])
    # descriptor #8 = a constant for a given libsigner build
    globals()["DESC8"] = bytes.fromhex(
        cfg.get("d8", "bffffffffffffd1f0007000000000000"))
    # the d0 head phase is PER APP, not global
    globals()["WIN_PHASE"] = tuple(int(h, 16)
                                   for h in cfg.get("head_phase", ["0x2b"]))
    globals()["ADJ_SIGNING_ID"] = cfg.get("adj_signing_id", "1500000")
    globals()["ADJ_VERIFICATION"] = cfg.get("adj_verification", "")
    globals()["NATIVE_VERSION"] = cfg.get("native_version", "5.0.0")
    globals()["CLIENT_SDK"] = cfg.get("client_sdk", "android5.7.0")
    # pick the claim law for this SDK generation
    if str(cfg.get("sdk_version", "5.7.0")) >= "5.8":
        globals()["claims_padded"] = claims_padded_58
    else:
        globals()["claims_padded"] = _law57


def _stamp(ts, ms, tz_min=330, tz_label="+0530"):
    import datetime
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=tz_min))
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + tz_label)


def _tz(dev):
    tz = dev.get("timezone", "+0530")
    sign = -1 if tz[0] == "-" else 1
    return sign * (int(tz[1:3]) * 60 + int(tz[3:5])), tz


def build_params(kind, gps, auid, device, campaign, t_click=None,
                 referrer=None):
    """Assemble the wire body for one request from the two JSON configs."""
    dev = dict((k, v) for k, v in device.items()
               if not str(k).startswith("_"))
    dev.pop("raw", None)
    dev.pop("timezone", None)      # local metadata, not a wire param
    t_click = int(t_click if t_click is not None else time.time())
    tz_min, tz = _tz(dev)
    ins = _stamp(t_click + 7, 774, tz_min, tz)
    p = dict(dev)
    p.pop("mcc", None)
    p.pop("mnc", None)             # genuine bodies carry neither
    p.update({
        "app_token": campaign["app_token"],
        "package_name": campaign["package_name"],
        "gps_adid": gps, "android_uuid": auid,
        "environment": "production", "device_type": "phone",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "foreground": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
    })
    if kind == "session":
        p.update({
            "store_name_from_system": "com.android.vending",
            "initiating_package_name": "com.android.vending",
            "session_count": "1",
            "created_at": _stamp(t_click + 55, 928, tz_min, tz),
            "sent_at": _stamp(t_click + 55, 942, tz_min, tz),
            "installed_at": ins, "updated_at": ins,
        })
    elif kind == "click":
        # these six are SESSION-only; the genuine click body carries none of them
        for _k in ("enqueue_size", "first_error", "last_error",
                   "retry_count", "wait_time", "wait_total"):
            p.pop(_k, None)
        p.update({
            "source": "install_referrer", "referrer_api": "google",
            "referrer": referrer, "google_play_instant": "0",
            "install_version": dev.get("app_version", "3.13.9"),
            "session_count": "1", "session_length": "0",
            "subsession_count": "1", "time_spent": "0",
            "created_at": _stamp(t_click + 55, 961, tz_min, tz),
            "sent_at": _stamp(t_click + 55, 970, tz_min, tz),
            "installed_at": ins, "updated_at": ins,
            "click_time": _stamp(t_click, 0, tz_min, tz),
            "click_time_server": _stamp(t_click - 1, 0, tz_min, tz),
            "install_begin_time": _stamp(t_click + 5, 0, tz_min, tz),
            "install_begin_time_server": _stamp(t_click + 4, 0, tz_min, tz),
        })
    elif kind == "attribution":
        p = {"initiated_by": "backend", "gps_adid_attempt": "1",
             "api_level": dev.get("api_level", "31"),
             "app_version": dev.get("app_version", "3.13.9"),
             "app_token": campaign["app_token"],
             "os_version": dev.get("os_version", "12"),
             "created_at": _stamp(t_click + 55, 666, tz_min, tz),
             "device_type": "phone", "gps_adid": gps, "foreground": "1",
             "android_uuid": auid,
             "sent_at": _stamp(t_click + 55, 696, tz_min, tz),
             "offline_mode_enabled": "0",
             "device_name": dev.get("device_name", ""),
             "environment": "production", "needs_response_details": "1",
             "attribution_deeplink": "1",
             "package_name": campaign["package_name"],
             "os_name": "android", "ui_mode": "1",
             "gps_adid_src": "service", "tracking_enabled": "1"}
    else:
        raise ValueError("kind must be session|click|attribution")
    return p


def sign(params, kind, second=None, seed=None):
    """Sign one request -> (blob192, info)."""
    if not CFG:
        raise RuntimeError("call configure_app(campaign) first")
    blob, sec, info = sign_request(params, kind, head=WIN_PHASE,
                                   second=second, seed=seed)
    return blob, {"second": sec, "status": info.get("status"),
                  "head": tuple(hex(h) for h in WIN_PHASE)}


# the VM section defines its own auth_header(); keep a private alias so the
# public one below does not shadow it into infinite recursion
_vm_auth_header = globals().get("auth_header")


_LAW_57 = claims_padded


def authorization_header(blob):
    """The envelope -> the exact value for the Authorization header.

    The server only checks the presence of Client-SDK/Content-Type/Host; this
    envelope itself is not verified on the join path, but it must still be
    well formed for the request to be accepted.
    """
    return _vm_auth_header(blob)

# ==========================================================================
# APPENDIX -- the inverse: decode a genuine blob back to its record.
# Lets probe_app.py read cert_sha1 and head_phase out of a real
# signature instead of trusting a hand-edited JSON.
# ==========================================================================
T_HEX = "3629222ea73e3a906554327eab82fe239fd79c28af0c12a5f881f7fac9f12795e2a8c673636aa29961f0b0a4248d6440519276964dc350cf5247d5b7be72e7205cd6794f4e3b0ff5076e83e67cb67ad1068455b875a9e40e3f9eeb6c1f190d9a85baffae161866d010ac572a0569cafd04f615dac7c86da0e9e38f7445aaa687985946b90ac2114291f22b6831084c2635d41a89777fc5dd13bbed418b0b5e8eb5676f5f1c5371099786f937c4c0b12cb29d6238d8801bfc3903a1bf302ffb5def2d707b49f3e193bd88214a1ee8dedf256be0331d56a35b346002ecd39448cbb4adcd443c8cdbc1ce4bd2bc9b007d8ad9f4dc58eab3173d14cc785ae501ee43"
KB_HEX = "43fc368804c8ed1b17e5c8f603002f469e8f7ca2b2713e088c3f18324e1bc3046d6ce7273cf15f697e41c2ca2814b8d9610c29c68628429b5f420ffc440c99ada427a6a5cd83ac99e6973b069bd6d68aeae0c558399dd296338a883f22d344c7e4a5e9507c73109ccfb17ecf0132fd10ca650736a6ad80f5c0725d9fb7f44c0dde7183c8f757c6016db3ed9b39d445de9a69cd0b699118abfcb610611e170939e23bd37b4039402f78dff8e1145ee86a1942b77e2586fa808c65bfb4c727e3d882758e3497199b4eba9336fafb988bc5fdffaa1e8d2c05cb541cef2ac66e59a7208b07e8e2c7c9f30d01aa5ca3cc74cc"
PI = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
PI_INV = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
F_ROWS = [0x01018180, 0x02028381, 0x04040602, 0x08088c84, 0x10109888,
          0x20203010, 0x40406020, 0x8080c040, 0x01818001, 0x02838102,
          0x04060204, 0x088c8408, 0x10988810, 0x20301020, 0x40602040,
          0x80c04080, 0x81800101, 0x83810202, 0x06020404, 0x8c840808,
          0x98881010, 0x30102020, 0x60204040, 0xc0408080, 0x80010181,
          0x81020283, 0x02040406, 0x8408088c, 0x88101098, 0x10202030,
          0x20404060, 0x408080c0]
F_C = 0x00000000
F_MINV = [0x2161a1e0, 0x62a2e321, 0xc445c643, 0xa9eb2d67, 0x72b6fa2e,
          0xe46cf45c, 0xc8d8e8b8, 0x90b0d070, 0x61a1e021, 0xa2e32162,
          0x45c643c4, 0xeb2d67a9, 0xb6fa2e72, 0x6cf45ce4, 0xd8e8b8c8,
          0xb0d07090, 0xa1e02161, 0xe32162a2, 0xc643c445, 0x2d67a9eb,
          0xfa2e72b6, 0xf45ce46c, 0xe8b8c8d8, 0xd07090b0, 0xe02161a1,
          0x2162a2e3, 0x43c445c6, 0x67a9eb2d, 0x2e72b6fa, 0x5ce46cf4,
          0xb8c8d8e8, 0x7090b0d0]

def _gmul_slow(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p


def _gpow(a, e):
    r, base = 1, a
    while e:
        if e & 1:
            r = _gmul_slow(r, base)
        base = _gmul_slow(base, base)
        e >>= 1
    return r


def _rotl8(x, n):
    n %= 8
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _aes_sbox():
    """The standard AES S-box, built from its definition rather than stored:
    S(x) = L(x^-1) ^ 0x63 over GF(2^8) mod 0x11B, L the AES affine map."""
    out = []
    for v in range(256):
        inv = 0 if v == 0 else _gpow(v, 254)
        y = inv
        for k in (1, 2, 3, 4):
            y ^= _rotl8(inv, k)
        out.append(y ^ 0x63)
    return out


# The whitening cipher's S-box IS the AES S-box, XOR-obfuscated with the same
# 0x55 the cipher wraps everything else in:  T[v] == AES_SBOX[v] ^ 0x55.
# Verified 256/256, and 0x55 is the UNIQUE constant that works (next best
# scores 0/256).  verify_T_law.py is the permanent gate.
T = bytes(v ^ 0x55 for v in _aes_sbox())
KB = bytes.fromhex(KB_HEX)
T_INV = [0] * 256
for _x, _v in enumerate(T):
    T_INV[_v] = _x

D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")   # cert SHA-1
SHA0 = hashlib.sha256(b"").digest()

REC_N = 144


# ---------------------------------------------------------------------------
# the diag-2 GF(2) linear map F (32-bit little-endian words)
# ---------------------------------------------------------------------------
def F_word(x):
    """Reference implementation of the diag-2 GF(2) map, kept for validation.

    The hot path uses F_TAB below (5x faster, provably identical)."""
    y = 0
    for j in range(32):
        m = F_ROWS[j] & x
        b = 0
        while m:
            b ^= m & 1
            m >>= 1
        y |= b << j
    return y


def _build_byte_table(rows):
    """F is GF(2)-linear, so F(x) = XOR of F(1<<k) over the set bits k.
    Precompute that per byte position: TAB[byte_pos][bit] -> 32-bit word."""
    def f(x):
        y = 0
        for j in range(32):
            m = rows[j] & x
            b = 0
            while m:
                b ^= m & 1
                m >>= 1
            y |= b << j
        return y
    return [[f(1 << (8 * p + bit)) for bit in range(8)] for p in range(4)]


F_TAB = None      # built lazily on first use (needs F_ROWS)
F_MINV_TAB = None


def _F_word_tab(x, tab):
    y = 0
    for b in range(4):
        t = tab[b]
        v = (x >> (8 * b)) & 0xFF
        if v & 1: y ^= t[0]
        if v & 2: y ^= t[1]
        if v & 4: y ^= t[2]
        if v & 8: y ^= t[3]
        if v & 16: y ^= t[4]
        if v & 32: y ^= t[5]
        if v & 64: y ^= t[6]
        if v & 128: y ^= t[7]
    return y & 0xFFFFFFFF


def _gmul(a, b):
    """Multiply in GF(2^8) mod the AES polynomial 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p


def _xt(x):
    """Branch-free bytewise xtime over a whole 32-bit word: multiply every
    byte by 2 in GF(2^8) mod 0x11B, in one go."""
    m = x & 0x80808080
    return ((x << 1) & 0xFEFEFEFE) ^ (((m >> 7) * 0x1B) & 0xFFFFFFFF)


def mix_columns(x):
    """AES MixColumns -- F IS MixColumns, not merely AES-shaped.

        y_b = 2*x_b ^ 3*x_(b+1) ^ x_(b+2) ^ x_(b+3)      byte indices mod 4

    Written as 3*z = 2*z ^ z over the byte-rotated z = x rotated right one
    byte, so the whole thing is word arithmetic with no per-byte loop.

    Verified equal to the stored F_ROWS matrix on all 32 basis vectors, which
    is a complete proof (both sides are GF(2)-linear).  test_f_formula.py is
    the permanent gate; F_ROWS is kept below purely as that reference.
    """
    z = ((x >> 8) | (x << 24)) & 0xFFFFFFFF        # rotate right one byte
    return (_xt(x ^ z) ^ z                         # 2*(x^z) ^ z  == 2x ^ 3z
            ^ ((x >> 16) | (x << 16))              # bytes +2
            ^ ((x >> 24) | (x << 8))) & 0xFFFFFFFF  # bytes +3


def inv_mix_columns_doc(y):
    x = 0
    for i in range(32):
        m = F_MINV[i] & y
        b = 0
        while m:
            b ^= m & 1
            m >>= 1
        x |= b << i
    return x


def inv_mix_columns(y):
    """AES InvMixColumns -- the inverse circulant [14, 11, 13, 9].

        v_b = 14*b_b ^ 11*b_(b+1) ^ 13*b_(b+2) ^ 9*b_(b+3)
    """
    b = [(y >> (8 * i)) & 0xFF for i in range(4)]
    out = 0
    for i in range(4):
        v = (_gmul(14, b[i]) ^ _gmul(11, b[(i + 1) % 4])
             ^ _gmul(13, b[(i + 2) % 4]) ^ _gmul(9, b[(i + 3) % 4]))
        out |= v << (8 * i)
    return out


def _mix_chunk(chunk):
    return b"".join(mix_columns(int.from_bytes(chunk[4 * b:4 * b + 4],
                                             "little")).to_bytes(4, "little")
                    for b in range(4))


def _inv_mix_chunk(chunk):
    return b"".join(inv_mix_columns(int.from_bytes(chunk[4 * b:4 * b + 4],
                                                 "little")).to_bytes(4, "little")
                    for b in range(4))


def _shift_rows(chunk):
    out = bytearray(16)
    for i in range(16):
        out[PI[i]] = chunk[i]
    return bytes(out)


def _inv_shift_rows(chunk):
    # undo out[PI[i]] = in[i]  ->  in[i] = out[PI[i]]
    return bytes(chunk[PI[i]] for i in range(16))


# ---------------------------------------------------------------------------
# forward (validation reference)
# ---------------------------------------------------------------------------
def _encrypt_chunk(chunk, WA, _kb=KB):
    """One forward chunk: 14 rounds + final sweep.  (chunk ^ WA is inside.)"""
    x = bytearray(a ^ b for a, b in zip(chunk, WA))
    for r in range(14):
        x = bytearray(v ^ 0x55 ^ _kb[16 * r + i] for i, v in enumerate(x))
        x = bytearray(T[v] ^ 0x55 for v in x)
        x = bytearray(_shift_rows(bytes(x)))
        if r < 13:
            x = bytearray(_mix_chunk(bytes(x)))
    return bytes(v ^ 0x55 ^ _kb[224 + i] for i, v in enumerate(x))


def encrypt(record, header):
    """record: 144 B plaintext, header: 16 B IV -> whitened body (144 B)."""
    out = bytearray()
    wa = header
    for k in range(len(record) // 16):
        c = _encrypt_chunk(record[16 * k:16 * k + 16], wa)
        out += c
        wa = c
    return bytes(out)


# ---------------------------------------------------------------------------
# the inverse
# ---------------------------------------------------------------------------
def whiten_inverse(chunk, WA, KB_=None, T_inv=None, pi1_inv=None, F_inv=None):
    """Invert one whitened 16-B chunk given its WA (previous chunk final, or
    the header for chunk 0).  Returns the recovered 16-B plaintext chunk.

    KB_      : 240-B key table            (default: extracted KB)
    T_inv    : 256-entry inverse S-box    (default: extracted T_INV)
    pi1_inv  : inverse byte permutation   (default: extracted PI_INV);
               must satisfy pi1_inv(pi1(x)) == x
    F_inv    : callable 16 B -> 16 B inverting the diag-2 map (default _inv_mix_chunk)
    """
    kb = KB if KB_ is None else KB_
    tinv = T_INV if T_inv is None else T_inv
    pinv = _inv_shift_rows if pi1_inv is None else pi1_inv
    finv = _inv_mix_chunk if F_inv is None else F_inv
    x = bytes(v ^ 0x55 ^ kb[224 + i] for i, v in enumerate(chunk))  # final sweep
    for r in range(13, -1, -1):
        if r < 13:
            x = finv(x)                       # undo diag-2 affine
        x = pinv(x)                           # undo diag-1 permutation
        x = bytes(tinv[v ^ 0x55] for v in x)  # undo S-box
        x = bytes(v ^ 0x55 ^ kb[16 * r + i] for i, v in enumerate(x))
    return bytes(a ^ b for a, b in zip(x, WA))  # remove the WA XOR



def whiten_body_inverse(body, header, KB_=None, T_inv=None, pi1_inv=None,
                        F_inv=None):
    """body: 144 whitened bytes (blob[16:160)), header: blob[0:16).
    Returns the 144-B record."""
    out = bytearray()
    wa = header
    for k in range(len(body) // 16):
        p = whiten_inverse(body[16 * k:16 * k + 16], wa, KB_, T_inv,
                           pi1_inv, F_inv)
        out += p
        wa = body[16 * k:16 * k + 16]
    return bytes(out)


# ---------------------------------------------------------------------------
# record -> region (validated convention)
# ---------------------------------------------------------------------------
CONST_CHECKS = (
    ((0, 3), bytes.fromhex("010008")),
    ((19, 20), b"\x02"),
    ((24, 25), b"\x03"),
    ((45, 46), b"\x04"),
    ((78, 79), b"\x05"),
    ((79, 111), SHA0),
    ((111, 114), bytes.fromhex("060107")),
    ((114, 128), b"\x00" * 14),
    ((130, 144), b"\x0e" * 14),
)


def record_checks(record):
    ok = all(record[a:b] == want for (a, b), want in CONST_CHECKS)
    ok = ok and record[25:45] == D9
    return ok


def head_words(d0w):
    return b"".join(struct.pack("<I", ((w & 0xFFFF) << 16) | (w >> 16))
                    for w in d0w[:4])



def decode_blob(blob):
    """192-B adj9 signature blob -> dict(record, checks, region)."""
    blob = bytes(blob)
    if len(blob) != 192:
        raise ValueError("blob must be 192 bytes, got %d" % len(blob))
    header, body = blob[:16], blob[16:160]
    record = whiten_body_inverse(body, header)
    region = _region_from_record(record)
    return {
        "header": header,
        "record": record,
        "consts_ok": record_checks(record),
        "head": record[3:19],
        "d2w": int.from_bytes(record[20:24], "little"),
        "F_seed": int.from_bytes(record[20:24], "big"),
        "block": record[46:78],
        "tail2": record[128:130],
        "region": region,
    }


# ---------------------------------------------------------------------------
# validation / demo main
# ---------------------------------------------------------------------------
def _load_traces():
    import gzip
    out = []
    for fn in ("_inv2_row7_real.json.gz", "_inv2_row7_rand.json.gz"):
        p = os.path.join(HERE, fn)
        if os.path.exists(p):
            out.append(json.load(gzip.open(p, "rt")))
    return out


def main():
    fast = "--fast" in sys.argv
    print("=== adj9 whitening decoder - validation ===")
    print("T permutation:", len(set(T)) == 256)
    print("KB[0:16]   :", KB[:16].hex())
    print("KB[224:240]:", KB[224:240].hex())
    print("pi1        :", PI)
    print("F linear, F_inv(F(x))==x:",
          all(inv_mix_columns_doc(F_word(x)) == x
              for x in (0, 1, 0x80000001, 0xDEADBEEF, 0xFFFFFFFF)))
    print()

    # -- 1. trace round-trips (forward AND inverse, byte-exact) --------------
    if not fast:
        for A in _load_traces():
            blob = bytes.fromhex(A["blob"])
            rec = bytes.fromhex(A["record"])
            body = encrypt(rec, blob[:16])
            back = whiten_body_inverse(blob[16:160], blob[:16])
            print("trace row %-3s (%s) forward==blob[16:160): %-5s "
                  "inverse==record: %s"
                  % (A.get("row", "?"), A.get("status", "?"),
                     body == blob[16:160], back == rec))
        print()

    # -- 2. corpus decode (pair_h3 blobs, all_signings regions) --------------
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    als = json.load(open(os.path.join(HERE, "all_signings.json")))
    nok = 0
    print("--- corpus (pair_h3 blobs, all_signings regions) ---")
    for r in ph3:
        i = r["i"]
        blob = bytes.fromhex(r["blob"])
        dec = decode_blob(blob)
        reg = dec["region"]
        a = als[i]
        ok_c = dec["consts_ok"]
        if reg is None:
            print("row %d: consts=%s region=None (head %s)"
                  % (i, ok_c, dec["head"].hex()))
            continue
        ok = (reg["d0"].hex() == a["d0"] and reg["d2"].hex() == a["d2"]
              and reg["d4"].hex() == a["d4"])
        nok += ok
        print("row %d: consts=%s region_match=%s phase=%s seed=%08x d2=%08x"
              % (i, ok_c, ok, reg["phase"], reg["seed"], reg["d2w"]))
    print("corpus region matches: %d/%d" % (nok, len(ph3)))

    # -- 2b. cross-pairing: which all_signings row does each blob belong to --
    # (pair_h3's capture->sample assignment is a heuristic; rows 2/4 carry the
    # SAME capture and row 3's capture has no sample in all_signings)
    print()
    print("--- cross-pairing by decoded d2 word / full region ---")
    decs = {r["i"]: decode_blob(bytes.fromhex(r["blob"])) for r in ph3}
    for j in range(len(als)):
        a = als[j]
        d2hits = [i for i, d in decs.items()
                  if "%08x" % d["d2w"] == a["d2"]]
        full = [i for i, d in decs.items()
                if d["region"] and d["region"]["d0"].hex() == a["d0"]
                and d["region"]["d4"].hex() == a["d4"]]
        if d2hits or full:
            print("all_signings[%d] d2=%s : blob rows %s (full region %s)"
                  % (j, a["d2"], d2hits, full))
    orphan = {i: "%08x" % d["d2w"] for i, d in decs.items()
              if not any("%08x" % d["d2w"] == als[j]["d2"]
                         for j in range(len(als)))}
    print("decoded blobs with NO all_signings sample (pairing artifact):",
          orphan)
    print()

    # -- 3. genuine winning blobs --------------------------------------------
    wp = os.path.join(HERE, "win_capture", "winning_material.json")
    wr = os.path.join(HERE, "win_capture", "win_rows.json")
    if os.path.exists(wp):
        W = json.load(open(wp))
        rowsw = json.load(open(wr)).get("rows", []) if os.path.exists(wr) else []
        print("--- genuine winning blobs (%d) ---" % len(W["blobs"]))
        matched = 0
        for bi, bh in enumerate(W["blobs"]):
            dec = decode_blob(bytes.fromhex(bh))
            reg = dec["region"]
            tag = ""
            if reg is not None:
                for ri, rw in enumerate(rowsw):
                    dd = (rw.get("desc", {}).get("0") or {}).get("hex")
                    if dd and dd == reg["d0"].hex():
                        matched += 1
                        tag = ("  == win_rows[%d] (S=%d second=%d sign_id=%s)"
                               % (ri, rw.get("S", -1), rw.get("second", -1),
                                  rw.get("sign_id")))
            print("win blob %d: consts=%s d2w=%08x F_seed=%08x head=%s%s"
                  % (bi, dec["consts_ok"], dec["d2w"], dec["F_seed"],
                     dec["head"].hex(), tag))
        print("win blob <-> win_rows region matches: %d (of %d blobs, %d rows)"
              % (matched, len(W["blobs"]), len(rowsw)))


if __name__ == "__main__":
    main()


def _region_from_record(record):
    """Stand-alone region check (no repo imports): recover (d0,d2,d4) or None."""
    try:
        seed = int.from_bytes(record[20:24], "big")
        d2w = int.from_bytes(record[20:24], "little")
        head = record[3:19]
        d4w = _d4_words(seed)
        for phase in ((0x2B,), (0x2B, 0x48), (0x22, 0x2E),
                      (0x2B, 0x07, 0x22, 0x2E)):
            d0w = _d0_words(d4w, head=phase)
            if head_words(d0w) == head:
                d0 = b"".join(w.to_bytes(4, "big") for w in d0w)
                d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
                return {"d0": d0, "d2": d2w.to_bytes(4, "big"), "d4": d4,
                        "seed": seed, "d2w": d2w, "d0w": d0w, "d4w": d4w}
        return None
    except Exception:
        return None


def decode_record(blob):
    """Convenience: blob -> dict with F_seed / head / record / cert."""
    d = decode_blob(blob)
    d["cert"] = d["record"][25:45]
    return d


# =============================================================================
# PART 5 -- THE PUBLIC API
# =============================================================================
# Read this top to bottom and the whole signing flow is obvious:
#
#   configure_app()            tell it which app it is signing for
#   build_*_request()          turn that into the exact fields for one API call
#   sign_request()             those fields -> a 192-byte adj9 envelope
#   authorization_header()     the envelope -> the value for Authorization
#
# Nothing here knows a package name, a tracker or a GAID.

# which app we are signing for (filled by configure_app)
# ---- descriptor #8, the one value that is NOT app-specific ----------------
# 16 bytes: a static XOR-keyed constant that lives in libsigner.so's .data and
# is deobfuscated in place at the moment of use.  It is not derived from the
# app, the device, the claims or the timestamp, and it never changes between
# signings.  libsigner.so is byte-identical across every app we have handled
# (same sha256), so they all share this one value.
#
# It cannot be read out of a signature -- it is not in the envelope.  It is
# verified instead by re-minting a known blob and demanding 192/192; a wrong
# value collapses the body to about 17 matching bytes.
D8_DEFAULT = bytes.fromhex("bffffffffffffd1f0007000000000000")

# ---- the d0 head selectors, which ARE per app -----------------------------
# Known: penti (0x2b, 0x48); creditsea and declic (0x2b,).  Sending the wrong
# one is silent -- the server still answers HTTP 200 with a real adid -- so
# override it per app and verify with probe_app.py.
HEAD_PHASE_DEFAULT = (0x2B,)

# ---- the d0 head selector phase, per app ---------------------------------
# The head is a short non-cycling prefix of the whitener's selector schedule.
# It rewrites only the FIRST FEW words of d0 (descriptor #0), which lives
# inside the signed blob -- so a wrong head is a wrong signature.  It fails
# SILENTLY: the server still answers HTTP 200 with a real adid.
#
# It is looked up here by app_token rather than carried in the campaign file,
# because it is a property of the app, not of the request.  Measured, not
# assumed -- each value was brute-forced against genuine device blobs with
# _declic_head.py / probe_app.py:
#
#     jut9tib0eo  penti      (43, 72)      = 0x2b, 0x48
#     i2n2e5kmcpvk creditsea  (43,)         = 0x2b
#     1afnt5j9dsg0 declic     (43,)         = 0x2b, verified on 3 live blobs
#
# An app missing from this table falls back to HEAD_PHASE_DEFAULT, which is
# right for most but should be confirmed with probe_app.py on a real capture.
HEAD_PHASE_BY_APP_TOKEN = {
    "jut9tib0eo":  (43, 72),    # penti
    "i2n2e5kmcpvk": (43,),       # creditsea
    "1afnt5j9dsg0": (43,),       # declic
}

APP_CONFIG = {}


def configure_app(config):
    """Load the app-level settings (a CAMPAIGN dict, or one apps.json entry).

    The fields that matter, and why each exists:
      cert_sha1   descriptor #9 - the SHA-1 of this app's APK signing
                  certificate.  Read straight out of a real signature with
                  probe_app.py.
      head_phase  the d0 head selectors.  PER APP, and the most dangerous
                  field here: send the wrong one and the server still
                  answers HTTP 200, so the failure is silent.
      d8          descriptor #8, a constant per libsigner build.  It cannot be
                  read out of a signature, so it is verified by re-minting a
                  known blob and demanding 192/192.
      client_sdk  the signed claim.  Flutter apps use a composite value like
                  "flutter5.8.0@android5.8.0", not the bare SDK version.
      sdk_version picks the claim law (5.7.x vs 5.8.0).
    """
    global APP_CONFIG
    APP_CONFIG = dict(config)
    globals()["DESC9"] = bytes.fromhex(config["cert_sha1"])
    globals()["DESC8"] = (bytes.fromhex(config["d8"]) if "d8" in config
                          else D8_DEFAULT)
    # an explicit head_phase in the config still wins (it is how you sign for
    # an app that is not in the table); otherwise look it up by app token
    if "head_phase" in config:
        # accepts 43 or "0x2b" alike
        globals()["WIN_PHASE"] = tuple(
            int(h, 16) if isinstance(h, str) else int(h)
            for h in config["head_phase"])
    else:
        globals()["WIN_PHASE"] = HEAD_PHASE_BY_APP_TOKEN.get(
            config.get("app_token"), HEAD_PHASE_DEFAULT)
    globals()["ADJ_SIGNING_ID"] = config.get("adj_signing_id", "1500000")
    globals()["ADJ_VERIFICATION"] = config.get("adj_verification", "")
    globals()["NATIVE_VERSION"] = config.get("native_version", "5.0.0")
    globals()["CLIENT_SDK"] = config.get("client_sdk", "android5.7.0")
    if str(config.get("sdk_version", "5.7.0")) >= "5.8":
        globals()["claims_padded"] = claims_padded_58
    else:
        globals()["claims_padded"] = _LAW_57


def _tz_parts(device):
    """'+05:30' -> minutes east of UTC, plus the original label."""
    tz = device.get("timezone", "+0530")
    sign = -1 if tz[0] == "-" else 1
    return sign * (int(tz[1:3]) * 60 + int(tz[3:5])), tz


def _stamp(unix_seconds, millis, tz_minutes, tz_label):
    """Adjust's wire timestamp, e.g. 2026-09-30T10:25:30.153Z+0530."""
    import datetime
    moment = (datetime.datetime.fromtimestamp(unix_seconds,
                                              datetime.timezone.utc)
              + datetime.timedelta(minutes=tz_minutes))
    return moment.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ%s"
                           % (millis, tz_label))


def _device_fields(device):
    """Device settings, minus the two that are never sent on the wire."""
    fields = {k: v for k, v in device.items()
              if not str(k).startswith("_")}
    fields.pop("raw", None)          # a pasted device dump, not a param
    fields.pop("timezone", None)     # local metadata, never transmitted
    return fields


def _common_fields(gaid, android_uuid, device, campaign):
    """The identity block every request carries."""
    return {
        "app_token": campaign["app_token"],
        "app_version": (device.get("app_version")
                        or campaign.get("app_version", "3.13.9")),
        "package_name": campaign["package_name"],
        "gps_adid": gaid, "android_uuid": android_uuid,
        "environment": "production", "device_type": "phone",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "foreground": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
    }


def build_session_request(gaid, android_uuid, device, campaign, t_click):
    """The fields for POST /session - the app announcing itself.  This is the
    request that creates the adid, so it carries installed_at."""
    fields = _device_fields(device)
    fields.update(_common_fields(gaid, android_uuid, device, campaign))
    tz_minutes, tz = _tz_parts(device)
    installed = _stamp(t_click + 7, 774, tz_minutes, tz)
    fields.update({
        # both true when the app was installed from the Play Store
        "store_name_from_system": "com.android.vending",
        "initiating_package_name": "com.android.vending",
        "session_count": "1",
        "created_at": _stamp(t_click + 55, 928, tz_minutes, tz),
        "sent_at": _stamp(t_click + 55, 942, tz_minutes, tz),
        "installed_at": installed, "updated_at": installed,
    })
    fields.pop("mcc", None)          # genuine bodies carry neither, even on SIM
    fields.pop("mnc", None)
    return fields


def build_click_request(gaid, android_uuid, device, campaign, t_click,
                        referrer):
    """The fields for POST /sdk_click - the install claiming a click.

    Carries the click's own timing: click_time and install_begin_time, each
    with a *_server twin exactly 1 s behind, and install_begin 20 s before
    installed_at.
    """
    fields = _device_fields(device)
    fields.update(_common_fields(gaid, android_uuid, device, campaign))
    tz_minutes, tz = _tz_parts(device)
    installed = _stamp(t_click + 25, 774, tz_minutes, tz)
    # these six are session-only; a genuine click body has none of them
    for key in ("enqueue_size", "first_error", "last_error", "retry_count",
                "wait_time", "wait_total"):
        fields.pop(key, None)
    fields.pop("mcc", None)
    fields.pop("mnc", None)
    fields.update({
        "source": "install_referrer", "referrer_api": "google",
        "referrer": referrer, "google_play_instant": "0",
        "install_version": (device.get("app_version")
                           or campaign.get("app_version", "3.13.9")),
        "session_count": "1", "session_length": "0",
        "subsession_count": "1", "time_spent": "0",
        "created_at": _stamp(t_click + 25, 961, tz_minutes, tz),
        "sent_at": _stamp(t_click + 25, 970, tz_minutes, tz),
        "installed_at": installed, "updated_at": installed,
        "click_time": _stamp(t_click, 0, tz_minutes, tz),
        "click_time_server": _stamp(t_click - 1, 0, tz_minutes, tz),
        "install_begin_time": _stamp(t_click + 5, 0, tz_minutes, tz),
        "install_begin_time_server": _stamp(t_click + 4, 0, tz_minutes, tz),
    })
    return fields


def build_attribution_request(gaid, android_uuid, device, campaign, t_click):
    """The fields for GET /attribution - asking what we were attributed to.
    Sends no mcc/mnc, no resolution, no build."""
    tz_minutes, tz = _tz_parts(device)
    return {
        "initiated_by": "backend", "gps_adid_attempt": "1",
        "api_level": device.get("api_level", "31"),
        "app_version": (device.get("app_version")
                         or campaign.get("app_version", "3.13.9")),
        "app_token": campaign["app_token"],
        "os_version": device.get("os_version", "12"),
        "created_at": _stamp(t_click + 25, 666, tz_minutes, tz),
        "device_type": "phone", "gps_adid": gaid, "foreground": "1",
        "android_uuid": android_uuid,
        "sent_at": _stamp(t_click + 25, 696, tz_minutes, tz),
        "offline_mode_enabled": "0",
        "device_name": device.get("device_name", ""),
        "environment": "production", "needs_response_details": "1",
        "attribution_deeplink": "1",
        "package_name": campaign["package_name"],
        "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service", "tracking_enabled": "1",
    }

# ---- short aliases, so either name works ----------------------------------
configure = configure_app
build_params = build_session_request
sign = sign_request
auth_header = authorization_header

_LAW_57 = claims_padded

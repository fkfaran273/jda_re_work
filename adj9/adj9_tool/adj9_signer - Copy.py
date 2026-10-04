"""adj9_signer.py -- the COMPLETE adj9 signature algorithm in one file.

Everything needed to turn a claims map into the 192-byte adj9 envelope and the
`Authorization` header, with no dependency on the rest of the research tree.

    from adj9_signer import mint_blob, auth_header
    blob = mint_blob(claims_map, kind="click", second=int(time.time()))
    hdr  = auth_header(blob)          # -> Signature signature="..."

What is in here
---------------
1. `Random3` / `make_header`  -- the 16-byte header PRNG (36/36 corpus).
2. `region(V, pid)`           -- descriptors #0/#2/#4, the per-call entropy.
3. desc10 law                 -- descriptor #10: which claims, in what order.
4. the VM (`Ex`, `FinStream`, `FinEx`) -- the native serializer at 0x100094,
   lifted instruction by instruction, which turns descriptors into the body.
5. `build_descriptors` / `mint_blob` -- the glue.

The only external requirements are `capstone` (the VM disassembles the real
libsigner.so) and the .so itself, located by `find_libsigner()`.

VERIFIED, and worth stating plainly because it is easy to assume otherwise:
the envelope does NOT depend on the Keystore HMAC `H`.  The region is a pure
function of a 4-byte seed that descriptor #2 fully determines -- #0 and #4 are
recoverable from #2 alone on 6/6 genuine device captures.  So `H` is an
authentication input to the native signer, not a body field, and nothing here
takes it.
"""
import base64
import os
import re
import struct
import sys
import time

# --- locate libsigner.so (the VM disassembles it at import time) ------------
def find_libsigner():
    """Find libsigner.so. Override with the ADJ9_LIB env var."""
    env = os.environ.get("ADJ9_LIB")
    if env and os.path.exists(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.path.join(here, "libsigner.so"),
        os.path.join(here, "..", "..", "extracted", "arm64", "lib",
                     "arm64-v8a", "libsigner.so"),
        os.path.join(here, "..", "extracted", "arm64", "lib",
                     "arm64-v8a", "libsigner.so"),
        r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib"
         r"\arm64-v8a\libsigner.so",
    ]
    for c in cands:
        c = os.path.abspath(c)
        if os.path.exists(c):
            return c
    raise FileNotFoundError(
        "libsigner.so not found. Set ADJ9_LIB to its full path. Tried:\n  "
        + "\n  ".join(cands))


LIB = find_libsigner()
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    raise SystemExit("adj9_signer needs capstone:  pip install capstone")


class _Elf:
    """Minimal ELF vaddr->offset reader (the repo's elf.py, inlined)."""
    def __init__(self, path):
        import struct as _s
        self.d = open(path, "rb").read()
        e = self.d
        if e[:4] != b"\x7fELF":
            raise ValueError("not an ELF: %s" % path)
        self.phoff = _s.unpack_from("<Q", e, 0x20)[0]
        self.phentsize = _s.unpack_from("<H", e, 0x36)[0]
        self.phnum = _s.unpack_from("<H", e, 0x38)[0]
        self.segments = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            p_type, p_flags = _s.unpack_from("<II", e, o)
            p_offset, p_vaddr = _s.unpack_from("<QQ", e, o + 0x08)
            p_filesz = _s.unpack_from("<Q", e, o + 0x20)[0]
            if p_type == 1:                      # PT_LOAD
                self.segments.append((p_vaddr, p_vaddr + p_filesz, p_offset))

    def vaddr_to_off(self, va):
        for lo, hi, off in self.segments:
            if lo <= va < hi:
                return off + (va - lo)
        raise ValueError("vaddr 0x%x not in any PT_LOAD" % va)


# ---------------------------------------------------------------- Random3 / header
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

# ---------------------------------------------------------------- region F(V,pid)


_MASK31 = 0x7FFFFFFF
_MASK16 = 0xFFFF
_MASK32 = 0xFFFFFFFF

# Whitener heads (0x1441e4 x1 sequence) by signing ordinal in the process.
# Byte-exact 36/36 on 7/7 genuine real-spawn captures (rows_full + rows_control):
# sign_id 1-2 -> HEAD_FIRST, sign_id 3+ -> HEAD_RESIGN.
HEAD_FIRST = (0x2B, 0x22, 0x25, 0x2E)            # 2b 22 25 2e
HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E)     # 2b 07 22 25 2e


def head_for_sign_id(sign_id: int):
    """Whitener head for a signing ordinal (1-based) within the process."""
    return HEAD_FIRST if sign_id <= 2 else HEAD_RESIGN


def head_for_kind(kind):
    """Whitener head for a request kind.

    session/sdk_click are the first two signings (H4); attribution and any
    re-sign are ordinal 3+ (H5).  ``kind`` here is the endpoint name; the
    ordinal mapping is confirmed byte-exact on 7/7 genuine real-spawn rows.
    """
    return head_for_sign_id(1 if str(kind).lower() in ("session", "click", "sdk_click") else 3)


def _step(x: int) -> int:
    """One step of the 31-bit Schrage PRNG at 0x13dfd0."""
    if x == 0:
        x = 0x075BD924
    q = x // 0x1F31D
    y = (x - q * 0x1F31D) * 0x41A7 - q * 0x0B14
    if y < 0:
        y += _MASK31
    return y & _MASK31


def _raw16(seed: int) -> list[int]:
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
    raw = _transpose16(_raw16(seed))
    packed = b"".join(x.to_bytes(2, "little") for x in raw)
    return [int.from_bytes(packed[i:i + 4], "big") for i in range(0, 32, 4)]


def _whitener_word(x1: int, source: list[int], initial: int = 0) -> int:
    """Replay one 0x144074 call.

    The native builds the mask as ((x1 << 1) + 3) & 0xffff (lsl 0x144078,
    add 0x1440c0, and 0x1440ec) and then runs SIXTEEN iterations -- the loop
    bound is `cmp x9, #0x10` at 0x1441cc, and the source is
    `ctx + 0x10 + 2*(15-bit)`.  Each set bit b loads that halfword and xors it
    into the running value (ldrh 0x14418c / eor 0x14419c / strh 0x1441a4).

    `initial` is x2 on entry, which the caller uses as the destination slot
    AND as the starting recurrence state.  The 72 ordinary calls pass the slot
    index, so value starts at the slot, not at zero.

    This used to loop only 8 times and start at 0, which silently corrupted
    every ordinary output: all eight ordinary masks (0x83..0x91) have bit 7
    set, so the truncation changed every single word.
    """
    mask = ((x1 << 1) + 3) & _MASK16
    value = initial & _MASK16
    for bit in range(16):
        if (mask >> bit) & 1:
            value ^= source[15 - bit]
    return value & _MASK16


def _d0_words(d4: list[int], head=None) -> list[int]:
    """Descriptor #0: 36 big-endian words from the 72-call whitener.

    The 72 ordinary calls (0x1439ac, `cmp x22, #0x48`) each use
    x1 = 0x40 | (slot & 7) (the bfxil at 0x143a30) but pass x2 = slot
    (0x143a34).  x2 is both the destination slot and the initial value the
    XOR accumulation starts from -- so the value entering the loop is the
    slot index, NOT zero.  Passing it is what makes the recurrence a
    recurrence.

    The `head` entries are the tail-call x1 operands replayed through the
    selector at 0x1441e4; they overwrite the leading slots after the
    ordinary pass.  Their exact per-signing sequence is control-flow
    dependent (see the note below).
    """
    d4_bytes = b"".join(word.to_bytes(4, "big") for word in d4)
    # The native reads ctx+0x10 + 2*(15-bit) for bit 0..15, i.e. all sixteen
    # little-endian halfwords of d4.  This used to slice only the top half
    # (range(16,32,2), eight entries) to match the old 8-bit loop.
    source = [int.from_bytes(d4_bytes[i:i + 2], "little") for i in range(0, 32, 2)]

    # Ordinary pass: x1 cycles 0x40..0x47, initial value = slot.
    values = [_whitener_word(0x40 | (i & 7), source, i) for i in range(72)]

    # Tail calls: the selector (0x143b20) finds the first slot whose ordinary
    # output still equals the 8-entry table, then the wrapper (0x1441e4)
    # tail-calls the whitener with that slot as x2.
    if head:
        table = values[:8]
        for x1 in head:
            slot = next((i for i in range(72) if values[i] == table[i & 7]), 72)
            value = _whitener_word(x1, source, slot)
            if slot < 72:
                values[slot] = value
            else:
                table[0] = value

    raw = b"".join(value.to_bytes(2, "little") for value in values)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 144, 4)]


def new_seed() -> int:
    """A fresh 32-bit signing seed, exactly as the native gets one.

    The native wrapper at 0x143794 reads 8 bytes from /dev/urandom
    (openat/read/close in 0x13e0e4) and takes the first four as a
    little-endian u32.  Nothing about the seed is derived from the request,
    the clock, the process id or a counter -- so it cannot be predicted, and
    must not be guessed.
    """
    return int.from_bytes(os.urandom(8)[:4], "little")


def region(seed: int = None, head=None):
    """Return ``(d0, d2, d4)`` as descriptor words for one signing.

    seed : the 32-bit signing seed.  Defaults to fresh /dev/urandom entropy,
           which is what the native does for every signing.  Pass an explicit
           value only to replay a known signing.
    head : ignored (accepted for source compatibility).  The whitener tail-call
           operands are produced by the live native VM and captured directly;
           they cannot be supplied from Python (the _d0_words head model does
           not reproduce them).

    The old signature was region(V, pid) and derived the seed as
    V ^ ((pid & 0xffff) << 16).  That is refuted by the native: the only
    caller of the entropy helper passes just the context pointer, and the
    wrapper that consumes it takes `ldr w1, [sp]` straight from the random
    buffer.  Because the seed is random per signing, no captured body is
    reproducible -- which is why sweeping V never matched.

    d0 is the POST-HEAD value (ordinary phase-1 d0 with the live head-call
    prefix slots replaced), captured from the real libsigner.so signing path
    under Unicorn.  Phase-1 (ordinary) d0 alone is provably insufficient --
    a live test signed with it was still attributed Organic.
    """
    if seed is None:
        seed = new_seed()
    seed &= _MASK32
    # Produce the POST-HEAD d0 (and d4, d2) from the real native signer.  The
    # Python 72-call whitener model in _d0_words does NOT reproduce either the
    # native d0 or the post-head prefix replacement, so the server's recompute
    # would not match and the click is not credited.  We raise on failure
    # rather than silently falling back to the wrong Python d0.
    from native_d0 import posthead_region_native
    d0, d2, d4 = posthead_region_native(seed)
    return d0, d2, d4

# ---------------------------------------------------------------- desc10 law
# desc10_law.py - the PROVEN unified desc10 law (slice 96): byte-exact for
# session + click vs the device's own captures. Shared by law tests and forge.
#   desc10 = sorted(profile claims A-Z) + adj_signing_id (pinned)
#          + sorted(session claims A-Z)
#          + [activity_kind, client_sdk, headers_id, native_version]
PROFILE_COMMON = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
    'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
    'gps_adid_src', 'hardware_name', 'installed_at', 'os_build', 'os_name',
    'os_version', 'package_name',
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


def desc10_keys(kind, val=None):
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


def build_desc10(val, kind):
    """val: dict key->string value (all law keys must be present, non-empty).
    Returns the exact byte string the native packs into descriptor #10."""
    keys = desc10_keys(kind, val)
    missing = [k for k in keys if k not in val or val[k] in (None, '')]
    if missing:
        raise KeyError('desc10 law missing values: %s' % missing)
    return ''.join(val[k] for k in keys)


# --- corpus-proven descriptor constants -------------------------------------
D8_HEX = "bffffffffffffd1f0007000000000000"      # #8: 16-B constant
D9_HEX = "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"  # #9: APK cert SHA-1

# ---------------------------------------------------------------- VM core (Ex)


elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
INS = list(md.disasm(elf[0x100094:0x12aa48], 0x100094))
IDX = {i.address: k for k, i in enumerate(INS)}
# second executable range: output assembly fn (slice 17/33). Bounds via ELF.
try:
    from elf import ELF as _ELF

    _e = _ELF(LIB)
    _o = _e.vaddr_to_off(0x99000)
    _INS0 = list(md.disasm(_e.data[_o:_o + 0xBB548 - 0x99000], 0x99000))
    _base = len(INS)
    INS.extend(_INS0)
    for _k, _i in enumerate(_INS0):
        IDX[_i.address] = _base + _k
    try:
        _o3 = _e.vaddr_to_off(0x146000)
        _INS3 = list(md.disasm(_e.data[_o3:_o3 + 0x3000], 0x146000))
        _base3 = len(INS)
        INS.extend(_INS3)
        for _k, _i in enumerate(_INS3):
            IDX[_i.address] = _base3 + _k
    except Exception:
        pass
    _o = _e.vaddr_to_off(0xBB548)
    _INS2 = list(md.disasm(_e.data[_o:_o + 0xBCA30 - 0xBB548], 0xBB548))
    _base = len(INS)
    INS.extend(_INS2)
    for _k, _i in enumerate(_INS2):
        IDX[_i.address] = _base + _k
except Exception:
    pass

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

def pt(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

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
    def __init__(self, seed, descs, n_streams=16, shared_q=False):
        self._shared_q = shared_q
        self.R = {}
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
        self.R["x29"] = X29
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
        # register entry state
        self.R["x19"] = W
        self.R["x20"] = CTX
        self.R["x23"] = 0
        self.R["x22"] = 0
        self.R["w26"] = len(descs)
        self.R["x21"] = 0
        self.R["x26"] = 11   # arg count (w2)
        self.R["x28"] = CTX
        self.R["x27"] = 0
        self.R["x27"] = 0
        self.pc = 0x100114


    def set_reg(self, name, val):
        """write a register with true ARM64 x/w aliasing (NOT invalidation):
        xN <- V64 (wN = low32); wN <- V32 (xN = zero-extended)."""
        if name in ("wzr", "xzr", "sp"):
            if name == "sp": self.R["sp"] = val
            return
        if len(name) >= 2 and name[0] in "wx" and name[1:].isdigit():
            n = name[1:]
            if name[0] == "x":
                self.R["x" + n] = val & (2**64 - 1)
                self.R["w" + n] = val & 0xFFFFFFFF
            else:
                v32 = val & 0xFFFFFFFF
                self.R["w" + n] = v32
                self.R["x" + n] = v32
            return
        self.R[name] = val & (2**64 - 1)

    # ---- memory ----
    def ld(self, va, size=8):
        va &= PM
        va &= ~7 if size == 8 else ~3
        v = self.mem.get(va, 0)
        return v
    def st(self, va, v, size=8):
        va &= PM
        self.mem[va & (~7 if size == 8 else ~3)] = v & (2**64 - 1)
        if self.__dict__.get("_storelog") is not None and len(self._storelog) < 5000:
            self._storelog.append((hex(self.pc), hex(va & 0xFFFFFFFFFFFF)))

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
        while self.steps < max_steps:
            self.steps += 1
            self._pc_hist[self.pc] += 1
            pre = self.__dict__.get("_preload", {})
            if self.pc in pre and pre[self.pc]:
                qva = self.mem.get(self.CTX, 0)
                self.queues.setdefault(qva, [])[0:0] = list(pre[self.pc])
            fr = self.__dict__.get("_forcereg", {})
            if self.pc in fr:
                for rn, vv in fr[self.pc]:
                    self.set_reg(rn, vv)
            k = IDX.get(self.pc)
            if k is None: return "pc-out"
            if self.pc in (0xBBB14,):
                self.__dict__.setdefault("_bbb14", []).append(
                    tuple(self.R.get("x%d" % n, 0) for n in range(10)) + (self.R.get("x19", 0), self.R.get("x20", 0)))
            if self.pc == 0x9C4C0:
                self.__dict__.setdefault("_9c4c0", []).append(
                    tuple(self.R.get("x%d" % n, 0) for n in range(5)) + (self.R.get("x8", 0), self.R.get("x9", 0)))
                self.__dict__.setdefault("_b8a0", []).append(
                    (self.R.get("x10", 0), self.R.get("sp", 0),
                     self.mem.get((self.R.get("sp", 0) + 0x50) & ~7, -1)))
            if self.pc == 0xBB668 and len(self.__dict__.get("_hublog", [])) < 500:
                self.__dict__.setdefault("_hublog", []).append(self.R.get("x9", 0))
                seq = self.__dict__.get("_hubseq", [])
                if seq:
                    self.set_reg("x9", seq.pop(0))
                if len(self.__dict__.get("_hublog", [])) == 7:
                    self.__dict__["_roll7"] = list(self.__dict__.get("_roll", []))
                if len(self.__dict__.get("_hublog", [])) in (5, 6):
                    self.__dict__["_roll%d" % len(self.__dict__.get("_hublog", []))] = list(self.__dict__.get("_roll", []))
            if self.pc == 0xBA674 and len(self.__dict__.get("_mazelog", [])) < 1000:
                self.__dict__.setdefault("_mazelog", []).append(
                    (self.R.get("x8", 0), self.R.get("x9", 0), self.R.get("x20", 0)))
            if 0xBA000 <= self.pc < 0xBC000 and INS[k].mnemonic in ("ldr", "ldur", "ldp", "ldrb", "ldrsw", "ldrsh", "ldrsb"):
                self.__dict__.setdefault("_loads", []).append(self.pc)
            i = INS[k]
            m, ops = i.mnemonic, i.op_str
            npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                w = self
                if len(w.__dict__.get("_calls", [])) < 2000:
                    w.__dict__.setdefault("_calls", []).append(
                        (hex(self.pc), hex(t) if t else ops,
                         tuple(w.R.get("x%d" % n, 0) & 0xFFFFFFFF for n in range(5)),
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
                        a = (w.R.get("x29", 0) + off) & (2**64 - 1)
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
                    qva = w.R.get("x1", 0)
                    w.queues.setdefault(qva, []).insert(0, w.R.get("w2", 0) & 0xFFFFFFFF)
                    w.__dict__.setdefault("_qlog", []).append(
                        (hex(self.pc), "PUSH", hex(qva & 0xFFFF), w.R.get("w2", 0) & 0xFFFFFFFF, len(w.queues[qva])))
                elif t in (OP_POP, OP_POP2):
                    qva = w.R.get("x1", 0)
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
                            w.mem.__setitem__(w.R.get("x19", 0), 3)
                            w.set_reg("w0", 0)
                    w.__dict__.setdefault("_qlog", []).append(
                        (hex(self.pc), "POP", hex(qva & 0xFFFF), w.R.get("w0", 0), len(w.queues.get(qva, []))))
                elif t == OP_EMIT:
                    s = w.stream_for(w.R.get("x1", 0))
                    n = w.R.get("w2", 0); v = w.R.get("w3", 0)
                    s.emit(n, v, self.pc)
                    w.emit_trace.append((s.va, n, v))
                    if len(w.__dict__.get("_slog", [])) < 400:
                        w.__dict__.setdefault("_slog", []).append(
                            (hex(self.pc), "EMIT", hex(s.va & 0xFFFFF)))
                elif t == OP_LENQ:
                    s = w.stream_for(w.R.get("x0", 0))
                    n = w.R.get("w1", 0) & 0xFFFFFFFF
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
                    s = w.stream_for(w.R.get("x0", 0))
                    acc = w.mem.get(s.va + 0x10, 0) & 0xFFFFFFFF
                    top = s.data[-1] if s.data else 0
                    w.set_reg("w0", (acc - top) & 0xFFFFFFFF)
                elif t == OP_PUSHS:
                    s = w.stream_for(w.R.get("x1", 0))
                    s.offs.append(w.R.get("w1", 0) & 0xFFFFFFFF)
                elif t == OP_POPS:
                    s = w.stream_for(w.R.get("x1", 0))
                    if len(s.offs) > 1: s.offs.pop()
                elif t == OP_MKITER:
                    nva = 0x5800000000 + (w.__dict__.get("_nit", 0)) * 0x100
                    w._nit = w.__dict__.get("_nit", 0) + 1
                    w.iters.append({"va": nva, "i": 0, "n": w.R.get("w2", 0)})
                    w.set_reg("w0", nva)
                    w.__dict__.setdefault("_mkiter", []).append(
                        (hex(self.pc), w.R.get("w2", 0)))
                elif t == OP_ITERNEXT:
                    va = w.R.get("x0", 0)
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
                    qva = w.R.get("x0", 0) or w.R.get("x1", 0)
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
                    qva = w.R.get("x1", 0)
                    q = w.queues.setdefault(qva, [])
                    top = q[0] if q else None
                    if top is None or (top & 0xFFFFFFFF) >= 0x10000:
                        q.insert(0, w.R.get("x21", 0) & 0xFFFFFFFF)
                # stack_chk / free / calloc etc: no-op (legacy). Heap mode
                # (live replay, slice 74): real bump allocator + byte ops.
                elif t in (0x148B10, 0x148B90) and w.__dict__.get("_heap") is not None:
                    n = w.R.get("x0", 0)
                    if t == 0x148B90:
                        n *= w.R.get("x1", 0)
                    n = (n + 15) & ~15
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    va = w._heap[0]
                    w._heap[0] = va + max(n, 16)
                    w._heap[1][va] = max(n, 16)
                    w.set_reg("x0", va)
                elif t == 0x148BA0 and w.__dict__.get("_heap") is not None:
                    d, s, n = (w.R.get("x%d" % i, 0) & 0x00FFFFFFFFFFFFFF for i in range(3))
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    for k in range(n):
                        w.stbyte(d + k, w.ldbyte(s + k))
                elif t == 0x148A20 and w.__dict__.get("_heap") is not None:
                    d = w.R.get("x0", 0) & 0x00FFFFFFFFFFFFFF
                    w2, n = w.R.get("x1", 0) & 0xFF, w.R.get("x2", 0)
                    for k in range(n):
                        w.stbyte(d + k, w2)
                elif t == 0x148C80 and w.__dict__.get("_heap") is not None:
                    # realloc(ptr, size): bump new, copy min(old,new).
                    old = w.R.get("x0", 0) & 0x00FFFFFFFFFFFFFF
                    n = (w.R.get("x1", 0) + 15) & ~15
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
                    s = w.R.get("x0", 0) & 0x00FFFFFFFFFFFFFF
                    n = 0
                    while w.ldbyte(s + n) != 0 and n < 0x10000:
                        n += 1
                    w.set_reg("x0", n)
            elif m == "blr":
                # indirect call (JNI through tables, callbacks): log args,
                # treat as no-op returning 0 (mapping runs; slice 69).
                # _blrret override {pc: value} for live replay (slice 73+).
                self.__dict__.setdefault("_calls", []).append(
                    (hex(self.pc), "blr:" + ops.split()[0],
                     tuple(self.R.get("x%d" % n, 0) & 0xFFFFFFFF for n in range(9))))
                ov = self.__dict__.get("_blrret", {})
                self.set_reg("x0", ov.get(self.pc, 0))
            elif m == "csel":
                p = [x.strip() for x in ops.split(",")]
                self.set_reg(p[0], self.R.get(p[1], 0) if self.F.get(p[3], False)
                             else self.R.get(p[2], 0))
            elif m == "cset":
                p = [x.strip() for x in ops.split(",")]
                self.set_reg(p[0], 1 if self.F.get(p[1], False) else 0)
            elif m == "ccmp":
                # ccmp Xn, #imm, #nzcv, cond: if cond true, set flags as cmp
                p = [x.strip() for x in ops.split(",")]
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
                    self.set_reg(d, (self.R.get(d, 0) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr", "rev", "rev16", "neg", "mvn"):
                p = [x.strip() for x in ops.split(",")]
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
                p = [x.strip() for x in ops.split(",")]
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
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1])
                if self.val(p[0]) == 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1])
                if self.val(p[0]) != 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "tbz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1]); bit = pt(p[1])
                if not (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318: return "exit-clean"
                        npc = t
            elif m == "tbnz":
                p = [x.strip() for x in ops.split(",")]
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
                self.mem_op(i)
            elif m in ("mrs",):
                self.R[i.op_str.split(",")[0].strip()] = 0x1000
            elif m in ("stp",):
                pass
            self.pc = npc
            self.__dict__.setdefault("_roll", []).append(self.pc)
            if len(self._roll) > 60: del self._roll[:30]
            if len(self.emit_trace) == 300:
                self.__dict__["_runaway_path"] = list(self._roll)
            if self.pc == 0x100120:
                self.__dict__.setdefault("_t120", []).append(self.R.get("x8"))
            if self.pc == 0x10014c:
                self.__dict__.setdefault("_t14c", []).append((self.R.get("x8"), self.R.get("x27")))
        return "steps"

    def val(self, s):
        s = s.strip()
        if s in ("wzr", "xzr", "sp"): return self.R.get("sp", 0) if s == "sp" else 0
        if s.startswith("#"): return pt(s) or 0
        if s in self.R: return self.R[s]
        # xN <-> wN aliasing
        if len(s) >= 2 and s[0] in "wx" and s[1:].isdigit():
            other = ("w" if s[0] == "x" else "x") + s[1:]
            if other in self.R:
                v = self.R[other]
                return v & 0xFFFFFFFF if s[0] == "w" else v
        # register + shift forms like 'w0, uxtw #3' handled by caller
        base = s.split(",")[0].strip()
        if base in self.R:
            v = self.R[base]
            mm = re.search(r"(uxtw|sxtw|lsl) #(\d+)", s)
            if mm:
                sh = int(mm.group(2))
                if mm.group(1) == "lsl": v = (v << sh) & (2**64 - 1)
                else: v = (v & 0xFFFFFFFF) << sh if mm.group(1) == "uxtw" else v
            return v
        try: return int(s, 0)
        except ValueError: return 0

    def mem_op(self, i):
        m, ops = i.mnemonic, i.op_str
        # parse: ldr Xt, [Xn{, #imm}{, ...}] (+ writeback !)
        mm = re.match(r"^([wx]\d+|\w+\d*),\[([wx]\d+|sp)(?:,(#?[-0-9x]+))?\](!?)", ops.replace(" ", ""))
        if not mm:
            # stp/ldp pair
            mm2 = re.match(r"^(\w+),(\w+),\[([wx]\d+|sp)(?:,(#?-?[\dx]+))?\](!?)", ops.replace(" ", ""))
            if mm2 and m in ("stp", "ldp"):
                d1, d2, base, imm, wb = mm2.group(1), mm2.group(2), mm2.group(3), mm2.group(4), mm2.group(5)
                bv = self.R.get(base, 0)
                off = int(imm.lstrip('#'), 0) if imm else 0
                addr = (bv + off) & (2**64 - 1)
                if m == "stp":
                    self.st(addr, self.R.get(d1, 0))
                    self.st(addr + 8, self.R.get(d2, 0))
                else:
                    self.set_reg(d1, self.ld(addr))
                    self.set_reg(d2, self.ld(addr + 8))
                if wb == "!":
                    self.set_reg(base, (bv + off) & (2**64 - 1))
                    # post/pre semantics: '!' pre-index: base += off
                    if off: self.set_reg(base, addr)
                return
            # ldr Xt, [Xn, Xm{, lsl #k}] indexed
            mm3 = re.match(r"^(\w+),\[(\w+)\],(#?-?[\dx]+)$", ops.replace(" ", ""))
            if mm3:   # post-index
                d, base, imm = mm3.group(1), mm3.group(2), int(mm3.group(3), 0)
                bv = self.R.get(base, 0)
                self.set_reg(d, self.ld(bv))
                self.set_reg(base, (bv + imm) & (2**64 - 1))
                return
            mm4 = re.match(r"^(\w+),\[(\w+),(\w+)(?:,(uxtw|lsl)#(\d+))?\]", ops.replace(" ", ""))
            if mm4:   # register-indexed
                d, base, idx, _, sh = mm4.group(1), mm4.group(2), mm4.group(3), mm4.group(4), int(mm4.group(5) or 0)
                bv = self.R.get(base, 0)
                iv = self.R.get(idx, 0) & 0xFFFFFFFF
                addr = (bv + (iv << sh)) & (2**64 - 1)
                v = self.ld(addr, 4 if d.startswith("w") else 8)
                self.set_reg(d, v)
                return
            return
        d, base, imm, wb = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
        imm = imm.strip() if imm else "0"
        try:
            off = int(imm.replace("#", ""), 0)
        except ValueError:
            off = 0
        if off is None: off = 0
        bv = self.R.get(base, 0)
        addr = (bv + off) & (2**64 - 1)
        size = 4 if (d.startswith("w") or m in ("ldrb", "strb", "ldrsw")) else 8
        if m in ("str", "stur", "strb"):
            self.st(addr, self.R.get(d, 0), 4 if m == "strb" else size)
        elif m in ("stp",):
            pass
        else:
            v = self.ld(addr, 8 if size == 8 else 4)
            self.set_reg(d, v)
            if m in ("ldrsw", "ldursw"):
                v32 = v & 0xFFFFFFFF
                self.set_reg(d, v32 - 2**32 if v32 >= 2**31 else v32)
        if wb == "!":
            self.set_reg(base, addr)

# ---------------------------------------------------------------- VM streams + FinEx
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
        for i, (lendl, tag, data) in enumerate(descs):
            dva = 0x5700000000 + i * 0x400
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
            self.mem[self.R.get("x19", 0)] = 4
            return
        q[0], q[k] = q[k], q[0]          # swap head value with node[k] value

    def cap_push(self, qva, k):
        q = self.queues.setdefault(qva, [])
        if len(q) <= k:
            self.mem[self.R.get("x19", 0)] = 4
            return
        q.insert(0, q[k])                # push a copy of node[k]'s value

    def mem_op(self, i):
        if i.mnemonic == "ldrh":
            super().mem_op(i)
            d = i.op_str.split(",")[0].strip()
            if d in self.R:
                self.set_reg(d, self.R[d] & 0xFFFF)
            return
        super().mem_op(i)

    def run(self, max_steps=4_000_000):
        R, F, mem = self.R, self.F, self.mem
        _hook = self.__dict__.get("_step_hook")
        while self.steps < max_steps:
            self.steps += 1
            if _hook is not None:
                _hook(self)
            if self.__dict__.get("_pc_log") is not None:
                self._pc_log.append(self.pc)
            k = IDX.get(self.pc)
            if k is None:
                return "pc-out"
            if self.pc == 0x100164 and self.__dict__.get("_dbg164") is not None:
                self._dbg164.append((R.get("x21"), R.get("x22"), self.steps))
            i = INS[k]
            m, ops = i.mnemonic, i.op_str
            npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                if t in (OP_PUSH, OP_PUSH2):
                    qva = R.get("x1", 0)
                    self.queues.setdefault(qva, []).insert(0, R.get("w2", 0) & 0xFFFFFFFF)
                    if self.__dict__.get("_qop_log") is not None:
                        self._qop_log.append(("PUSH", i.address, R.get("w2", 0) & 0xFFFFFFFF))
                elif t in (OP_POP, OP_POP2):
                    qva = R.get("x1", 0)
                    q = self.queues.get(qva)
                    if q:
                        R["w0"] = q.pop(0)
                        R["x0"] = R["w0"]
                    else:
                        mem[R.get("x19", 0)] = 3
                        R["w0"] = 0
                        R["x0"] = 0
                    if self.__dict__.get("_qop_log") is not None:
                        self._qop_log.append(("POP", i.address, R.get("w0", 0) & 0xFFFFFFFF))
                elif t == OP_EMIT:
                    s = self.stream_for(R.get("x1", 0))
                    n = R.get("w2", 0)
                    v = R.get("w3", 0)
                    s.emit(n, v)
                    self.emit_trace.append((s.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_emit_pc") is not None:
                        self._emit_pc.append((i.address, s.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                elif t == OP_LENQ:
                    s = self.stream_for(R.get("x0", 0))
                    R["w0"] = s.lenq(R.get("w1", 0))
                    R["x0"] = R["w0"]
                    if self.__dict__.get("_lenq_log") is not None:
                        self._lenq_log.append((i.address, s.va, R.get("w1", 0) & 0xFFFFFFFF,
                                               s.top[-1], R["w0"]))
                elif t == OP_OUTLEN:
                    s = self.stream_for(R.get("x0", 0))
                    R["w0"] = s.outlen()
                    R["x0"] = R["w0"]
                elif t == OP_PUSHS:
                    s = self.stream_for(R.get("x1", 0))
                    if self.__dict__.get("_sp_log") is not None:
                        self._sp_log.append(("PUSHS", i.address, s.va, s.acc, list(s.top)))
                    s.pushs()
                elif t == OP_POPS:
                    s = self.stream_for(R.get("x1", 0))
                    if self.__dict__.get("_sp_log") is not None:
                        self._sp_log.append(("POPS", i.address, s.va, s.acc, list(s.top)))
                    err = s.pops()
                    if err:
                        mem[R.get("x19", 0)] = err
                elif t in CAP_SWAPS:
                    if self.__dict__.get("_cap_log") is not None:
                        q = self.queues.get(R.get("x1", 0), [])
                        self._cap_log.append(("SW", i.address, len(q), R.get("w2", 0), list(q[:6])))
                    self.cap_swap(R.get("x1", 0), R.get("w2", 0) & 0xFFFFFFFF)
                elif t in CAP_PUSHS:
                    kk = 0 if t == 0x147a18 else (R.get("w2", 0) & 0xFFFFFFFF)
                    # 0x147a18 = thunk: mov w2,wzr; b 0x14784c  (CAP push, k:=0)
                    if self.__dict__.get("_cap_log") is not None:
                        q = self.queues.get(R.get("x1", 0), [])
                        self._cap_log.append(("PU", i.address, len(q), kk, list(q[:6])))
                    self.cap_push(R.get("x1", 0), kk)
                elif t == OP_MKITER:
                    # native MKITER(x0=writer, x1=head_cell, w2=n):
                    #   node = calloc(1,16); node[0]=n; node[8]=[x1]; [x1]=node
                    #   (alloc failure -> [writer]=2; cannot happen here)
                    # The nodes form a LIFO list through the head cell, so
                    # nested iterators nest correctly.
                    cell = R.get("x1", 0) & PM
                    nva = 0x5800000000 + (self.__dict__.get("_nit", 0)) * 0x100
                    self._nit = self.__dict__.get("_nit", 0) + 1
                    self.iters[nva] = {"count": R.get("w2", 0) & 0xFFFFFFFF,
                                       "next": self.mem.get(cell)}
                    self.mem[cell] = nva
                    R["w0"] = nva
                    R["x0"] = nva
                elif t == OP_ITERNEXT:
                    # native ITERNEXT(x0=head_cell):
                    #   node = [x0]; w21 = node.count - 1; node.count = w21
                    #   if w21 == 0: [x0] = node.next; free(node)
                    #   return w21    (caller loops with cbnz while non-zero)
                    cell = R.get("x0", 0) & PM
                    nva = self.mem.get(cell)
                    node = self.iters.get(nva) if nva is not None else None
                    if node is None:
                        R["w0"] = 0
                        R["x0"] = 0
                    else:
                        c = (node["count"] - 1) & 0xFFFFFFFF
                        node["count"] = c
                        if c == 0:
                            self.mem[cell] = node["next"]
                            self.iters.pop(nva, None)
                        R["w0"] = c
                        R["x0"] = c
                elif t == OP_ISEMPTY:
                    qva = R.get("x0", 0) or R.get("x1", 0)
                    R["w0"] = 1 if not self.queues.get(qva) else 0
                    R["x0"] = R["w0"]
                elif t == OP_RAND:
                    R["w0"] = self.rnd.next() & 0xFFFFFFFF
                    R["x0"] = R["w0"]
                    self.nrand += 1
                else:
                    # unknown bl: log it loudly, treat as no-op
                    self.__dict__.setdefault("_unk_bl", set()).add(hex(t or 0))
                    R["w0"] = R.get("w0", 0)
            elif m == "blr":
                self.set_reg("x0", 0)
            elif m == "csel":
                p = [x.strip() for x in ops.split(",")]
                self.set_reg(p[0], R.get(p[1], 0) if F.get(p[3], False)
                             else R.get(p[2], 0))
            elif m == "cset":
                p = [x.strip() for x in ops.split(",")]
                self.set_reg(p[0], 1 if F.get(p[1], False) else 0)
            elif m == "ccmp":
                p = [x.strip() for x in ops.split(",")]
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
                    self.set_reg(d, (R.get(d, 0) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr",
                       "rev", "rev16", "neg", "mvn", "udiv", "msub"):
                p = [x.strip() for x in ops.split(",")]
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
                p = [x.strip() for x in ops.split(",")]
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
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1])
                if self.val(p[0]) == 0 and t is not None:
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1])
                if self.val(p[0]) != 0 and t is not None:
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "tbz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1]); bit = pt(p[1])
                if not (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318:
                            return "exit-clean"
                        npc = t
            elif m == "tbnz":
                p = [x.strip() for x in ops.split(",")]
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
                self.mem_op(i)
            elif m == "mrs":
                R[i.op_str.split(",")[0].strip()] = 0x1000
            self.pc = npc
        return "steps"

region_fn = region


# ============================================================================
#  Public API
# ============================================================================
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]   # descriptor order into the VM
BLOB_WORDS = 48                                  # 48 x BE u32 = 192 bytes

ADJ_SIGNING_ID = "1500000"
CLIENT_SDK = "android5.7.0"
NATIVE_VERSION = "5.0.0"
ADJ_VERIFICATION = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"

# Claim keys the map carries internally; the HTTP form never carries them.
INTERNAL_CLAIMS = {
    "adj_verification": ADJ_VERIFICATION,
    "adj_signing_id": ADJ_SIGNING_ID,
    "client_sdk": CLIENT_SDK,
    "headers_id": "10",
    "native_version": NATIVE_VERSION,
}   # + activity_kind, taken from the kind itself


def claims_from_wire(params, kind):
    """Build the claims map from HTTP form params.

    Single source of truth: every claim equals the value that goes on the wire.
    Internal-only claims come from INTERNAL_CLAIMS.
    """
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
            else:
                val[k] = str(v)
    if missing:
        raise KeyError("claims_from_wire(%s): params missing %s"
                       % (kind, missing))
    return val


def _b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def build_descriptors(val, kind, region=None, seed=None, V=None, pid=None,
                      tid=None, d8_hex=None, d9_hex=None, head=None):
    """Assemble the 11 descriptors in VA_ORDER from a claims map + a region.

    region = (d0_words, d2, d4_words); if omitted it is derived from a fresh
    random signing seed via region().  d8/d9 default to the corpus-proven
    constants.  `head` selects the whitener tail-call operands.

    `V`/`pid` are accepted only for source compatibility and are IGNORED --
    the native seed does not depend on them.
    """
    del V, pid, tid
    if region is None:
        region = region_fn(seed, head=head)
    d0w, d2v, d4w = region

    raw10 = build_desc10(val, kind).encode("latin1")
    n10 = (len(raw10) + 3) // 4
    d10 = raw10 + b"\x00" * (-len(raw10) % 4)

    d8 = bytes.fromhex(d8_hex or D8_HEX)
    d9 = bytes.fromhex(d9_hex or D9_HEX)

    by = {
        0:  (36, _b(d0w)),
        9:  (5, d9),
        8:  (4, d8),
        4:  (8, _b(d4w)),
        2:  (1, _b([d2v])),
        7:  (1, _b([len(raw10)])),      # UNPADDED length
        10: (n10, d10),
        5:  (1, _b([0])),
        1:  (0, b""),
        6:  (1, _b([0])),
        3:  (0, b""),
    }
    return [(by[i][0], 0, by[i][1]) for i in VA_ORDER]


def make_V(sec=None, usec=None):
    """V = tv_sec ^ tv_usec at the fill instant (not transmitted).

    IMPORTANT: `sec` MUST be the same second that is stamped into the
    transmitted created_at/sent_at.  A server that wants to recompute the
    region enumerates tv_usec inside that millisecond window, so a V built
    from a different second can never be reproduced and is a detectable tell.
    """
    if sec is None:
        t = time.time()
        sec, usec = int(t), int((t - int(t)) * 1_000_000)
    return (int(sec) ^ int(usec)) & 0xFFFFFFFF


def make_V_in_window(created_ms, sent_ms, sec=None):
    """Build a V whose (tv_sec, tv_usec) is consistent with the wire stamps.

    `created_ms`/`sent_ms` are the millisecond-of-second values actually put
    into created_at and sent_at, and `sec` is the Unix second those stamps
    denote.  We pick a tv_usec inside [created_ms, sent_ms] so the region is
    reproducible by anyone who reads the request -- which is exactly what the
    real device produces.
    """
    if sec is None:
        sec = int(time.time())
    lo = int(created_ms) * 1000
    hi = int(sent_ms) * 1000 + 999
    if hi < lo:
        lo, hi = hi, lo
    span = hi - lo
    # A real app fills the region between its two stamps; take the midpoint so
    # the value is not pinned to either edge of the window.
    usec = lo + (span // 2)
    return make_V(sec, usec)


DEFAULT_PID = 26530      # observed app pid; only the low 16 bits reach the seed
DEFAULT_TID = 0


def mint_blob(val, kind, second=None, seed=None, region=None,
              max_steps=40_000_000, d8_hex=None, d9_hex=None, head=None):
    """claims map + kind -> the 192-byte adj9 envelope (16-B header + body).

    Returns (blob_bytes, info).  info carries the step count, the exit status,
    the signing seed actually used, and the descriptor #10 sizes, so a caller
    can sanity-check the result.

    `seed` pins the signing seed; by default a fresh random one is drawn,
    which is what the native does.  `head` supplies the whitener tail-call
    operands (see _d0_words).
    """
    if second is None:
        second = int(time.time())
    second = int(second)
    if head is None:
        head = head_for_kind(kind)
    if region is None and seed is None:
        seed = new_seed()
    descs = build_descriptors(val, kind, region=region, seed=seed,
                              d8_hex=d8_hex, d9_hex=d9_hex, head=head)
    ex = FinEx(second, descs)
    st = ex.run(max_steps=max_steps)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(second))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    if stream is None:
        raise RuntimeError("VM produced no stream carrying the expected header")
    blob = b"".join(struct.pack(">I", out.get((stream, k), 0))
                    for k in range(BLOB_WORDS))
    raw10 = build_desc10(val, kind).encode("latin1")
    d2 = int.from_bytes((seed or 0).to_bytes(4, "little"), "big")
    return blob, {
        "status": st, "steps": ex.steps, "second": second, "stream": stream,
        "seed": seed, "d2": d2,
        "desc10_padded": len(raw10) + (-len(raw10) % 4),
        "desc10_unpadded": len(raw10),
    }


def auth_header(blob):
    """The Authorization header value for a minted envelope."""
    return ('Signature signature="%s",adj_signing_id="%s",'
            'algorithm="adj9",headers_id="10",native_version="%s",'
            'adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_SIGNING_ID,
               NATIVE_VERSION, ADJ_VERIFICATION))


def region_laws(d0b, d4b):
    """Structural laws every real region satisfies (advisory check).

      L1: some tile phase has U[2]^U[0] == R||R
      L2: d4[6]>>16 == R for one such R
      L3: d0[1] == U[3] at some phase

    A random region fails L1 with probability ~1-2**-16 per position.
    """
    d0 = struct.unpack(">36I", d0b)
    d4 = struct.unpack(">8I", d4b)
    hits = []
    for p in range(0, 32):
        x = d0[2 + p] ^ d0[4 + p]
        if (x >> 16) == (x & 0xFFFF):
            hits.append((p, x & 0xFFFF))
    return {
        "L1_tile_Rrep": bool(hits),
        "L1_hits": hits[:8],
        "L2_d4_6_hi_eq_R": any((d4[6] >> 16) == r for (_, r) in hits),
        "L3_X_eq_U3": any(d0[1] == d0[2 + p + 3] for (p, _) in hits),
    }


if __name__ == "__main__":
    import json
    sec = int(time.time())
    val = claims_from_wire({
        "api_level": "31", "app_token": "jut9tib0eeps", "app_version": "3.14.0",
        "gps_adid": "00000000-0000-0000-0000-000000000000",
        "android_uuid": "00000000-0000-0000-0000-000000000001",
        "created_at": "2026-09-24T12:00:00.000Z+0000",
        "sent_at": "2026-09-24T12:00:01.000Z+0000",
        "installed_at": "2026-09-24T11:59:00.000Z+0000",
        "updated_at": "2026-09-24T11:59:00.000Z+0000",
        "device_name": "moto g42", "device_type": "phone",
        "device_manufacturer": "motorola", "os_name": "android",
        "os_version": "12", "os_build": "S2SE32.28-28-4",
        "hardware_name": "S2SE32.28-28-4", "language": "tr",
        "package_name": "com.penti.app", "environment": "production",
        "gps_adid_src": "service", "session_count": "1",
        "store_name_from_system": "com.android.vending",
        "initiating_package_name": "com.android.vending",
        "tracking_enabled": "1", "connectivity_type": "1",
        "display_width": "1080", "display_height": "2237",
        "screen_size": "normal", "screen_density": "high",
        "screen_format": "long", "cpu_type": "arm64-v8a",
    }, "session")
    blob, info = mint_blob(val, "session", second=sec)
    print(json.dumps(info, indent=1))
    print("blob   :", blob.hex())
    print("header :", blob[:16].hex())
    print("body   :", blob[16:].hex())
    print("len    :", len(blob))
    print("auth   :", auth_header(blob)[:100], "...")

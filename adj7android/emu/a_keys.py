# Key-material hunt: two mints (different params+seconds), heap dumps +
# read-count maps; constant+read-heavy 32B windows = key candidates; each
# candidate tested by AES-256-CBC-decrypting emu body chunk 0 and checking
# for record-looking plaintext.
import sys, os, struct, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP, STACK, STACK_SZ
from unicorn import *
from unicorn.arm64_const import *
import unicodedata

OUT = os.path.dirname(os.path.abspath(__file__))

def mint(tag, params, second):
    e = Emu()
    counts = collections.Counter()
    def hr(uc, access, address, size, value, ud):
        counts[address] += 1
    e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=HEAP, end=HEAP + 0x1000000)
    out = e.run(payload=bytes(32), mapobj=params, second=second)
    heap = bytes(e.uc.mem_read(HEAP, e.brk - HEAP))
    open(os.path.join(OUT, "heap_%s.bin" % tag), "wb").write(heap)
    open(os.path.join(OUT, "blob_%s.bin" % tag), "wb").write(out)
    return out, heap, counts, e

P1 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "session", "client_sdk": "android5.6.0",
      "app_version": "3.0.4"}
P2 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "event", "client_sdk": "android5.6.0",
      "app_version": "9.9.9", "event_token": "abcdef"}

if not (os.path.exists(os.path.join(OUT, "heap_B.bin"))):
    outA, heapA, cntA, eA = mint("A", P1, 1791358552)
    print("A blob", outA[:16].hex(), len(heapA))
    import pickle
    pickle.dump(cntA, open(os.path.join(OUT, "cntA.pkl"), "wb"))
    outB, heapB, cntB, eB = mint("B", P2, 1791358553)
    print("B blob", outB[:16].hex(), len(heapB))
    pickle.dump(cntB, open(os.path.join(OUT, "cntB.pkl"), "wb"))
else:
    outA = open(os.path.join(OUT, "blob_A.bin"), "rb").read()
    heapA = open(os.path.join(OUT, "heap_A.bin"), "rb").read()
    outB = open(os.path.join(OUT, "blob_B.bin"), "rb").read()
    heapB = open(os.path.join(OUT, "heap_B.bin"), "rb").read()
    import pickle
    cntA = pickle.load(open(os.path.join(OUT, "cntA.pkl"), "rb"))
    cntB = pickle.load(open(os.path.join(OUT, "cntB.pkl"), "rb"))

n = min(len(heapA), len(heapB))
const = bytearray(n)
for i in range(n):
    const[i] = heapA[i] == heapB[i]

# aggregate read counts per 32B block over both mints
blk = collections.Counter()
for c in (cntA, cntB):
    per = collections.Counter()
    for addr, k in c.items():
        per[(addr - HEAP) >> 5] += k
    for b, k in per.items():
        blk[b] += k

cands = []
for b, k in blk.most_common(400):
    off = b * 32
    if off + 32 > n:
        continue
    if all(const[off:off + 32]):
        cands.append((off, k))
print("constant+read blocks:", len(cands))
for off, k in cands[:40]:
    w = heapA[off:off + 32]
    print("  +%#010x reads=%3d %s" % (off, k, w.hex()))

# ---- AES-256 decrypt test on each candidate (both plain and dword-swapped)
SBOX = None
def sbox():
    global SBOX
    if SBOX is None:
        # log-table GF(2^8) inverse + affine
        exp = [0]*512; log = [0]*256
        x = 1
        for i in range(255):
            exp[i] = x
            log[x] = i
            x ^= (x << 1) ^ (0x1B if x & 0x80 else 0)
            x &= 0xFF
        for i in range(255, 512):
            exp[i] = exp[i-255]
        sb = [0]*256
        for i in range(256):
            if i == 0:
                inv = 0
            else:
                inv = exp[255 - log[i]]
            b = inv
            r = inv
            for _ in range(4):
                b = ((b << 1) | (b >> 7)) & 0xFF
                r ^= b
            sb[i] = r ^ 0x63
        SBOX = sb
    return SBOX

INV_SBOX = None
def inv_sbox():
    global INV_SBOX
    if INV_SBOX is None:
        sb = sbox()
        INV_SBOX = [0]*256
        for i, v in enumerate(sb):
            INV_SBOX[v] = i
    return INV_SBOX

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40]

def expand256(key):
    ws = list(struct.unpack(">8I", key))
    for k in range(8, 60):
        t = ws[k-1]
        if k % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
            s = 0
            for sh in (24, 16, 8, 0):
                s |= sbox()[(t >> sh) & 0xFF] << sh
            t = s ^ (RCON[k//8 - 1] << 24)
        elif k % 8 == 4:
            s = 0
            for sh in (24, 16, 8, 0):
                s |= sbox()[(t >> sh) & 0xFF] << sh
            t = s
        ws.append(ws[k-8] ^ t)
    return ws

def dec_block(c, ws):
    # standard AES-256 decrypt of one 16B block
    def addrk(st, rk):
        return [st[i] ^ ((rk >> (24 - 4*i if i < 4 else 24 - 4*(i-4))) if False else 0) for i in range(16)]
    # simpler: work on 16-ble state with round keys as 4 words
    def xor_w(st, w4):
        st = st[:]
        for c in range(4):
            w = w4[c]
            st[4*c] ^= (w >> 24) & 0xFF
            st[4*c+1] ^= (w >> 16) & 0xFF
            st[4*c+2] ^= (w >> 8) & 0xFF
            st[4*c+3] ^= w & 0xFF
        return st
    IS = inv_sbox()
    def inv_shift_rows(st):
        o = [0]*16
        for c in range(4):
            for r in range(4):
                o[4*c + r] = st[4*((c - r) % 4) + r]
        return o
    # inverse MixColumns via gmul
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p
    def inv_mix(st):
        o = [0]*16
        for c in range(4):
            col = st[4*c:4*c+4]
            o[4*c+0] = gmul(col[0],14) ^ gmul(col[1],11) ^ gmul(col[2],13) ^ gmul(col[3],9)
            o[4*c+1] = gmul(col[0],9) ^ gmul(col[1],14) ^ gmul(col[2],11) ^ gmul(col[3],13)
            o[4*c+2] = gmul(col[0],13) ^ gmul(col[1],9) ^ gmul(col[2],14) ^ gmul(col[3],11)
            o[4*c+3] = gmul(col[0],11) ^ gmul(col[1],13) ^ gmul(col[2],9) ^ gmul(col[3],14)
        return o
    st = list(c)
    st = xor_w(st, ws[56:60])
    for rnd in range(13, 0, -1):
        st = inv_shift_rows(st)
        st = [IS[b] for b in st]
        st = xor_w(st, ws[4*rnd:4*rnd+4])
        st = inv_mix(st)
    st = inv_shift_rows(st)
    st = [IS[b] for b in st]
    st = xor_w(st, ws[0:4])
    return bytes(st)

def swap4(b):
    return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))

def looks(rec0):
    if not rec0:
        return False
    pr = sum(1 for x in rec0 if 32 <= x < 127)
    return rec0[0] in (0x7B, 0x20, 0x22) or pr >= 14

bodyA = outA[16:272]
headA = outA[:16]
tested = 0
hits = []
for off, k in cands[:200]:
    for form, key in (("plain", heapA[off:off+32]),
                      ("cc", bytes(b ^ 0xCC for b in heapA[off:off+32])),
                      ("sw", swap4(heapA[off:off+32])),
                      ("ccsw", swap4(bytes(b ^ 0xCC for b in heapA[off:off+32])))):
        try:
            ws = expand256(key)
        except Exception:
            continue
        tested += 1
        for cform, ct in (("plain", bodyA[:16]), ("sw", swap4(bodyA[:16]))):
            for ivf, iv in (("hdr", headA), ("sw", swap4(headA))):
                r = dec_block(ct, ws)
                rec0 = bytes(x ^ y for x, y in zip(r, iv))
                if looks(rec0):
                    hits.append((off, k, form, cform, ivf, rec0))
                    print("LOOKS GOOD off=%#x form=%s ct=%s iv=%s -> %r" %
                          (off, form, cform, ivf, rec0))
print("tested", tested, "candidates; hits:", len(hits))
if not hits:
    print("no AES hit — dumping top-12 constant+read blocks for manual review")
    for off, k in cands[:12]:
        print("  +%#x %s" % (off, heapA[off:off+64].hex()))

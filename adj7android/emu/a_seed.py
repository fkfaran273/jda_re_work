# SEED hunt: find the AES-256 generation key; verify strictly via
# rec0[:8] == '{ "a":  ' after AES-256(no-final-SB) decrypt of emu body chunk0.
# Scans: .so file, heap snapshots, post-mint .data/.bss dumps.
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import UcError

OUT = os.path.dirname(os.path.abspath(__file__))
so = open(r"..\apks\lib\hanaf\libsigner.so", "rb").read()
snapA = open(os.path.join(OUT, "snap2_A.bin"), "rb").read()
snapB = open(os.path.join(OUT, "snap2_B.bin"), "rb").read()
blobA = open(os.path.join(OUT, "blob_A.bin"), "rb").read()
bodyA, headA = blobA[16:272], blobA[:16]

# post-mint .data/.bss from a fresh emu
e = Emu()
out = e.run(payload=bytes(32), mapobj={"app_token": "smxi7gqwu39c",
           "package_name": "in.hanafintech", "activity_kind": "session",
           "client_sdk": "android5.6.0"}, second=1791358552)
libdata = bytes(e.uc.mem_read(BASE + 0x11bd80, 0x335a))
libbss = bytes(e.uc.mem_read(BASE + 0x11f0e0, 0xaa8))
print("post-mint .data/.bss dumped")

SBOX = None
def sbox():
    global SBOX
    if SBOX is None:
        exp = [0]*512; log = [0]*256
        x = 1
        for i in range(255):
            exp[i] = x; log[x] = i
            x ^= (x << 1) ^ (0x1B if x & 0x80 else 0); x &= 0xFF
        for i in range(255, 512): exp[i] = exp[i-255]
        sb = [0]*256
        for i in range(256):
            inv = 0 if i == 0 else exp[255 - log[i]]
            b = inv; r = inv
            for _ in range(4):
                b = ((b << 1) | (b >> 7)) & 0xFF; r ^= b
            sb[i] = r ^ 0x63
        SBOX = sb
    return SBOX
INV = None
def inv_sbox():
    global INV
    if INV is None:
        sb = sbox(); INV = [0]*256
        for i, v in enumerate(sb): INV[v] = i
    return INV
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40]

def expand256(key):
    ws = list(struct.unpack(">8I", key))
    for k in range(8, 60):
        t = ws[k-1]
        if k % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
            s = 0
            for sh in (24,16,8,0): s |= sbox()[(t >> sh) & 0xFF] << sh
            t = s ^ (RCON[k//8-1] << 24)
        elif k % 8 == 4:
            s = 0
            for sh in (24,16,8,0): s |= sbox()[(t >> sh) & 0xFF] << sh
            t = s
        ws.append(ws[k-8] ^ t)
    return ws

def gmul(a,b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def dec_nofinalSB(c, ws):
    # inverse of AES-256 whose final round lacks SubBytes:
    # forward: out = SR(s13) ^ K14  ->  in: st = c ^ K14; st = ISR(st);
    # then rounds 13..1 standard-inverse; round 0 addkey.
    # NOTE: careful — standard AES fwd: st = AK(s0,P); for r 1..13: SB,SR,MC,AK;
    # final r14: SB,SR,AK. Here final is SR,AK (no SB).
    # Decrypt: st = c^K14; st = ISR(st);  (undo SR)   [no inv-SB for r14]
    # for r = 13..1: st = IMC(st ^ K_r ... wait order: fwd r: SB->SR->MC->AK
    # inv: AK^-1=^K, MC^-1, SR^-1, SB^-1
    def xor_w(st, w4):
        st = st[:]
        for c_ in range(4):
            w = w4[c_]
            st[4*c_] ^= (w>>24)&0xFF; st[4*c_+1] ^= (w>>16)&0xFF
            st[4*c_+2] ^= (w>>8)&0xFF; st[4*c_+3] ^= w&0xFF
        return st
    IS = inv_sbox()
    def isr(st):
        o=[0]*16
        for c in range(4):
            for r in range(4):
                o[4*c+r] = st[4*((c-r)%4)+r]
        return o
    def imc(st):
        o=[0]*16
        for c in range(4):
            col=st[4*c:4*c+4]
            o[4*c+0]=gmul(col[0],14)^gmul(col[1],11)^gmul(col[2],13)^gmul(col[3],9)
            o[4*c+1]=gmul(col[0],9)^gmul(col[1],14)^gmul(col[2],11)^gmul(col[3],13)
            o[4*c+2]=gmul(col[0],13)^gmul(col[1],9)^gmul(col[2],14)^gmul(col[3],11)
            o[4*c+3]=gmul(col[0],11)^gmul(col[1],13)^gmul(col[2],9)^gmul(col[3],14)
        return o
    st = list(c)
    st = xor_w(st, ws[56:60])     # undo final AK (r14)
    st = isr(st)                  # undo final SR (no SB to undo)
    for rnd in range(13, 0, -1):
        st = xor_w(st, ws[4*rnd:4*rnd+4])
        st = imc(st)
        st = isr(st)
        st = [IS[b] for b in st]
    st = xor_w(st, ws[0:4])
    return bytes(st)

def swap4(b):
    return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))

PREFIX = bytes.fromhex("f110fb41")
SUFFIX = bytes.fromhex("654b")

def forms(buf):
    yield "plain", buf
    yield "cc", bytes(b ^ 0xCC for b in buf)
    yield "55", bytes(b ^ 0x55 for b in buf)
    yield "sw", swap4(buf)
    yield "ccsw", swap4(bytes(b ^ 0xCC for b in buf))

regions = [("so", so), ("snapA", snapA), ("snapB", snapB),
           ("libdata", libdata), ("libbss", libbss)]

cands = []
for nm, buf in regions:
    # prefix-anchored
    i = buf.find(PREFIX)
    while i >= 0:
        if buf[i+28:i+32] == SUFFIX:
            cands.append((nm + "@%#x" % i, buf[i:i+32]))
        i = buf.find(PREFIX, i+1)
    # masked prefix-anchored
    for f in ("cc", "55"):
        mb = bytes(b ^ int(f, 16) for b in buf)
        i = mb.find(PREFIX)
        while i >= 0:
            if mb[i+28:i+32] == SUFFIX:
                cands.append(("%s/%s@%#x" % (nm, f, i), buf[i:i+32]))
            i = mb.find(PREFIX, i+1)
    # swap4-domain prefix anchor (LE word order): seed words stored reversed
    sw = swap4(buf)
    i = sw.find(PREFIX)
    while i >= 0:
        if sw[i+28:i+32] == SUFFIX:
            cands.append(("%s/sw@%#x" % (nm, i), swap4(sw[i:i+32])))
            cands.append(("%s/sw@%#x.raw" % (nm, i), sw[i:i+32]))
        i = sw.find(PREFIX, i+1)
print("prefix-anchored candidates:", len(cands))
for nm, k in cands[:10]:
    print("  ", nm, k.hex())

def test_key(key, label):
    for kf, kk in forms(key):
        try:
            ws = expand256(kk)
        except Exception:
            continue
        r = dec_nofinalSB(bodyA[:16], ws)
        rec0 = bytes(x ^ y for x, y in zip(r, headA))
        if rec0[:8] == b'{ "a":  ':
            print("SEED FOUND %s form=%s key=%s" % (label, kf, kk.hex().upper()))
            print("   rec0:", rec0)
            return (kf, kk)
        # also try IV swap4
        r2 = dec_nofinalSB(swap4(bodyA[:16]), ws)
        rec0b = bytes(x ^ y for x, y in zip(r2, swap4(headA)))
        if rec0b[:8] == b'{ "a":  ':
            print("SEED FOUND(swdomain) %s form=%s key=%s" % (label, kf, kk.hex().upper()))
            print("   rec0:", rec0b)
            return (kf + "+swct", kk)
    return None

hit = None
for nm, k in cands:
    hit = test_key(k, nm)
    if hit:
        break
if not hit:
    print("prefix anchored miss; brute every 32B window of libbss+libdata (plain/cc/sw)")
    for nm, buf in (("libdata", libdata), ("libbss", libbss)):
        for off in range(0, len(buf) - 32):
            w = buf[off:off+32]
            if len(set(w)) < 8:
                continue
            for f in ("plain", "cc", "sw"):
                kk = dict(forms(w))[f]
                ws = expand256(kk)
                r = dec_nofinalSB(bodyA[:16], ws)
                rec0 = bytes(x ^ y for x, y in zip(r, headA))
                if rec0[:8] == b'{ "a":  ':
                    print("SEED FOUND %s+%#x form=%s key=%s" % (nm, off, f, kk.hex().upper()))
                    print("   rec0:", rec0)
                    hit = (f, kk)
                    break
            if hit: break
        if hit: break
if not hit:
    print("no seed found yet")

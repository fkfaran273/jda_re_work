# Cross-mint constant-window analysis of snap2_A/snap2_B + AES chunk-0 test.
import sys, os, struct
OUT = os.path.dirname(os.path.abspath(__file__))
sA = open(os.path.join(OUT, "snap2_A.bin"), "rb").read()
sB = open(os.path.join(OUT, "snap2_B.bin"), "rb").read()
outA = open(os.path.join(OUT, "blob_A.bin"), "rb").read()

setA16 = set(sA[i:i+16] for i in range(0, len(sA) - 16))
seen = set()
matches = []
for i in range(0, len(sB) - 32):
    w = sB[i:i + 32]
    if w[:16] in setA16 and w[16:] in setA16 and w not in seen:
        seen.add(w)
        if len(set(w)) >= 12:
            matches.append(w)
print("cross-mint constant 32B windows:", len(matches))

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
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def dec_block(c, ws):
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
    st = xor_w(st, ws[56:60])
    for rnd in range(13, 0, -1):
        st = isr(st); st = [IS[b] for b in st]
        st = xor_w(st, ws[4*rnd:4*rnd+4]); st = imc(st)
    st = isr(st); st = [IS[b] for b in st]
    st = xor_w(st, ws[0:4])
    return bytes(st)

def swap4(b):
    return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))

bodyA, headA = outA[16:272], outA[:16]
hits = 0
for w in matches:
    for form, key in (("plain", w),
                      ("cc", bytes(b ^ 0xCC for b in w)),
                      ("sw", swap4(w)),
                      ("ccsw", swap4(bytes(b ^ 0xCC for b in w)))):
        ws = expand256(key)
        for cform, ct in (("plain", bodyA[:16]), ("sw", swap4(bodyA[:16]))):
            for ivf, iv in (("hdr", headA), ("sw", swap4(headA))):
                r = dec_block(ct, ws)
                rec0 = bytes(x ^ y for x, y in zip(r, iv))
                pr = sum(1 for x in rec0 if 32 <= x < 127)
                if rec0[0] in (0x7B, 0x22, 0x20, 0x31, 0x32) or pr >= 13:
                    print("CAND key=%s form=%s ct=%s iv=%s rec0=%r" %
                          (key.hex(), form, cform, ivf, rec0))
                    hits += 1
print("aes hits:", hits)
print("first 12 constant windows:")
for w in matches[:12]:
    print("  ", w.hex())

# a_sched.py — stride-aware AES-256 key-schedule consistency scan over cached
# heap/stack/libdata dumps. Catches schedules stored as VM nodes (fixed stride)
# or masked/word-swapped, which a contiguous textbook scan misses.
import sys, os, struct, itertools

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "a_cache")

SBOX = None
def get_sbox():
    global SBOX
    if SBOX is None:
        p, q = 1, 1
        sb = [0] * 256
        while True:
            p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
            q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
            if q & 0x80:
                q ^= 0x09
            x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
                ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
            sb[p] = (x ^ 0x63) & 0xFF
            if p == 1:
                break
        sb[0] = 0x63
        SBOX = sb
    return SBOX

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]

def subword(t):
    S = get_sbox()
    return (S[(t >> 24) & 0xFF] << 24) | (S[(t >> 16) & 0xFF] << 16) \
        | (S[(t >> 8) & 0xFF] << 8) | S[t & 0xFF]

def rotword(t):
    return ((t << 8) | (t >> 24)) & 0xFFFFFFFF


def word_at(buf, off, be, mask):
    if off < 0 or off + 4 > len(buf):
        return None
    if be:
        w = (buf[off] << 24) | (buf[off+1] << 16) | (buf[off+2] << 8) | buf[off+3]
    else:
        w = struct.unpack_from("<I", buf, off)[0]
    return (w ^ mask) & 0xFFFFFFFF


def scan(name, strides=(0x20, 0x10, 0x18, 0x28, 0x8, 0x4, 0x1)):
    h = open(os.path.join(CACHE, name, "heap.bin"), "rb").read()
    s = open(os.path.join(CACHE, name, "stack.bin"), "rb").read()
    l = open(os.path.join(CACHE, name, "libdata.bin"), "rb").read()
    hits = []
    for rname, buf in (("heap", h), ("stack", s), ("libdata", l)):
        n = len(buf)
        for stride in strides:
            for be in (False, True):
                for mask in (0, 0xCCCCCCCC):
                    # need base..base+stride*9 within buffer; word off = base+4j
                    for base in range(0, n - stride * 8 - 4, 4):
                        w7 = word_at(buf, base + stride * 7, be, mask)
                        w8 = word_at(buf, base + stride*8, be, mask)
                        if w7 is None or w8 is None:
                            continue
                        if w8 == 0 and w7 == 0:
                            continue
                        w0 = word_at(buf, base, be, mask)
                        exp = w0 ^ subword(rotword(w7)) ^ (RCON[0] << 24)
                        if w8 == exp:
                            # verify deeper words
                            ws = [word_at(buf, base + stride*i, be, mask)
                                  for i in range(9)]
                            ok2 = True
                            for j in range(9, min(14, (n - base)//stride)):
                                wj = word_at(buf, base + stride*j, be, mask)
                                if j % 8 == 0:
                                    e = ws[j-8] ^ subword(rotword(ws[j-1])) \
                                        ^ (RCON[j//8-1] << 24)
                                else:
                                    e = ws[j-8] ^ ws[j-1]
                                    if j % 8 == 4:
                                        e = ws[j-8] ^ subword(ws[j-1])
                                if wj != e:
                                    ok2 = False
                                    break
                                ws.append(wj)
                            hits.append((rname, base, stride, be, hex(mask),
                                         j - 0 if ok2 else 1, ok2))
    return hits

if __name__ == "__main__":
    for name in ("p1", "p3"):
        hs = scan(name)
        print("==", name, len(hs), "candidate hits")
        for r in hs[:60]:
            print("  ", r)

# Extract AES-256 key schedules + records from emu memory after a mint
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP, STACK, STACK_SZ
from unicorn import UcError

SBOX = None
def get_sbox():
    global SBOX
    if SBOX is None:
        # standard AES S-box, computed via GF(2^8) inverse + affine
        p, q = 1, 1
        sb = [0] * 256
        while True:
            # multiply p by 3
            p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
            # divide q by 3 (multiply by inverse: q ^= q<<1; q ^= q<<2; ...)
            q ^= q << 1
            q ^= q << 2
            q ^= q << 4
            q &= 0xFF
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

RCON = [r << 24 for r in (1, 2, 4, 8, 0x10, 0x20, 0x40)]

def sub(t, S):
    return (S[(t >> 24) & 0xFF] << 24 | S[(t >> 16) & 0xFF] << 16
            | S[(t >> 8) & 0xFF] << 8 | S[t & 0xFF])

def scan_schedules(emu):
    S = get_sbox()
    uc = emu.uc
    found = []
    for lo, hi in ((HEAP, e.brk), (STACK, STACK + STACK_SZ)):
        try:
            buf = bytes(uc.mem_read(lo, hi - lo))
        except UcError:
            continue
        n = len(buf) - 240
        i = 0
        while i < n:
            w0 = int.from_bytes(buf[i:i + 4], "big")
            w7 = int.from_bytes(buf[i + 28:i + 32], "big")
            w8 = int.from_bytes(buf[i + 32:i + 36], "big")
            if w8 == (w0 ^ sub(((w7 << 8) | (w7 >> 24)) & 0xFFFFFFFF, S) ^ RCON[0]):
                ws = list(struct.unpack_from(">8I", buf, i))
                ok = True
                for k in range(8, 60):
                    t = ws[k - 1]
                    if k % 8 == 0:
                        t = sub(((t << 8) | (t >> 24)) & 0xFFFFFFFF, S) ^ RCON[k // 8 - 1]
                    elif k % 8 == 4:
                        t = sub(t, S)
                    ws.append(ws[k - 8] ^ t)
                kb = b"".join(struct.pack(">I", x) for x in ws)
                if kb == buf[i:i + 240]:
                    found.append((lo + i, kb))
                    i += 240
                    continue
            i += 4
    return found

if __name__ == "__main__":
    params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
              "activity_kind": "session", "client_sdk": "android5.6.0"}
    e = Emu()
    out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
    print("blob:", out.hex().upper()[:80], "...")
    scheds = scan_schedules(e)
    print("schedules:", len(scheds))
    for p, kb in scheds[:6]:
        print("  @%#x key32=%s" % (p, kb[:32].hex()))
    # records: look for the plaintext record shape in heap
    uc = e.uc
    buf = bytes(uc.mem_read(HEAP, e.brk - HEAP))
    i = buf.find(b'{ "a"')
    while i >= 0:
        print("record@%#x: %r" % (HEAP + i, buf[i:i + 200]))
        i = buf.find(b'{ "a"', i + 1)

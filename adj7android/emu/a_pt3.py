# a_pt3.py — snapshot the LE-word-domain record buffer 0x9004e40 at every
# early read/write until it stops looking like plaintext ASCII.
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP, STACK, STACK_SZ
from unicorn import *
from unicorn.arm64_const import *
from a_dump import P1, CACHE

BUF = HEAP + 0x4e40
LEN = 0x140

def snap_of(b):
    return bytes(
        b[i:i+4][::-1] for i in range(0, len(b) - len(b) % 4, 4)) + \
        b[len(b) - len(b) % 4:]

def main(name, second, nonce_hex, params):
    e = Emu()
    e.nonce12 = bytes.fromhex(nonce_hex)
    uc = e.uc
    snaps = []
    nsnap = [0]

    def look_ascii(b):
        run = 0
        for c in b:
            if 32 <= c < 127 or c in (0x10, 0):
                run += 1
            else:
                break
        return run

    def maybe_snap(tag):
        if nsnap[0] > 400:
            return
        b = bytes(uc.mem_read(BUF, LEN))
        a1 = look_ascii(b)
        a2 = look_ascii(snap_of(b))
        if a1 > 40 or a2 > 40:
            snaps.append((tag, a1, a2, b.hex()))
            nsnap[0] += 1

    def hook_r(uc, access, address, size, value, ud):
        maybe_snap("R%#x" % address)

    def hook_w(uc, access, address, size, value, ud):
        maybe_snap("W")

    uc.hook_add(UC_HOOK_MEM_READ, hook_r, begin=BUF, end=BUF + LEN)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_w, begin=BUF, end=BUF + LEN)
    out = e.run(payload=bytes(32), mapobj=params, second=second)
    print("blob:", out.hex()[:32] if out else None, "snaps:", len(snaps))
    d = os.path.join(CACHE, name)
    os.makedirs(d, exist_ok=True)
    json.dump({"blob": out.hex() if out else None, "second": second,
               "nonce": nonce_hex, "params": params, "snaps": snaps},
              open(os.path.join(d, "pt3.json"), "w"))
    # print the first few and the longest-ascii one
    best = max(snaps, key=lambda s: max(s[1], s[2])) if snaps else None
    for tag, a1, a2, hx in snaps[:6]:
        b = bytes.fromhex(hx)
        print(tag, "plain_ascii=%d swap_ascii=%d" % (a1, a2))
        print("   plain:", b[:64])
        print("   swap :", snap_of(b)[:64])
    if best:
        print("BEST", best[0], best[1], best[2])
        b = bytes.fromhex(best[3])
        print("plain:", b)
        print("swap :", snap_of(b))

if __name__ == "__main__":
    import sys
    nm = sys.argv[1] if len(sys.argv) > 1 else "pt1"
    sec = int(sys.argv[2]) if len(sys.argv) > 2 else 1791358552
    main(nm, sec, "00112233445566778899AABB", P1)

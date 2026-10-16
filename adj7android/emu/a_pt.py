# a_pt.py — capture the record plaintext (JSON {"a":...}) at mint time by
# watching writes near the staging area; save PT + final heap for key hunt.
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP, STACK, STACK_SZ
from unicorn import *
from unicorn.arm64_const import *
from a_dump import P1, CACHE

WATCH_LO, WATCH_HI = HEAP + 0x4000, HEAP + 0x6000

def main(name, second, nonce_hex, params):
    e = Emu()
    e.nonce12 = bytes.fromhex(nonce_hex)
    uc = e.uc
    snaps = {}          # start_addr -> latest snapshot bytes
    live = set()        # addresses currently tracked as JSON buffers

    def hook_w(uc, access, address, size, value, ud):
        if not (WATCH_LO <= address < WATCH_HI):
            return
        # look for a JSON start near the write
        lo = max(address - 260, WATCH_LO)
        try:
            buf = bytes(uc.mem_read(lo, min(600, WATCH_HI - lo)))
        except UcError:
            return
        i = buf.find(b'{"a"')
        while i >= 0:
            s = lo + i
            snap = bytes(uc.mem_read(s, 256))
            if snap[:1] == b'{':
                snaps[s] = snap
            i = buf.find(b'{"a"', i + 1)

    uc.hook_add(UC_HOOK_MEM_WRITE, hook_w, begin=WATCH_LO, end=WATCH_HI)
    out = e.run(payload=bytes(32), mapobj=params, second=second)
    print("blob:", out.hex() if out else None)
    d = os.path.join(CACHE, name)
    os.makedirs(d, exist_ok=True)
    keep = {}
    for s, snap in snaps.items():
        # keep only snapshots that look like full-ish JSON (ends with } before
        # 256 or is all-ASCII for a long prefix)
        ascii_run = 0
        for c in snap:
            if 32 <= c < 127 or c in (0,):
                ascii_run += 1
                if c == 0:
                    break
            else:
                break
        keep["%#x" % s] = {"ascii_run": ascii_run, "hex": snap.hex()}
    json.dump({"blob": out.hex() if out else None,
               "second": second, "nonce": nonce_hex, "params": params,
               "snaps": keep}, open(os.path.join(d, "pt.json"), "w"), indent=1)
    for s, snap in sorted(snaps.items()):
        print("PT @%#x len_ascii=%d: %r" % (s, keep["%#x" % s]["ascii_run"],
                                            snap[:80]))

if __name__ == "__main__":
    main("pt1", 1791358552, "00112233445566778899AABB", P1)

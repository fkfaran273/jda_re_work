# a_pt2.py — capture record plaintext at first encryption read of the staged
# body buffer; then count heap/libdata read hotspots for the rest of the mint.
import sys, os, json, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP, STACK, STACK_SZ, BASE
from unicorn import *
from unicorn.arm64_const import *
from a_dump import P1, CACHE

BODY = HEAP + 0x49b0           # staged body (record buffer, 256 B)
LIBDATA_LO, LIBDATA_HI = BASE + 0x11b000, BASE + 0x121000

def main(name, second, nonce_hex, params):
    e = Emu()
    e.nonce12 = bytes.fromhex(nonce_hex)
    uc = e.uc
    state = {"pt": None, "armed": False, "snapshots": []}
    counts = collections.Counter()

    def hook_r_body(uc, access, address, size, value, ud):
        if state["pt"] is None:
            state["pt"] = bytes(uc.mem_read(BODY, 256))
            state["snapshots"].append(
                ("body@firstread", bytes(uc.mem_read(HEAP + 0x4900, 0x700))))
            state["armed"] = True

    def hook_r_heap(uc, access, address, size, value, ud):
        if state["armed"]:
            counts[(address - HEAP) >> 5] += 1

    def hook_r_lib(uc, access, address, size, value, ud):
        if state["armed"]:
            counts[(address - BASE + 0x100000) >> 5] += 1

    uc.hook_add(UC_HOOK_MEM_READ, hook_r_body, begin=BODY, end=BODY + 256)
    uc.hook_add(UC_HOOK_MEM_READ, hook_r_heap, begin=HEAP,
                end=HEAP + 0x12000)
    uc.hook_add(UC_HOOK_MEM_READ, hook_r_lib, begin=LIBDATA_LO,
                end=LIBDATA_HI)
    out = e.run(payload=bytes(32), mapobj=params, second=second)
    print("blob:", out.hex()[:32] if out else None)
    d = os.path.join(CACHE, name)
    os.makedirs(d, exist_ok=True)
    pt = state["pt"]
    print("PT captured:", pt is not None)
    if pt:
        print("PT[0:64] %r" % pt[:64])
        print("PT[64:128] %r" % pt[64:128])
        ascii_run = 0
        for c in pt:
            if 32 <= c < 127:
                ascii_run += 1
            else:
                break
        print("ascii run:", ascii_run)
    hot = counts.most_common(4000)
    total = sum(counts.values())
    print("total armed reads:", total)
    json.dump({"blob": out.hex() if out else None, "second": second,
               "nonce": nonce_hex, "params": params,
               "pt": pt.hex() if pt else None,
               "hot": [[k, v] for k, v in hot]}, open(os.path.join(d,
               "pt2.json"), "w"))
    for k, v in hot[:30]:
        if k >= 0x10000:
            print("lib VA %#x  %d" % (BASE + k * 32 - 0x100000, v))
        else:
            print("heap %#x  %d" % (HEAP + k * 32, v))

if __name__ == "__main__":
    main("pt1", 1791358552, "00112233445566778899AABB", P1)

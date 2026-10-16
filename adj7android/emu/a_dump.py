# a_dump.py — deterministic mint + full memory cache for adj7android key hunt.
# Usage: python a_dump.py name second noncehex params_json
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import UcError
from sign_emu import Emu, HEAP, STACK, STACK_SZ, BASE, segs

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "a_cache")
LIBDATA_RVA = 0x11b000           # covers .data 0x11bd80 + .got + .bss to ~0x120000
LIBDATA_LEN = 0x6000

P1 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "session", "client_sdk": "android5.6.0",
      "os_version": "12"}
P2 = dict(P1, os_version="13")            # differs in ONE claim value only
P3 = dict(P1, activity_kind="event")      # different kind word


def mint(name, second, nonce_hex, params, no_resume=False):
    e = Emu()
    e.nonce12 = bytes.fromhex(nonce_hex)
    reads = []
    orig_ur = e._urandom

    def ur(n):
        reads.append(n)
        return orig_ur(n)
    e._urandom = ur
    out = e.run(payload=bytes(32), mapobj=params, second=second,
                on_resume=not no_resume)
    if not out or len(out) != 304:
        print("MINT FAILED", name)
        return None
    d = os.path.join(CACHE, name)
    os.makedirs(d, exist_ok=True)
    uc = e.uc
    heap = bytes(uc.mem_read(HEAP, e.brk - HEAP))
    stack = bytes(uc.mem_read(STACK, STACK_SZ))
    libdata = b""
    for off, vaddr, filesz, memsz in segs:
        if vaddr >= 0x100000:      # data/bss segment(s) only
            try:
                libdata += struct.pack("<QQ", vaddr, memsz)
                libdata += bytes(uc.mem_read(BASE + vaddr, memsz))
            except UcError:
                pass
    open(os.path.join(d, "heap.bin"), "wb").write(heap)
    open(os.path.join(d, "stack.bin"), "wb").write(stack)
    open(os.path.join(d, "libdata.bin"), "wb").write(libdata)
    meta = {"second": second, "nonce": nonce_hex, "params": params,
            "blob": out.hex(), "brk": e.brk, "srand": e.srand_seeds,
            "rand_calls": e.rand_calls, "urandom_reads": reads,
            "heap_base": HEAP, "stack_base": STACK,
            "libdata_base": BASE + LIBDATA_RVA,
            "jni_tail": [str(t) for t in e.jni_log[-8:]]}
    json.dump(meta, open(os.path.join(d, "meta.json"), "w"), indent=1)
    print("dumped", name, "brk=%#x heap=%d blob=%s" %
          (e.brk, len(heap), out.hex()[:32]))
    return meta


if __name__ == "__main__":
    if len(sys.argv) > 4:
        mint(sys.argv[1], int(sys.argv[2]), sys.argv[3],
             json.loads(sys.argv[4]))
    else:
        S = 1791358552
        N = "00112233445566778899AABB"
        mint("p1", S, N, P1)
        mint("p2", S, N, P2)
        mint("p3", S + 100, "CCDDEEFF0011223344556677", P3)

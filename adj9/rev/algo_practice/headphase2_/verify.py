"""verify.py -- verify the recovered head-phase list, and locate its constants.

Part 1: native check.  For N pinned urandom8 values, run the VM, decode the
signature, and test head16_for(seed, CANDIDATE_PHASES).
Part 2: binary check.  Locate the ten immediate-bearing tiny functions and
confirm which ones ran.
Part 3: reconcile with the genuine-capture phase WIN_PHASE.
"""
import os, sys, struct, json, re

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP
import adj9_signature as SG

NATIVE_PHASE = (0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B, 0x35, 0x36)
FULL10 = (0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B, 0x35, 0x36, 0x2D, 0x05)
SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"


def native_heads(pins):
    out = []
    for ur in pins:
        cfg = FR.build_cfg(0)
        cfg["urandom8"] = bytes.fromhex(ur)
        e = E.Emu(cfg=cfg)
        e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
        blob = e.result["blob"]
        rec = SG.whiten_body_inverse(bytes(blob[16:160]), bytes(blob[:16]))
        seed = int.from_bytes(bytes.fromhex(ur), "little")   # native reads LE
        out.append((ur, seed, bytes(rec[3:19])))
    return out


def find_sites():
    """Every `mov w1, #imm` / `bl 0x1441e4` pair in the binary."""
    data = open(SO, "rb").read()
    # aarch64 MOVZ w1, #imm  = 0x52800000 | (imm16<<5) | (hw<<21)
    sites = []
    for i in range(0, len(data) - 4, 4):
        w = int.from_bytes(data[i:i + 4], "little")
        if (w & 0xFF80001F) == 0x52800001 and (w >> 5) & 0xFFFF:
            hw = (w >> 21) & 3
            imm = ((w >> 5) & 0xFFFF) << (hw * 16)
            nxt = int.from_bytes(data[i + 4:i + 8], "little", signed=False)
            if (nxt & 0xFC000000) == 0x94000000:      # BL
                off = (nxt & 0x3FFFFFF) << 2
                if off & 0x8000000:
                    off -= 1 << 30
                tgt = i + 4 + off
                if tgt == 0x1441E4:
                    sites.append((i - 4, imm))
    return sites


def main():
    pins = ["11223344", "deadbeef", "a5a5a5a5", "01020304", "00000001",
            "7fffffff", "cafebabe", "00ff00ff"]
    rows = native_heads(pins)
    print("PART 1 -- native verification of the recovered phase")
    ok = 0
    for ur, seed, head in rows:
        h8 = AP.head16_for(seed, NATIVE_PHASE)
        h10 = AP.head16_for(seed, FULL10)
        hwin = AP.head16_for(seed, (0x2B, 0x48))
        hdef = AP.head16_for(seed)
        print("  pin=%s seed=%08x native=%s" % (ur, seed, head.hex(" ")))
        print("     phase(30 2b 34 37 38 3b 35 36) -> %s  %s"
              % (h8.hex(" "), "MATCH" if h8 == head else "no"))
        print("     phase(30 2b 34 37 38 3b 35 36 2d 05) -> %s  %s"
              % (h10.hex(" "), "MATCH" if h10 == head else "no"))
        print("     WIN_PHASE(2b 48) -> %s  %s"
              % (hwin.hex(" "), "MATCH" if hwin == head else "no"))
        print("     default(2b) -> %s  %s"
              % (hdef.hex(" "), "MATCH" if hdef == head else "no"))
        ok += (h8 == head)
    print("  native-phase match: %d/%d" % (ok, len(rows)))

    print()
    print("PART 2 -- immediate-bearing call sites of 0x1441e4 in libsigner.so")
    sites = find_sites()
    print("  %d sites:" % len(sites))
    for addr, imm in sorted(sites, key=lambda t: t[1]):
        print("    0x%06x  mov w1,#0x%02x   bl 0x1441e4" % (addr, imm))

    print()
    print("PART 3 -- the genuine-capture phase")
    for phase in [NATIVE_PHASE, (0x2B, 0x48), (0x2B,)]:
        try:
            blob, sec, info = SG.sign_request_vm(
                {"activity_kind": "session"}, "session", head=phase,
                second=SG.SIGNINGS[0]["ts"] // 1000, seed=1, max_steps=20000000)
            want = bytes.fromhex(SG.SIGNINGS[0]["blob_hex"])
            print("  sign_request_vm head=%s -> %s" % ([hex(x) for x in phase],
                                                       "GENUINE MATCH" if blob == want else "differs (%d bytes)" % sum(1 for a, b in zip(blob, want) if a != b)))
        except Exception as ex:
            print("  phase %s: %s" % ([hex(x) for x in phase], ex))


if __name__ == "__main__":
    main()

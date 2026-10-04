"""prng.py -- recover the seed by logging the Lehmer draws the d0 builder makes.

0x143970: ldr x0,[sp,#8]; bl 0x13dfd0 ; mov w23,w0  -> w23 is the PRNG state.
Log every w23 and try to reproduce the chain with adj9_pure._step from
candidate seeds.
"""
import os, sys, struct

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_W0, UC_ARM64_REG_W23

M = AP._MASK32


def run(urandom_hex="11223344", n=0):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    draws = []

    def h(uc, a, s, ud):
        draws.append(uc.reg_read(UC_ARM64_REG_W23) & M)
    mu.hook_add(UC_HOOK_CODE, h, begin=0x14397c, end=0x14397c)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    return draws, e


def chain(S, n):
    out = []
    s = S & M
    for _ in range(n):
        s = AP._step(s)
        out.append(s)
    return out


def main():
    ur = sys.argv[1] if len(sys.argv) > 1 else "11223344"
    draws, e = run(ur)
    print("urandom8=%s  draws=%d" % (ur, len(draws)))
    print("first 30 draws:", [hex(d) for d in draws[:30]])
    cands = {"urand_be": int(ur, 16), "urand_le": int.from_bytes(bytes.fromhex(ur), "little")}
    for name, S in cands.items():
        c = chain(S, len(draws))
        same = sum(1 for a, b in zip(c, draws) if a == b)
        print("  %s S=%08x chain matches %d/%d" % (name, S, same, len(draws)))
        if same:
            print("   first 10 chain:", [hex(x) for x in c[:10]])


if __name__ == "__main__":
    main()

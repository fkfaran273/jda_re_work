"""_ceiling.py — what is the REAL ceiling for a lifted straight-line program?

The agent measured its lifted code at 0.17M steps/s and concluded the lift is
3.6x SLOWER than the interpreter.  But 0.17M steps/s = ~6 us per step, which is
far too slow for Python arithmetic: a register op should be ~0.1 us.  I suspect
the generated code still uses DICT-based registers (the translator was
incomplete -- it reported register divergence).

This measures the ceiling directly: run N steps of representative register
arithmetic with FLAT LISTS and see how fast Python actually goes.  That is the
best case any lifted program could reach.
"""
import time

N = 2_000_000
M64 = 0xFFFFFFFFFFFFFFFF


def run_flat_lists(n):
    """the shape a lifted step takes: xor/and/add over a flat list"""
    r = [0] * 32
    r[0], r[1], r[2] = 0x12345678, 0x9ABCDEF0, 0x0F0F0F0F
    a, b, c, d, e, f = r[0], r[1], r[2], 3, 5, 7
    for _ in range(n):
        a = (a ^ b) & M64
        c = (c + a) & M64
        d = (d ^ c) & M64
        e = (e + d) & M64
        f = (f ^ e) & M64
        b = (b + f) & M64
    return a


def run_dicts(n):
    """the shape if registers stay dict-keyed by name"""
    r = {"x0": 0x12345678, "x1": 0x9ABCDEF0, "x2": 0x0F0F0F0F}
    a = r["x0"]; b = r["x1"]; c = r["x2"]
    d, e, f = 3, 5, 7
    for _ in range(n):
        a = (a ^ b) & M64
        c = (c + a) & M64
        d = (d ^ c) & M64
        e = (e + d) & M64
        f = (f ^ e) & M64
        b = (b + f) & M64
    return a


def main():
    for name, fn in (("flat lists", run_flat_lists), ("dict registers", run_dicts)):
        t = time.time()
        fn(N)
        el = time.time() - t
        # 6 register ops per iteration == 6 "steps"
        steps = N * 6
        print("%-14s %8.2fs for %d steps -> %.2f M steps/s"
              % (name, el, steps, steps / el / 1e6))
    print()
    vm_steps = 9_869_394
    for name, fn in (("flat lists", run_flat_lists), ("dict registers", run_dicts)):
        t = time.time()
        fn(200_000)
        el = (time.time() - t) / (200_000 * 6)     # sec per step
        print("%-14s -> projected full 9.87M-step signature: %.1f s"
              % (name, el * vm_steps))
    print()
    print("current interpreter for reference: 0.61 M steps/s -> ~16 s per signature")


if __name__ == "__main__":
    main()

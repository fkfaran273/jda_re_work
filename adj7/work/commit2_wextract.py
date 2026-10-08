"""commit2_wextract.py — recover the VM SHA-256 messages from the op stream.

For each tracked state buffer (8 contiguous dwords), the VM writes the 8
state words per round.  With the state known before the round,
T1 = new_e - old_d (mod 2^32) and

    W[r] = T1 - h - Sigma1(e) - Ch(e,f,g) - K[r]   (mod 2^32)

recovers the exact message words.  Every block is verified by recompression.

    python commit2_wextract.py
"""
import pickle

M = 0xFFFFFFFF
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
     0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
     0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
     0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

FIPS = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
        0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def compress(state, blk):
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = ((x >> 7 | x << 25) & M) ^ ((x >> 18 | x << 14) & M) ^ (x >> 3)
        s1 = ((y >> 17 | y << 15) & M) ^ ((y >> 19 | y << 13) & M) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = ((e >> 6 | e << 26) & M) ^ ((e >> 11 | e << 21) & M) ^ ((e >> 25 | e << 7) & M)
        ch = (e & f) ^ (~e & g & M)
        t1 = (h + S1 + ch + K[i] + w[i]) & M
        S0 = ((a >> 2 | a << 30) & M) ^ ((a >> 13 | a << 19) & M) ^ ((a >> 22 | a << 10) & M)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & M
        h, g, f = g, f, e
        e = (d + t1) & M
        d, c, b = c, b, a
        a = (t1 + t2) & M
    return [(x + st) & M for x, st in zip((a, b, c, d, e, f, g, h), state)]


def _S1(x):
    return ((x >> 6 | x << 26) & M) ^ ((x >> 11 | x << 21) & M) ^ ((x >> 25 | x << 7) & M)


def _ch(e, f, g):
    return (e & f) ^ (~e & g & M)


def extract_runs(ops, base, min_gap=1200):
    sw = [(i, ops[i][0], ops[i][1]) for i in range(len(ops))
          if base <= ops[i][1] < base + 32 and ops[i][2] == 4]
    assert sw, "no writes to %s" % hex(base)
    runs, cur = [], [sw[0]]
    for x in sw[1:]:
        if x[0] - cur[-1][0] > min_gap:
            runs.append(cur)
            cur = []
        cur.append(x)
    runs.append(cur)
    out = []
    for r in runs:
        init = [None] * 8
        for (i, v, d) in r[:8]:
            init[(d - base) // 4] = v
        # group writes into rounds of 8 (each covering all 8 slots)
        rounds = []
        cur8 = {}
        order = []
        for (i, v, d) in r[8:]:
            j = (d - base) // 4
            if j in cur8:                     # new round started
                rounds.append(cur8)
                cur8 = {}
            cur8[j] = v
            order.append((i, j, v))
        if cur8:
            rounds.append(cur8)
        ws = []
        state = list(init)
        okall = True
        for rnd in rounds:
            if len(rnd) != 8:
                break
            a, b, c, d, e, f, g, h = state
            newe = rnd[4]
            t1 = (newe - d) & M
            wv = (t1 - h - _S1(e) - _ch(e, f, g) - K[len(ws) % 64]) & M
            ws.append((wv, rnd[0], rnd[4], t1))
            # new state from writes
            state = [rnd[j] for j in range(8)]
            # sanity: b..d,f..h shift
            if not (rnd[1] == a and rnd[2] == b and rnd[3] == c
                    and rnd[5] == e and rnd[6] == f and rnd[7] == g):
                okall = False
        out.append({"init": init, "nwrites": len(r), "nrounds": len(ws),
                    "ws": ws, "final": state, "shift_ok": okall})
    return out


def main():
    ops = pickle.load(open("commit2_ops.pkl", "rb"))
    for base, name in ((0x900bcd8, "run1@bcd8"), (0x900be98, "c32@be98"),
                       (0x900bb78, "c20@bb78")):
        print("=====", name, hex(base))
        runs = extract_runs(ops, base)
        for ri, run in enumerate(runs):
            print("  run %d: init %s rounds %d (writes %d) shift_ok %s"
                  % (ri, " ".join("%08x" % v for v in run["init"]),
                     run["nrounds"], run["nwrites"], run["shift_ok"]))
            state = list(run["init"])
            nb = 0
            for bstart in range(0, run["nrounds"] - 63, 64):
                blk = [w for (w, _, _, _) in run["ws"][bstart:bstart + 64]]
                st2 = compress(state, blk)
                rec_a = run["ws"][bstart + 63][1]
                rec_e = run["ws"][bstart + 63][2]
                ok = (st2[0] == rec_a and st2[4] == rec_e)
                print("    block %d: W[0..3] %s | rec a=%08x e=%08x calc a=%08x e=%08x %s"
                      % (nb, " ".join("%08x" % x for x in blk[:4]),
                         rec_a, rec_e, st2[0], st2[4], "OK" if ok else "MISMATCH"))
                state = st2
                nb += 1
            if nb == 0 and run["nrounds"]:
                blk = [w for (w, _, _, _) in run["ws"]]
                print("    rounds<64: W = %s" % " ".join("%08x" % w for w in blk[:20]))
            print("    final state: %s" % " ".join("%08x" % x for x in run["final"]))
        print()


if __name__ == "__main__":
    main()

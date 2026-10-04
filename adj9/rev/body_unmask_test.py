"""body_unmask_test.py — TEST: is the 176-B body whitened by the continuation
of the bionic random() stream that produced the 16-B header?
srand(time(NULL)) was proven at 0x12cb74; header = draws 1..8 pairwise-XOR.
Body candidates: draws 9+ in several packings. Score = structure in unmasked
body (zero bytes / ASCII / runs)."""
import json, struct, sys
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from header_gen import Random3

sigs = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/saz_sigs.json"))
CREATED = {1: 1788856522, 2: 1788856522, 3: 1788856525, 4: 1788856527}

def draws(seed, n):
    R = Random3(seed)
    return [R.next() for _ in range(n)]

def unmask(body, t, layout):
    n = len(body) // 4
    d = draws(t, 8 + n * 2 + 8)          # generous
    if layout == "pair_xor_be":          # mirror header: w[i]=d[2i]^d[2i+1] BE
        ks = b"".join(struct.pack(">I", d[8 + 2 * i] ^ d[9 + 2 * i]) for i in range(n))
    elif layout == "pair_xor_le":
        ks = b"".join(struct.pack("<I", d[8 + 2 * i] ^ d[9 + 2 * i]) for i in range(n))
    elif layout == "raw_be":
        ks = b"".join(struct.pack(">I", d[8 + i]) for i in range(n))
    elif layout == "raw_le":
        ks = b"".join(struct.pack("<I", d[8 + i]) for i in range(n))
    elif layout == "lowbyte":            # one draw per body byte, low 8 bits
        d2 = draws(t, 8 + len(body))
        ks = bytes(x & 0xFF for x in d2[8:])
    elif layout == "byte3210":           # 4 draws per dword, bytes 3,2,1,0
        d2 = draws(t, 8 + len(body))
        ks = bytes(x & 0xFF for x in d2[8:])
    return bytes(a ^ b for a, b in zip(body, ks))

def score(b):
    zeros = b.count(0)
    printable = sum(1 for c in b if 32 <= c < 127)
    run = maxrun = 0
    for c in b:
        run = run + 1 if c == 0 else 0
        maxrun = max(maxrun, run)
    return zeros, printable, maxrun

# baseline: raw body scores
print("=== raw bodies (baseline) ===")
for s in sigs:
    blob = bytearray(192)
    import base64
    blob = base64.b64decode(s["sig_b64"])
    z, p, r = score(blob[16:])
    print("S%d raw  zeros=%3d printable=%3d maxrun=%d" % (s["sess"], z, p, r))

print("\n=== unmask attempts (t = created_at and +1) ===")
import base64
for s in sigs:
    blob = base64.b64decode(s["sig_b64"])
    body = blob[16:]
    t0 = CREATED[s["sess"]]
    # verify header law first
    hd = draws(t0 + 1, 8)
    w = [hd[2 * i] ^ hd[2 * i + 1] for i in range(4)]
    hdr_ok = b"".join(struct.pack(">I", x) for x in w) == blob[:16]
    print("S%d header-law@t+1: %s" % (s["sess"], hdr_ok))
    for layout in ("pair_xor_be", "pair_xor_le", "raw_be", "raw_le", "lowbyte"):
        for dt in (1, 0, 2):
            um = unmask(body, t0 + dt, layout)
            z, p, r = score(um)
            flag = "  <== STRUCTURE" if (z > 20 or p > 110 or r > 6) else ""
            print("   %-11s t+%d zeros=%3d printable=%3d maxrun=%d%s"
                  % (layout, dt, z, p, r, flag))
    print()

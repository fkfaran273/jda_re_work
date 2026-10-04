"""noise_match_test.py — decisive test of the noise model:
body dwords should CONTAIN raw Random3(T) draw values (the rand() noise words)
at fixed positions. T = header second. Draw range 1..~600 covers header (8) +
body noise."""
import json, struct, sys, base64
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from header_gen import Random3

sigs = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/saz_sigs.json"))
CREATED = {1: 1788856522, 2: 1788856522, 3: 1788856525, 4: 1788856527}

def draw_gen(seed, n):
    R = Random3(seed)
    return [R.next() for _ in range(n)]

for s in sigs:
    blob = base64.b64decode(s["sig_b64"])
    T = CREATED[s["sess"]] + 1
    d = draw_gen(T, 800)
    dset = {}
    for k, v in enumerate(d, 1):
        dset.setdefault(v, []).append(k)
    print("S%d T=%d" % (s["sess"], T))
    for endian, fmt in (("LE", "<I"), ("BE", ">I")):
        hits = []
        for off in range(16, 192, 4):
            w = struct.unpack_from(fmt, blob, off)[0]
            for cand in (w, w & 0x7FFFFFFF, w << 1):
                if cand in dset:
                    hits.append((off, hex(w), dset[cand][:3]))
                    break
        print("  %s: %d dword hits -> %s" % (endian, len(hits),
              [(o, w, k) for o, w, k in hits[:12]]))
    # byte-level containment too (rand low bytes pattern at noise byte positions)
    lowbytes = {}
    for k, v in enumerate(d, 1):
        lowbytes.setdefault(v & 0xFF, []).append(k)
    hb = [(off, blob[off], lowbytes[blob[off]][:4]) for off in range(16, 192)
          if blob[off] in lowbytes]
    print("  byte-level low-byte members: %d/176 (chance ~%d)" % (len(hb), 176 * len(lowbytes) // 256))
    print()

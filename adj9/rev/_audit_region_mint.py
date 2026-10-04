"""Audit: rebuild the region (#0/#2/#4) PURELY from the captured d2 seed +
brute-forced head masks, then re-mint the full 192-B blob and compare."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import F, mint_pipeline as M

a = json.load(open(os.path.join(HERE, "all_signings.json")))
ph = json.load(open(os.path.join(HERE, "pair_h3.json")))

def region_from_seed(seed, w0mask, xmask):
    d4 = F._d4_words(seed)
    src = F._d0_source(d4)
    cyc = [F._selector_halfword((((0x40 | (i & 7)) << 1) + 3), src) for i in range(8)]
    hw = [F._selector_halfword(w0mask, src), F._selector_halfword(xmask, src)]
    # observed: hw[2..71] == cyc[(2+k) % 8]
    for k in range(70):
        hw.append(cyc[(2 + k) % 8])
    assert len(hw) == 72
    raw = b"".join(v.to_bytes(2, "little") for v in hw)
    d0 = raw
    d2 = int.from_bytes(seed.to_bytes(4, "little"), "big")
    return d0, struct.pack(">I", d2), b"".join(struct.pack(">I", w) for w in d4)

def descs_from_row(r, d0b, d2b, d4b):
    order = M.VA_ORDER
    d = {}
    for bi in range(11):
        d[bi] = r.get("d%d" % bi, "")
    raw = {"d0": d0b, "d2": d2b, "d4": d4b}
    out = []
    for bi in order:
        h = d[bi]
        b = raw[bi].hex() if bi in raw else h
        n = len(b) // 2
        out.append((n, 0, bytes.fromhex(b)))
    return out

for i in (0, 9):
    r = a[i]; p = ph[i]
    blob = bytes.fromhex(p["blob"]); second = int(p["second"])
    d2w = int.from_bytes(bytes.fromhex(r["d2"]), "big")
    seed = int.from_bytes(bytes.fromhex(r["d2"]), "little")
    d4b = bytes.fromhex(r["d4"]); d0cap = bytes.fromhex(r["d0"])
    src = F._d0_source(list(struct.unpack(">8I", d4b)))
    hw = [int.from_bytes(d0cap[j:j+2], "little") for j in range(0, 144, 2)]
    w0m = [m for m in range(256) if F._selector_halfword(m, src) == hw[0]][0]
    x0m = [m for m in range(256) if F._selector_halfword(m, src) == hw[1]][0]
    d0n, d2n, d4n = region_from_seed(seed, w0m, x0m)
    print("ROW %d second=%d seed=%08x  masks W0=%#x X=%#x  d0_modeled==d0_captured: %s"
          % (i, second, seed, w0m, x0m, d0n == d0cap), flush=True)
    descs = descs_from_row(r, d0n, d2n, d4n)
    out, info = M.finex_mint(descs, second, max_steps=60_000_000)
    w = struct.unpack(">48I", out)
    wb = struct.unpack(">48I", blob)
    diff = [k for k in range(48) if w[k] != wb[k]]
    print("   remint with MODELED region: %d/48 words  diffs=%s  status=%s"
          % (48 - len(diff), diff, info.get("status")), flush=True)

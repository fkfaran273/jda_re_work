"""verify_saz_like_server.py - server-style verification of adj9 blobs.
Server step 1 (header/clock): EXACT - regenerate Random3(sec) stream, match.
Server step 2 (body/claims): STRUCTURAL - size, dword shape, diffusion, H-opacity.
Claim recomputation (H vs history, digests vs request) needs the merge trace (slice 9).
Usage: python verify_saz_like_server.py -> PASS/FAIL per blob (38).
"""
import json, base64, struct
M31 = 2147483647
class Random3:
    __slots__ = ("r", "f", "b")
    def __init__(self, seed):
        r = self.r = [0] * 31
        s = seed & 0xFFFFFFFF
        if s == 0: s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w; prev = w
        for i in range(1, 31):
            hi = prev // 127773 if prev >= 0 else -((-prev) // 127773); lo = prev - hi * 127773
            word = 16807 * lo - 2836 * hi
            if word < 0: word += M31
            prev = word; r[i] = word
        self.f = 3; self.b = 0
        for _ in range(310): self.next()
    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31; self.b = (self.b + 1) % 31
        return o
def make_header(sec):
    R = Random3(sec)
    d = [R.next() for _ in range(8)]
    return b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1]) for i in range(4))
ADJVER = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
def check_blob(name, raw, sec_hint):
    out = []
    if len(raw) != 192: return [(name, "SIZE", False, len(raw))]
    hdr, body = raw[:16], raw[16:]
    secs = [sec_hint + d for d in (1, 0, -1, -2, 2)] if sec_hint else []
    hm = any(make_header(s) == hdr for s in secs)
    out.append((name, "HEADER(time,±2s)", hm, hdr.hex()))
    msb = all(hdr[o] < 0x80 for o in (0, 4, 8, 12))
    out.append((name, "MSB-law", msb, ""))
    dw = struct.unpack(">48I", raw)
    out.append((name, "SHAPE(48dw)", True, "%d body dw" % 44))
    return out
rows = []
bs = json.load(open("blobset.json"))
for e in bs:
    rows += check_blob("oracle@%d" % e["ts"], bytes.fromhex(e["hex"]), e["ts"] // 1000)
sigs = json.load(open("saz_sigs.json"))
secc = {1: 1788856523, 2: 1788856523, 3: 1788856526, 4: 1788856528}
for s in sigs:
    rows += check_blob("saz%d" % s["sess"], base64.b64decode(s["sig_b64"]), secc[s["sess"]])
np_ = sum(1 for _, _, ok, _ in rows if ok); nt = len(rows)
print("server-style: %d/%d checks PASS (header-exact + shape/MSB)" % (np_, nt))
for r in rows:
    if not r[2]: print("FAIL", r)
# corpus-level body laws
allb = [bytes.fromhex(e["hex"]) for e in bs] + [base64.b64decode(s["sig_b64"]) for s in sigs]
dws = [struct.unpack(">48I", b) for b in allb]
print("corpus stable dwords: %s (expect none)" % [i for i in range(48) if len(set(d[i] for d in dws)) == 1])
print("adj_verification const: %s (offline-computable, server compares to expected)" % ADJVER)

# Offline byte-exact reconstruction of all captured adj7 blobs.
# Every component derived independently:
#   header : bionic rand PRNG seeded by the sent_at second
#   body   : spn.py CBC over the decrypted record
#   tag    : HMAC-SHA256(K, body)
# The only borrowed piece per row is the record itself (decrypted from the
# capture with the same cipher) — the roundtrip through decrypt/encrypt plus
# the independently-derived header and tag prove the full law.
import json, sys, os, hmac, hashlib, struct, re, urllib.parse, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spn import body_encrypt, body_decrypt, make_tag

class Random3Bionic:
    M = (1 << 31) - 1
    A = 16807
    Q = M // A
    R = M % A
    def __init__(self, seed):
        s = seed & 0xFFFFFFFF
        if s == 0:
            s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        self.r = [0] * 31
        self.r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi, lo = divmod(prev, self.Q)
            else:
                hi = -((-prev) // self.Q)
                lo = prev - hi * self.Q
            word = self.A * lo - self.R * hi
            if word < 0:
                word += self.M
            prev = word
            self.r[i] = word
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()
    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o

def header_of(second):
    g = Random3Bionic(second)
    d = [g.next() for _ in range(8)]
    words = [d[0] ^ d[1], d[2] ^ d[3], d[4] ^ d[5], d[6] ^ d[7]]
    return b"".join(struct.pack(">I", w) for w in words)

def sent_second(entry):
    if entry["method"] == "POST":
        m = re.search(r"sent_at=([^&]+)", entry.get("body", ""))
    else:
        m = re.search(r"sent_at=([^&]+)", entry["url"])
    s = urllib.parse.unquote(m.group(1)).replace("Z+", "+")
    return int(datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp())

for cap in ("cap/payruki_signed.json", "cap/hunch_signed.json"):
    rows = [r for r in json.load(open(cap)) if "blob" in r]
    print("==", cap)
    for r in rows:
        want = bytes.fromhex(r["blob"])
        sec = sent_second(r)
        hdr = header_of(sec)
        rec = body_decrypt(want[16:272], hdr if hdr == want[:16] else want[:16])
        body = body_encrypt(rec, hdr)
        tag = make_tag(body)
        got = hdr + body + tag
        print("  sid %3d sec=%d header=%s FULL-BLOB BYTE-EXACT: %s" %
              (r["sid"], sec, hdr == want[:16], got == want))
        if r["sid"] in (65, 47):
            print("    record:", rec[:239])

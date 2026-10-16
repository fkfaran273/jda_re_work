# Static DK37 hunt: find a 32-byte window in libsigner.so s.t.
# HMAC-SHA256(window, blob[16:272]) == blob[272:304] for a captured blob.
import hmac, hashlib, json, sys

d = open(r"..\apks\lib\hanaf\libsigner.so", "rb").read()
rows = json.load(open(r"..\cap\payruki_signed.json"))
sig_rows = [r for r in rows if "blob" in r]
cap = bytes.fromhex(sig_rows[2]["blob"])     # sid 67
body, tag = cap[16:272], cap[272:304]
print("target tag", tag.hex())

hits = []
i = 0
n = len(d) - 32
while i < n:
    w = d[i:i + 32]
    if hmac.new(w, body, hashlib.sha256).digest() == tag:
        hits.append(i)
        print("HIT plain @%x" % i)
    i += 1
if not hits:
    print("no plain-window hit")
    # try 0xCC-masked windows over .data only (fast enough)
    base = 0x113d80
    for off in range(base, min(len(d), base + 0x4000) - 32, 4):
        w = bytes(b ^ 0xCC for b in d[off:off + 32])
        if hmac.new(w, body, hashlib.sha256).digest() == tag:
            print("HIT cc-masked @%x" % off)

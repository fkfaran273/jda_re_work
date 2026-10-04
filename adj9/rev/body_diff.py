# body_diff.py — (A) run7 rapid-fire: same inputs + same seed-second -> do bodies match?
#                 (B) corpus-wide body byte stats (is the 176B body PRNG-like or cipher-like?)
import re, glob, collections, struct

def parse_events(path):
    ev, cur = [], None
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\S+) ts=(\d+)", ln)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            ev.append(cur); continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"): cur = None; continue
            cur["body"].append(ln.rstrip("\n"))
    return ev

rows = {}   # idx -> (t0, t1, blob)
for path in ("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run7.log",):
    for e in parse_events(path):
        if not (e["type"].startswith("rapid_batch") or e["type"] == "rapid_fire"):
            continue
        T = "\n".join(e["body"])
        for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=(\d+) sec=(\d+) len=192\n([0-9a-f]+)", T):
            idx = int(m.group(1))
            rows[idx] = (int(m.group(2)), int(m.group(3)), bytes.fromhex(m.group(6)))

print("rapid rows with full 192B:", len(rows))
byhdr = collections.defaultdict(list)
for i in sorted(rows):
    t0, t1, b = rows[i]
    byhdr[b[:16]].append(i)
    print("  row %2d t0=%d dur=%dms hdr=%s" % (i, t0, t1 - t0, b[:16].hex()))

print("\n=== same-header (same seed second) groups ===")
for hdr, idxs in byhdr.items():
    if len(idxs) < 2: continue
    print("header %s rows=%s" % (hdr.hex(), idxs))
    for a in range(len(idxs)):
        for b in range(a + 1, len(idxs)):
            A = rows[idxs[a]][2]; B = rows[idxs[b]][2]
            ba, bb = A[16:], B[16:]
            diff = [i for i in range(176) if ba[i] != bb[i]]
            cp = 0
            while cp < 176 and ba[cp] == bb[cp]: cp += 1
            ham = sum(bin(x ^ y).count("1") for x, y in zip(ba, bb))
            print("  rows %d vs %d: hdr EQUAL, body: common-prefix=%dB diff=%d/176 hamming=%d/1408 (%.1f%%)"
                  % (idxs[a], idxs[b], cp, len(diff), ham, 100.0 * ham / 1408))
            print("   A body[:24] %s" % ba[:24].hex())
            print("   B body[:24] %s" % bb[:24].hex())

# ---- (B) corpus body stats ----
print("\n=== corpus-wide body byte stats (176B bodies) ===")
blobs = {}
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log"):
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"^hex=([0-9a-f]{384})\s*$", ln)
        if m: blobs[m.group(1)[:384]] = None
import base64
fidd = base64.b64decode("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ")
blobs[fidd.hex()] = None
Bs = [bytes.fromhex(k) for k in blobs if len(bytes.fromhex(k)) == 192]
print("unique 192B blobs:", len(Bs))
hi = [0] * 192
for b in Bs:
    for i, x in enumerate(b):
        if x & 0x80: hi[i] += 1
hdr_msbs = [hi[i] for i in range(0, 16, 4)]
body_msbs = [hi[i] for i in range(16, 192, 4)]
print("header bytes 0,4,8,12 with high bit: %s / %d  (PRNG 31-bit law -> expect 0)" % (hdr_msbs, len(Bs)))
print("body bytes 16,20,24,...,188 with high bit: %s" % body_msbs)
print("body MSB average: %.2f (uniform-random expectation ~ %.2f)" %
      (sum(body_msbs) / len(body_msbs) / len(Bs), len(Bs) / 2 / len(Bs)))

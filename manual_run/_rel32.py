"""_rel32.py — are block32 and the trailer the SAME 32-byte function?

If the VM invokes one construction twice, then across many genuine signings
the two outputs should be related in a detectable way.  Tests:

 1. does trailer == block32 for any blob?            (smoking gun)
 2. does the trailer contain any 4-byte word from block32, in any order?
 3. is trailer a GF(2) image of block32 via the known matrix F / F_MINV?
 4. across blobs, is the trailer a fixed function of block32 (same value ->
    same value, across independent samples)?
 5. is the trailer a function of the WHITENED body via F?
"""
import re
import sys

sys.path.insert(0, ".")
import adj9_signature as SG

CAPS = ["../adj9/rev/creditsea/adj9_cap_declic.log",
        "../adj9/rev/creditsea/adj9_cap_fresh.log",
        "../adj9/rev/creditsea/adj9_cap_live_tarsan.log",
        "../adj9/rev/creditsea/adj9_cap_scopefix.log"]

samples = []
for cap in CAPS:
    try:
        text = open(cap, "rb").read().decode("utf-8", "replace")
    except OSError:
        continue
    for h in dict.fromkeys(re.findall(
            r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", text)):
        blob = bytes.fromhex(h)
        dec = SG.decode_blob(blob)
        samples.append((dec["record"][46:78], blob[160:192],
                        blob[16:160], dec["record"], blob[:16]))
print("samples: %d" % len(samples))

print("\n1. trailer == block32 anywhere?")
print("   ", any(b == t for b, t, *_ in samples))

print("\n2. shared 4-byte words between block32 and trailer?")
hits = 0
for b, t, *_ in samples:
    bw = {b[i:i + 4] for i in range(0, 32, 4)}
    tw = {t[i:i + 4] for i in range(0, 32, 4)}
    if bw & tw:
        hits += 1
print("   samples with any shared word: %d / %d" % (hits, len(samples)))

print("\n3. trailer = F-image of block32 (per word)?")


def fwd_word(w):
    # F_word is exposed by the signer; try it word-wise
    try:
        return SG.F_word(w)
    except Exception:
        return None


ok3 = 0
for b, t, *_ in samples:
    match = True
    for i in range(8):
        if fwd_word(int.from_bytes(b[4 * i:4 * i + 4], "big")) != \
           int.from_bytes(t[4 * i:4 * i + 4], "big"):
            match = False
            break
    ok3 += match
print("   samples where trailer == F(block32) wordwise: %d / %d" % (ok3, len(samples)))

print("\n4. is trailer a pure function of block32 across samples?")
m = {}
consistent = True
for b, t, *_ in samples:
    if b in m and m[b] != t:
        consistent = False
    m[b] = t
print("   distinct block32: %d ; no conflicts: %s" % (len(m), consistent))

print("\n5. all pairs (block32, trailer), first 5:")
for b, t, *_ in samples[:5]:
    print("   b=%s" % b.hex()[:24])
    print("   t=%s" % t.hex()[:24])

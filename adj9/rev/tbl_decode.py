#!/usr/bin/env python3
"""Decode the XOR-per-entry string table over a file range.
Entry layout: ciphertext(plaintext XOR key) followed by one stored byte == key
(the encoded NUL terminator). So for start S and length L: key = data[S+L]."""
import sys

FN = "../../extracted/arm64/lib/arm64-v8a/libsigner.so"
d = open(FN, "rb").read()
lo = int(sys.argv[1], 16)
hi = int(sys.argv[2], 16)

def printable(bs):
    return all(32 <= c < 127 for c in bs)

def plausible(t):
    if not t:
        return False
    if sum(1 for c in t if c.isalnum()) < max(1, len(t) * 0.6):
        return False
    return True

found = []
S = lo
while S < hi:
    hit = None
    for L in range(3, 72):
        if S + L >= len(d):
            break
        k = d[S + L]
        if k == 0:
            continue
        pt = bytes(c ^ k for c in d[S:S + L])
        if not printable(pt):
            continue
        t = pt.decode()
        if plausible(t):
            hit = (S, L, k, t)
            break
    if hit:
        found.append(hit)
        S += hit[1] + 1
    else:
        S += 1

for S, L, k, t in found:
    print("file 0x%06x va 0x%06x k=0x%02x L=%-3d %r" % (S, S + 0x8000, k, L, t))
print("entries:", len(found))

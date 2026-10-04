"""d4_struct.py - decompose the 8 golden #4 dwords against the VM's known small
integer sources: queue positions (0..90), stream indices (0..15), descriptor
lengths (36,5,4,8,1,4,90,4,1,1,1), descriptor tags, and Random3 draw indices.

Hypothesis: #4 is a STRUCT (positions/flags/lengths packed by the VM), not
randomness. Test: does each d4 dword split into bytes/nybbles that match the
known small constants? Print byte-split + bit positions for manual reading.
"""
D4 = [0x00100400, 0x04144000, 0x8000C440, 0x88104C05,
      0x0025C852, 0xCC6E00B1, 0x01E76C80, 0x427BF58E]
KNOWN = {36: "#0len", 5: "#9len", 4: "#8len/#4self...", 8: "#4len",
         1: "#5/#7...len", 90: "#10len", 11: "ndesc", 16: "hdrlen",
         0: "zero", 48: "blobdw", 192: "bloblen", 144: "#0lenB", 32: "#4lenB",
         360: "#10lenB", 1500000: "signid&0xffff=0xe2e0?"}

print("=== golden d4 dwords: bytes + set-bit positions ===")
for i, w in enumerate(D4):
    bs = [(w >> s) & 0xFF for s in (24, 16, 8, 0)]
    bits = [b for b in range(32) if (w >> b) & 1]
    print("  d4[%d]=0x%08x bytes=%s bits=%s" % (i, w, bs, bits))

print("\n=== byte values vs known small constants ===")
vals = set()
for w in D4:
    for s in (24, 16, 8, 0):
        vals.add((w >> s) & 0xFF)
print("distinct bytes in d4:", sorted(vals))
print("knowns:", sorted(KNOWN))
print("intersection:", sorted(set(KNOWN) & vals))
print("done")

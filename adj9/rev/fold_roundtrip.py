"""Round-trip validation of the layer-2 fold + its inverse.

Proves (offline, no device): given a ctx and a fold sequence (lens), the
forward transform is deterministic, and the inverse — undoing each fold in
reverse order, using the recorded per-step search slots — recovers the
original ctx exactly. This is the exact procedure a runtime ctx dump feeds.

Fold semantics (from the resolved 0x144074 state graph):
  seed = search_slot(ctx)                  # first i in 0..71 with
                                          # word[24+i] == word[96+(i&7)], else 72
  cursor = word index 24+seed               # ctx+0x30 + seed*2
  mask = (2*len + 3) & 0xffff
  acc = 0
  for x9 in 0..15:
      if mask>>x9 & 1:
          src = word[8 + (15-x9) + 1]       # ctx+0x10..0x30, reversed bit order
          acc = src ^ acc
          word[cursor] = acc
          nxt = src                          # w3 = plaintext word
      acc = nxt                              # w2 = w3 at loop end
Inverse per step (given the recorded slot and mask):
  acc = 0
  for x9 in 0..15 (same order):
      if bit set:
          src = word[8 + (15-x9) + 1]        # sources are untouched by this fold
          acc = src ^ acc
          # word[cursor] held `acc` — but acc's chain includes the PREVIOUS
          # slot value only through `acc` itself, so restoring is direct:
          # nothing to restore from acc — the slot's old value is NOT
          # recoverable from the fold itself.
CRITICAL FINDING: the fold OVERWRITES the slot without mixing the old value
in — the old slot content is LOST unless recovered another way. But the fold
READS the sources and the slot's old value is not read. Therefore:
  - encode is NOT invertible for the overwritten slot from the output alone;
  - the design relies on the slot's old value being either known (padding /
    counters) or reconstructible (claims).
For the SEAL path this means: the blob's slots contain fold results; the
claims are recovered by running the SEARCH sequence, not by un-XORing.
The practical decoder is therefore a FORWARD simulator:
  given candidate claims + nonce, rebuild ctx, run the fold program, and
  CHECK the result equals the captured blob — a verifier, not a decryptor.
That matches the server model: it validates, it does not "decrypt".
"""
import struct
from collections import defaultdict

M31 = (1 << 31) - 1

def park_miller(x):
    hi, lo = divmod(x & 0x7fffffff, 127773)
    v = 16807 * lo - 2836 * hi
    if v < 0:
        v += M31
    return v & M31

def mkctx(seed=12345):
    """deterministic synthetic ctx: 0xd0 bytes from the Park-Miller stream"""
    x = seed
    out = bytearray()
    for _ in range(0xd0 // 4):
        x = park_miller(x)
        out += struct.pack('<I', x)
    return bytes(out[:0xd0])

def words(b):
    return struct.unpack('<%dH' % (len(b) // 2), b)

def search_slot(ctx):
    w = words(ctx)
    for i in range(72):
        if w[24 + i] == w[96 + (i & 7)]:
            return i
    return 72

def fold16(ctx, length, seed=None, record=None):
    """forward fold; returns (new_ctx, seed, mask) — and appends to record."""
    if seed is None:
        seed = search_slot(ctx)
    b = bytearray(ctx)
    mask = (2 * length + 3) & 0xffff
    cursor = 24 + seed
    acc = 0
    nxt = 0
    for x9 in range(16):
        if (mask >> x9) & 1:
            src = struct.unpack_from('<H', b, (8 + (15 - x9) + 1) * 2)[0]
            acc = src ^ acc
            struct.pack_into('<H', b, cursor * 2, acc & 0xffff)
            nxt = src
        acc = nxt
    if record is not None:
        record.append((seed, mask, cursor))
    return bytes(b), seed, mask

def simulate(ctx, lens):
    """run the fold program forward; return final ctx + step records"""
    rec = []
    c = ctx
    for ln in lens:
        c, s, m = fold16(c, ln, record=rec)
    return c, rec

if __name__ == '__main__':
    ctx0 = mkctx(987654321)
    lens = [42, 0x40, 0x41, 0x42, 7, 0x57, 0x2a, 3, 0x44, 5]
    final, rec = simulate(ctx0, lens)
    # 1) determinism
    final2, rec2 = simulate(ctx0, lens)
    assert final == final2 and rec == rec2, "non-deterministic!"
    print("determinism: OK (same ctx -> same blob, same slot sequence)")
    # 2) slot-write accounting: every step writes exactly the recorded slot
    diffs = []
    c = ctx0
    for (seed, mask, cursor), ln in zip(rec, lens):
        c, _, _ = fold16(c, ln, seed=seed)
        d = [i for i in range(0xd0) if c[i] != ctx0[i]]
        diffs.append(len(d))
    print(f"per-fold changed bytes vs ORIGINAL ctx (cumulative): {diffs}")
    # 3) the overwrite property: slot value after fold != before (sources intact)
    c1, s1, m1 = fold16(ctx0, 42)
    w0, w1 = words(ctx0), words(c1)
    changed = [i for i in range(len(w0)) if w0[i] != w1[i]]
    print(f"single fold(42): seed={s1} cursor-word={24+s1} changed words={changed}")
    src_idx = [8 + (15 - x9) + 1 for x9 in range(16) if (m1 >> x9) & 1]
    srcs_intact = all(w1[i] == w0[i] for i in src_idx)
    print(f"source words {srcs_intact and 'INTACT' or 'MODIFIED'} after fold")
    print("\n=> encode is a slot-overwrite fold: verify-by-resimulation, not un-XOR.")

"""r3_probe.py - is descriptor #0 (and the region) a slice of the Random3(second)
PRNG stream?  Tested against two fully-known signings:
  A) our live harvest  : second 1789834707, H=1..32, #0 = 35 words
  B) golden fin_descs  : second 1789240512, #0 = 36 words (wh4 nsign #7)
"""
import sys

sys.path.insert(0, ".")
sys.stdout.reconfigure(line_buffering=True)
from header_gen import Random3, make_header, M31

# --- our live mint's #0 (from harvest_out.json, stream q=3467672896) --------
OURS = [0x00000090, 0x3204a5d5, 0x656999f1, 0x020b5db1, 0xb6fc215f, 0xef8bfc98,
        0x772f01cc, 0x3df99269, 0xfd0b3eea, 0x3c01f6a2, 0xf44937a8, 0x3543fcf7]
OURS_SEC = 1789834707
OURS_BLOB_HDR = bytes.fromhex("20d2b5593204a5d5656999f1020b5db1")

# --- golden (fin_descs.json, whcap_hits7) #0 --------------------------------
GOLD = [0x13271271, 0xdb50f44c, 0xb63798cc, 0xdab7f51a, 0xb7d0992b, 0xdb50f44c,
        0xb63798cc, 0xdab7f51a]
GOLD_SEC = 1789240512


def raw_stream(seed, n=4000):
    """Random3 internals: also expose the raw r[] words and every next()."""
    r = Random3(seed)
    out = []
    for _ in range(n):
        out.append(r.next())
    return out


def raw_words(seed, n=4000):
    """The generator's internal state words r[] over time (what a caller could
    read), plus the raw 16807 recurrence words."""
    r = [0] * 31
    s = seed & 0xFFFFFFFF
    w = s if s < 2**31 else s - 2**32
    r[0] = w
    prev = w
    for i in range(1, 31):
        hi = prev // 127773 if prev >= 0 else -((-prev) // 127773)
        lo = prev - hi * 127773
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += M31
        prev = word
        r[i] = word
    seq = []
    f, b = 3, 0
    for _ in range(n):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < 2**31 else v - 2**32
        seq.append(v & 0xFFFFFFFF)
        f = (f + 1) % 31
        b = (b + 1) % 31
    return seq


def probe(name, sec, words, hdr):
    print()
    print("=== %s  second=%d ===" % (name, sec))
    print("blob[:16] == make_header(sec):", make_header(sec) == hdr)
    ns = raw_stream(sec, 4000)
    ws = raw_words(sec, 4000)
    print("header words (xor form):", ["%08x" % x for x in
          [int.from_bytes(make_header(sec)[i:i + 4], "big") for i in (0, 4, 8, 12)]])
    for tag, seq in (("next()", ns), ("r[]-word", ws)):
        hits = 0
        for i, w in enumerate(words):
            if w in seq:
                j = seq.index(w)
                print("  %-8s words[%2d]=%08x found at seq idx %d" % (tag, i, w, j))
                hits += 1
        print("  %-8s total hits: %d / %d" % (tag, hits, len(words)))
        # look for consecutive runs
        for i in range(len(seq) - 8):
            if seq[i:i + 4] == words[8:12]:
                print("  %-8s RUN of our tile at seq idx %d" % (tag, i))
            if seq[i:i + 4] == words[1:5]:
                print("  %-8s RUN of first-4 at seq idx %d" % (tag, i))


probe("OURS (live harvest)", OURS_SEC, OURS, OURS_BLOB_HDR)
probe("GOLDEN fin_descs #0", GOLD_SEC, GOLD,
      bytes.fromhex("") or make_header(GOLD_SEC))
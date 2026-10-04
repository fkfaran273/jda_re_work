"""analyze_trace.py — replay streams_sample0 full_emit_trace and reconstruct
the digest computation segment (words 40..47 provenance).

Outputs a readable log of every emit in the tail window plus a word-array
snapshot of MAIN (0x5450001000) at the digest-relevant points.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

d = json.load(open(os.path.join(HERE, "..", "streams_sample0.json")))
tr = d["full_emit_trace"]
SINK = d["sink_va"]
MAIN = 0x5450001000


def w(v):
    return "%08x" % (v & 0xFFFFFFFF)


def ascii4(v):
    b = struct.pack(">I", v & 0xFFFFFFFF)
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    return s if s.strip(".") else ""


def replay(lo, hi, streams=(SINK, MAIN), min_len=None):
    """Print events[lo:hi]; merge consecutive ascending/descending runs."""
    evs = []
    for i in range(lo, min(hi, len(tr))):
        sva, n, v = tr[i]
        evs.append((i, sva, n, v))
    return evs


def print_events(lo, hi):
    for i, sva, n, v in replay(lo, hi):
        tag = "SINK" if sva == SINK else ("MAIN" if sva == MAIN else hex(sva))
        print("%6d %-12s %4d %s %s" % (i, tag, n, w(v), ascii4(v)))


def snapshot_main(after_idx, nwords=120):
    words = {}
    for i in range(0, after_idx + 1):
        sva, n, v = tr[i]
        if sva == MAIN:
            words[n] = v
    out = []
    for k in sorted(words)[:nwords]:
        out.append((k, words[k]))
    return out


def words_upto(after_idx, sva=MAIN):
    words = {}
    for i in range(0, after_idx + 1):
        s, n, v = tr[i]
        if s == sva:
            words[n] = v
    return words


def group(idx_from, idx_to, sva=MAIN):
    """Collect words written to sva in trace[index range] in write order."""
    evs = [(n, v) for i, s, n, v in replay(idx_from, idx_to) if s == sva]
    return evs


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "tail"
    if mode == "tail":
        print_events(int(sys.argv[2]), int(sys.argv[3]))
    elif mode == "snap":
        a = int(sys.argv[2])
        ws = words_upto(a)
        for k in sorted(ws):
            print("%4d %s %s" % (k, w(ws[k]), ascii4(ws[k])))
    elif mode == "find":
        # find all events writing a given value
        val = int(sys.argv[2], 16)
        for i, (sva, n, v) in enumerate(tr):
            if (v & 0xFFFFFFFF) == val:
                print(i, hex(sva), n, w(v))

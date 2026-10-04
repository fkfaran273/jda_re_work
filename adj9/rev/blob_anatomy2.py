"""blob_anatomy2.py - where does the blob live in the capture?

Searches ALL segments (not just seg0) for the blob words, and checks the blob's
relationship to the descriptors: is it a transform, or a copy of something else?
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "app_reg.json"), encoding="utf-8"))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


segs = segment([(st, n, v) for st, n, v in d["emits"]])
print("segments: %d" % len(segs))

blob_hex = ("645095aa156c490e2a67d7572b5b2e525c336a55be9462fb8b581861cc49cd1d"
            "023671bd9830b8dd8484fadb11c16f72ac2ca9a9601f52cbb1daa02355ab939"
            "11d07baae3f1a226f8f932a3aacc43aebeb067dedb6ce4075d38ad85dfa9a7183"
            "f114876a42896e9ab7084cdc6aaebbcad549fad2de7aafa7dd50936ac86b479a"
            "3be73e37b9a1ab7e87e8e84e8e415fb9cac01f3b52f645fc2e87e8a4393eb546"
            "9dc3ce42152aad5368de227c663f42802ab1b870918d2ef6202abe0760588dad")
blob = bytes.fromhex(blob_hex)
bw = struct.unpack(">48I", blob)

# search every segment / every stream for any blob word
print()
print("which segment holds the blob stream?")
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) == 48:
            head = b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in vs[:4])
            if head == blob[:16]:
                print("  seg %d stream %s = THE BLOB (48w)" % (k, st))
        # partial: how many blob words in this stream?
        hits = sum(1 for w in vs if w in bw)
        if hits >= 8:
            print("  seg %d stream %s len=%d blob-words=%d" % (k, st, len(vs), hits))

# where do the first 40 blob words appear anywhere?
print()
print("blob word presence across ALL segments:")
present = {i: [] for i in range(48)}
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        for i, w in enumerate(bw):
            if w in vs:
                present[i].append("seg%d" % k)
miss = [i for i in range(48) if not present[i]]
print("  words NOT found anywhere:", miss)
for i in range(48):
    if present[i]:
        print("  blob[%2d] = %08x in %s" % (i, bw[i], ",".join(present[i][:3])))

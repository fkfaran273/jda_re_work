# desc_probe2.py - THE decisive probe: are golden #0/#2/#8 outputs of the SAME
# Random3(second) stream that builds the header? If yes -> pure python signer.
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3, make_header

F = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
D = {x["build_idx"]: x for x in F["descs"]}
T = F["target"]
sec = T["second"]
w2 = int(D[2]["data_hex"], 16)                    # fb1a8296
d0 = bytes.fromhex(D[0]["data_hex"])[-8:]         # b63798ccdab7f51a
d8 = bytes.fromhex(D[8]["data_hex"])              # bffffffffffffd1f0007000000000000
print("golden sec", sec, "hdr", make_header(sec).hex())
print("golden #2 %08x  #0tail %s  #8 %s" % (w2, d0.hex(), d8.hex()))

R = Random3(sec)
stream = [R.next() for _ in range(64)]            # raw dword stream

def fmt4(x):
    return struct.pack(">I", x)

# candidate encodings per stream position
targets = {
    "#2 as BE u32": (4, fmt4(w2)),
    "#2 as LE u32": (4, struct.pack("<I", w2)),
    "#0 tail (8B)": (8, d0),
    "#8     (16B)": (16, d8),
}
for tname, (tlen, tval) in targets.items():
    found = []
    # raw contiguous stream dwords
    for i in range(len(stream) - tlen // 4 + 1):
        blob = b"".join(fmt4(stream[i + k]) for k in range(tlen // 4))
        if blob == tval:
            found.append("raw[%d..]" % i)
    # xored pairs (like header words): w_k = d[2k]^d[2k+1] over a shifted window
    for sh in range(0, 8):
        xs = [stream[sh + 2 * k] ^ stream[sh + 2 * k + 1] for k in range(tlen // 2)]
        blob = b"".join(fmt4(x) for x in xs)
        if blob == tval:
            found.append("xor-pair@%d" % sh)
    # xor of consecutive raw dwords byte-wise into len
    print("%-14s -> %s" % (tname, found or "no raw/xor match in stream[0..64]"))

# also try seeds sec-1, sec+1, sec+2 for #2 only (mint hits were at +1/+2)
for dsec in (-2, -1, 1, 2):
    R2 = Random3(sec + dsec)
    s2 = [R2.next() for _ in range(64)]
    for i in range(63):
        if fmt4(s2[i]) == fmt4(w2):
            print("#2 == raw[%d] of Random3(sec%+d)" % (i, dsec))
        x = s2[i] ^ s2[i + 1] if i + 1 < len(s2) else 0
        if fmt4(x) == fmt4(w2):
            print("#2 == xor[%d,%d+1] of Random3(sec%+d)" % (i, i, dsec))
print("done")

# d_ydecode.py — decode b_ywrites.json (writes into the swap4 staging arena
# Y=0x9004e20 by rva 0x1102b4) chronologically into dword hex + ascii to
# expose the HMAC/tag construction sequence.
import json, os, struct, collections

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "b_ywrites.json")))
ws = d["writes"]

blob = bytes.fromhex(d["blob"])

def dw(v):
    return struct.pack("<I", v & 0xFFFFFFFF)

# chronological with run-length grouping
lines = []
prev = None
for pc, off, sz, val in ws:
    b = dw(val)
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    lines.append((pc, off, sz, val & 0xFFFFFFFFFFFFFFFF, b.hex(), asc))

# print with index, marking interesting values
TAGS = {0x2dbf6161, 0xdc5dc5b0, 0xaa8a90ec, 0x1309fe4a, 0xab3f36f9,
        0x41d711c0, 0x5c60726b, 0xffebbf00}
out = []
for i, (pc, off, sz, val, hx, asc) in enumerate(lines):
    mark = ""
    v32 = val & 0xFFFFFFFF
    if v32 in TAGS:
        mark = "  <<< TAG[%d]" % [0x2dbf6161, 0xdc5dc5b0, 0xaa8a90ec,
                                  0x1309fe4a, 0xab3f36f9, 0x41d711c0,
                                  0x5c60726b, 0xffebbf00].index(v32)
    if v32 == 0x36363636:
        mark = "  <<< ipad"
    if v32 == 0x5C5C5C5C:
        mark = "  <<< opad"
    if v32 == 0x10101010:
        mark = "  <<< pad10"
    if v32 == 0x80808080:
        mark = "  <<< pad80"
    out.append("%5d pc=%#x Y%+4d sz%d %08x %s %s%s" %
               (i, pc, off, sz, v32, hx, asc, mark))
open(os.path.join(HERE, "d_ydecoded.txt"), "w").write("\n".join(out))
print("wrote d_ydecoded.txt lines=%d" % len(out))
# also find where body bytes 7b1ff82b (0x7b1ff82b) appear
for i, (pc, off, sz, val, hx, asc) in enumerate(lines):
    v32 = val & 0xFFFFFFFF
    if v32 == 0x7b1ff82b:
        print("body[0:4] val at idx %d off %+d" % (i, off))

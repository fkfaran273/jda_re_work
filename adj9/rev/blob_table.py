"""blob_table.py - decode the self-describing XOR string table:
entry = [data ^ key][key][00 00 00]  (variable-length data)
Slide through the area, split on key+3-zero markers, decode, score.
"""
import sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from decryptors import LIB

data = open(LIB, "rb").read()
DELTA = 0x7E20
LO, HI = 0x151000, 0x15540A

def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c == 0) / len(b)

i = LO
results = []
while i < HI:
    fo = i - DELTA
    if fo < 0 or fo >= len(data):
        break
    # find next position j where data[j+1:j+4] == 000000 and decoding data[i:j]^data[j] is printable
    found = None
    for j in range(i, min(i + 160, HI) - 4):
        foj = j - DELTA
        if foj + 4 > len(data):
            break
        if data[foj + 1:foj + 4] == b"\x00\x00\x00":
            k = data[foj]
            seg = data[fo:j - DELTA]
            if not seg:
                continue
            dec = bytes(c ^ k for c in seg)
            r = printable_ratio(dec)
            if r >= 0.9 and len(seg) >= 2:
                found = (j, k, dec, r)
                break
    if found:
        j, k, dec, r = found
        results.append((i, j, k, dec, r))
        i = j + 4
    else:
        i += 1

for (a, b, k, dec, r) in results:
    txt = "".join(chr(c) if 32 <= c < 127 else ("\x00" if c == 0 else ".") for c in dec)
    print("0x%x-0x%x key=%02x %r" % (a, b, k, txt))
print("# entries:", len(results), file=sys.stderr)

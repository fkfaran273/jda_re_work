#!/usr/bin/env python3
import sys
sys.path.insert(0,'.')
from _fold_exact import data, secs
def va2off(va):
    for nm,(a,o,s) in secs.items():
        if s and a<=va<a+s: return o+(va-a),nm
    return None,None
def dump(va,n=64,label=""):
    o,nm=va2off(va)
    if o is None: print("0x%06x <no sec>"%va); return
    raw=data[o:o+n]
    print("0x%06x [%s] %s"%(va,nm,raw.hex()))
    for k in range(256):
        d=bytes(c^k for c in raw)
        if d.count(0x2f)>=2 and all(32<=c<127 or c==0 for c in d[:20]):
            print("     key=0x%02x -> %r"%(k,d[:60]))
print("=== 0x151f10 (x22 in fn 0x1c230) ===")
dump(0x151f10,64)
print()
print("=== 0x151f00..0x151f80 raw ===")
o,_=va2off(0x151f00); print(data[o:o+0x80].hex())
print()
print("=== scan whole .data for XOR-decoded paths ===")
da,do,ds=secs['.data']
blob=data[do:do+ds]
import re
seen=set()
for k in range(1,256):
    d=bytes(c^k for c in blob)
    for m in re.finditer(rb'/[a-z][a-z0-9_/.\-]{3,60}', d):
        s=m.group().decode()
        if s not in seen:
            seen.add(s); print("   key=0x%02x  %s"%(k,s))

"""d2_ldscan.py - where does the VM read descriptor data? Log every ld/ldbyte
address in the 0x56/0x57 range for one base run."""
import json
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, '.')
import vm_final as V
from fin_vm2 import FinEx
import mint_pipeline as M

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
r = rows[7]
sec = pairs[7]['second']
d0w = list(struct.unpack('>36I', bytes.fromhex(r['d0'])))
d2w = struct.unpack('>I', bytes.fromhex(r['d2']))[0]
d4w = list(struct.unpack('>8I', bytes.fromhex(r['d4'])))
claims = bytes.fromhex(r['d10'])
unp = len(claims)
padded = claims + b'\x00' * ((-unp) % 4)
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")


def mk(d0, d2, d4):
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in M.VA_ORDER]


d0 = b''.join(struct.pack('>I', w) for w in d0w)
d2 = struct.pack('>I', d2w)
d4 = b''.join(struct.pack('>I', w) for w in d4w)
descs = mk(d0, d2, d4)


class ScanEx(FinEx):
    def ld(self, va, size=8):
        a = va & V.PM
        if 0x5600000000 <= a < 0x5800000000:
            self._ldc[a & ~3] += 1
        return super().ld(va, size)

    def ldbyte(self, va):
        a = va & V.PM
        if 0x5600000000 <= a < 0x5800000000:
            self._ldc[a] += 1
        return super().ldbyte(va)


t = time.time()
ex = ScanEx(sec, descs)
ex._ldc = Counter()
status = ex.run(max_steps=60_000_000)
print("status=%s steps=%d (%.0f s)" % (status, ex.steps, time.time() - t))
print("distinct descriptor-region addresses loaded:", len(ex._ldc))
# group by 0x1000 page
pages = Counter((a >> 12) << 12 for a in ex._ldc)
for pg in sorted(pages):
    tag = {0: 'd0', 1: 'd9', 2: 'd8', 3: 'd4', 4: 'd2', 5: 'd7',
           6: 'd10', 7: 'd5', 8: 'd1', 9: 'd6', 10: 'd3'}.get(
               (pg - 0x5700000000) >> 12, '?')
    print("  page %012x (%s): %d distinct addrs, %d loads"
          % (pg, tag, len([a for a in ex._ldc if (a >> 12) << 12 == pg]),
             pages[pg]))
# detail for d2 page + node pages
for a in sorted(ex._ldc):
    if 0x570000004000 <= a < 0x570000005000 or 0x5600000000 <= a < 0x5600000B00:
        print("    %012x : %d" % (a, ex._ldc[a]))

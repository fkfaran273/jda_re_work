"""_d8proof.py — is D8 (the 'penti capture - to verify' constant) actually
PROVEN for creditsea, or just inherited from penti?

Test: re-run the 192/192 reproduction with a DELIBERATELY WRONG D8.  If D8 were
unverified-but-correct, a wrong D8 must break the reproduction.  If it still
reproduces, D8 does not affect the body and is irrelevant.
"""
import sys, os, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import testbed as TB
from testbed import mine_log, decode, region_parts
import desc10_58 as D

s = mine_log()[0]
kind = s['val'].get('activity_kind', 'session')
dec = decode(s['blob'])
d0, d4, d2, pfx = region_parts(dec, s['second'])
raw, _padded = D.claims_for_law_58(s['val'], kind)
print('genuine %s second=%d, recovered head prefix=%s' % (kind, s['second'], pfx))
print()
for label, d8 in (("penti D8 (current)", "bffffffffffffd1f0007000000000000"),
                  ("WRONG D8 (all zero)", "00000000000000000000000000000000"),
                  ("WRONG D8 (all ff)",  "ffffffffffffffffffffffffffffffff")):
    TB.D8_HEX = d8
    descs = TB.build_descs(s['second'], raw, d0, d4, d2)
    blob, status = TB.run_vm(s['second'], descs, max_steps=60_000_000)
    n = sum(1 for a, b in zip(blob, s['blob']) if a == b)
    print('  %-22s -> %d/192  %s' % (label, n, 'BYTE-EXACT' if blob == s['blob'] else 'differs'))

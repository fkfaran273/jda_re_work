"""_solve_info.py -- solve the info claims law with the saz oracle.

The saz /sdk_info request is from a DIFFERENT session than the oracle_run3
capture, and its form body carries the EXACT field values the device claimed.
The block-law oracle is: record_block(head, seed, claims, cert) == block.

Strategy: the law shape is sorted(profile) + PIN + sorted(tail) + block2.
Search which of the 19 non-BLOCK2, non-PIN keys are profile vs tail vs absent.
Keep the constraint that BLOCK2 keys and PIN are always emitted.
"""
import itertools
import json
import sys

sys.path.insert(0, '.')
import adj9_pure as P  # noqa: E402
import adj9_decode as D  # noqa: E402
from urllib.parse import parse_qs  # noqa: E402

V = json.load(open('saz_vectors.json'))
r = V['info']
sig = bytes.fromhex(r['sig_hex'])
rec = D.whiten_body_inverse(sig[16:160], sig[:16])
seed = int.from_bytes(rec[20:24], 'big')
head = rec[3:19]
cert = rec[25:45]
want = rec[46:78]

fields = {k: v[0] for k, v in parse_qs(r['form']).items()}
PIN = 'adj_signing_id'
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
# activity_kind is not in the form body (it is added by the SDK), but the
# block hash needs it -- the capture was for sdk_info so kind='info'.
fields.setdefault('activity_kind', 'info')
fields.setdefault('client_sdk', 'android5.7.0')
fields.setdefault('headers_id', '10')
fields.setdefault('native_version', '5.0.0')
fields.setdefault('adj_signing_id', '1500000')
# the two time stamps: created_at/sent_at are in the form.  The head is
# derived from the seed, and the seed must be consistent with the stamps --
# the agent's make_V_in_window shows how the native picks it.  For the search
# we leave the form's own values in.

POOL = [k for k in sorted(fields) if k not in BLOCK2 and k != PIN]
print('pool: %d keys' % len(POOL))
print('  ', POOL)
print()

# The law shape for the other kinds always ends: ... sorted(tail) + BLOCK2,
# and the PIN sits between profile and tail.  So the claims string is:
#   sorted(profile) + [PIN] + sorted(tail) + BLOCK2
# The unknown is which pool keys are profile and which are tail.

hits = []
n_keys = len(POOL)
# profile is any subset; tail is the complement.  2^n_keys subsets.
for mask in range(1 << n_keys):
    prof, tail = [], []
    for i in range(n_keys):
        (prof if mask >> i & 1 else tail).append(POOL[i])
    keys = sorted(prof) + [PIN] + sorted(tail) + BLOCK2
    claims = ''.join(fields[k] for k in keys).encode('latin1')
    if P.record_block(head, seed, claims, cert) == want:
        hits.append((prof, tail, len(claims)))
        if len(hits) >= 3:
            break

print()
if hits:
    print("MATCHES: %d" % len(hits))
    for prof, tail, ln in hits[:3]:
        print("   profile:", sorted(prof))
        print("   tail   :", sorted(tail))
        print("   claims : %d bytes" % ln)
else:
    print("no subset split reproduced the block")
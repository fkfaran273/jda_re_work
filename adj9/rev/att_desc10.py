# att_desc10.py - the SIGNATURE claim set for the `attribution` kind.
#
# The user's framing, made precise:
#   * REQUEST params  -> known from the .saz (session 43, click 47, attribution 22).
#   * SIGNATURE claim set -> what desc10 actually packs. This is NOT the request
#     param set and it differs per activity kind:
#         session     27 law keys   (request carries 43)
#         click       32 law keys   (request carries 47)
#         attribution 21 predicted  (request carries 22)
# Every /attribution send in the campaign was signed with the SESSION claim set,
# which embeds 7 claims the request never carries and omits `initiated_by` - a
# claim-key mismatch by construction (slice 99 §8.2: the server rebuilds the claim
# set from the request).
#
# This script derives the attribution claim set from the device's OWN attribution
# map (gold6 idx 2/5, activity_kind="attribution") and prints the exact bytes the
# native would pack, so a future capture can confirm it by length.
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from desc10_law import (PROFILE_COMMON, SESSION_TAIL, CLICK_TAIL, BLOCK2, PINNED)

G = json.load(open(os.path.join(DEV, 'gold6.json'), encoding='utf-8'))
GEN = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))

# ---- pull the device's own attribution map ---------------------------------
N = max(len(v) for v in G.values())
att = None
for i in range(N):
    si = G['sign_input'][i]
    txt = (' '.join(str(x) for x in si) if isinstance(si, (list, tuple)) else str(si))
    if 'map_toString=' not in txt:
        continue
    body = txt.split('map_toString=', 1)[1].strip()
    kv = dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*?)(?=, |$|,)',
                         body + ','))
    if kv.get('activity_kind') == 'attribution':
        att = kv
        blobs = G['nsign'][i]
        att['_blob'] = (' '.join(str(x) for x in blobs)
                        if isinstance(blobs, (list, tuple)) else str(blobs))
        break

print('=== the device\'s own ATTRIBUTION map (%d keys) ===' % len(att))
print()

# ---- predicted claim set for the attribution kind ---------------------------
# Rule: exactly the law's blocks, restricted to what this map carries, with
# `initiated_by` joining the profile block (it is payload-bearing per §8.2 and is
# present in every attribution map).
INSTR = {'key2_hex', 'key2_len'}
def profile_keys(val):
    ks = [k for k in PROFILE_COMMON if k in val]
    if 'initiated_by' in val:
        ks.append('initiated_by')
    return ks

def tail_keys(val):
    # SESSION_TAIL and CLICK_TAIL overlap (tracking_enabled), so dedupe
    ks = {k for k in (SESSION_TAIL + CLICK_TAIL) if k in val}
    return sorted(ks)

pk = sorted(profile_keys(att))
tk = sorted(tail_keys(att))
order = pk + [PINNED] + tk + BLOCK2

print('profile block  (%2d, sorted): %s' % (len(pk), pk))
print('pinned         ( 1)        : %s' % PINNED)
print('tail block     (%2d, sorted): %s' % (len(tk), tk))
print('envelope block (%2d)        : %s' % (len(BLOCK2), BLOCK2))
print('TOTAL          (%2d keys)' % len(order))
print()

pred = ''.join(att[k] for k in order)
padded = pred + '\0' * (-len(pred) % 4)
print('=== predicted desc10 (attribution) ===')
print(pred)
print()
print('unpadded length = %d B   (descriptor #7 value)' % len(pred))
print('padded length   = %d B   (descriptor #10 length, %d dwords)'
      % (len(padded), len(padded) // 4))
print()

# ---- the size comparison that matters --------------------------------------
print('=== request params vs signature claim set, per kind ===')
SAZ = {'session': 43, 'click': 47, 'attribution': 22}
for kind, nreq in SAZ.items():
    if kind == 'session':
        n = 27
    elif kind == 'click':
        n = 32
    else:
        n = len(order)
    print('  %-11s request=%-3d  signature=%-3d  (signature is a subset: %s)'
          % (kind, nreq, n, n < nreq))
print()
print('  => the signature never covers the whole request; it covers a kind-specific')
print('     claim subset. Signing an /attribution request with the session subset')
print('     means the blob asserts 7 claims the request does not carry.')

# ---- what the session law would wrongly assert ------------------------------
from desc10_law import desc10_keys
sess = desc10_keys('session', att)
print()
print('=== session law vs the attribution map ===')
print('  session-law keys ABSENT from an /attribution request : %s'
      % [k for k in sess if k not in att])
print('  attribution-only key the session law never packs    : %s'
      % [k for k in ('initiated_by',) if k in att and k not in sess])
print()
print('=== the genuine /attribution query, for the record ===')
q = {k: v[0] for k, v in urllib.parse.parse_qs(GEN['query'].split('?', 1)[1],
                                               keep_blank_values=True).items()}
print('  %d query keys; all of them present in the attribution map: %s'
      % (len(q), all(k in att for k in q)))
print('  map keys absent from the query (claims the wire does not carry): %s'
      % sorted(set(k for k in att if not k.startswith('_')) - set(q)))
print()
print('=== captured attribution blob (gold6 idx 2) ===')
print('  %s' % att['_blob'][:200])
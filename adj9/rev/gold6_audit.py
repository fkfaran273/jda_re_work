# gold6_audit.py - audit the 6 oracle signings against the desc10 law.
#
# gold6.json: 6 fresh device signings, each with canonical / sign_input (the
# ordered map) / nsign_in (arg3 = H) / nsign (the 192-B blob). Two things to
# establish here:
#   1. is H (arg3) the Mac.doFinal output (i.e. no separate value)?
#   2. does `push_token` appear as an ordinary MAP entry? Slice 105 inferred the
#      token is a normal profile claim; if the map carries it as a key, the model
#      is confirmed at the map level (not a native injection).
# Plus: which law keys are present/missing per signing, and the implied kind.
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from desc10_law import desc10_keys, BLOCK2, PINNED

G = json.load(open(os.path.join(DEV, 'gold6.json'), encoding='utf-8'))


def recs(v):
    """the oracle log format: list of [ 'key: value', ... ] strings"""
    out = []
    for item in v:
        if isinstance(item, (list, tuple)):
            out.append(' '.join(str(x) for x in item))
        else:
            out.append(str(item))
    return out


def field(records, name):
    for r in records:
        m = re.search(r'%s[=:]\s*(\S+)' % re.escape(name), r)
        if m:
            return m.group(1)
    return None


def map_entries(records):
    """parse map_toString into an ordered list of (key, value)"""
    txt = None
    for r in records:
        if 'map_toString=' in r:
            txt = r.split('map_toString=', 1)[1]
            break
    if not txt:
        return None, None
    txt = txt.strip()
    size = None
    for r in records:
        m = re.search(r'map_size=(\d+)', r)
        if m:
            size = int(m.group(1))
    kv = re.findall(r'([A-Za-z0-9_]+)=', txt)
    return kv, txt


print('gold6.json top-level fields: %s' % sorted(G))
LENS = {k: (len(v) if isinstance(v, list) else 1) for k, v in G.items()}
print('records per field: %s' % LENS)
N = max(LENS.values())
print('signings in gold6.json: %d' % N)
print()


def recs(v):
    if not isinstance(v, list):
        v = [v]
    out = []
    for item in v:
        if isinstance(item, (list, tuple)):
            out.append(' '.join(str(x) for x in item))
        else:
            out.append(str(item))
    return out


def signing(i):
    """gather field i across all fields (records are index-aligned)"""
    out = {}
    for k, v in G.items():
        if isinstance(v, list) and i < len(v):
            out[k] = recs([v[i]])
    return out


def tostring(rs):
    for r in rs:
        if 'map_toString=' in r:
            return r.split('map_toString=', 1)[1].strip()
    return None


print('%-4s %-8s %-6s %-9s %-7s %s' %
      ('idx', 'kind', 'mapN', 'arg3==mac', 'token', 'law coverage'))
rows = []
for i in range(N):
    s = signing(i)
    si = s.get('sign_input', [])
    txt = tostring(si)
    if not txt:
        print('%-4d (no map_toString)' % i)
        continue
    keys = re.findall(r'([A-Za-z0-9_]+)=', txt)
    keys = [k for k in keys if k not in ('map_order',)]
    kind = 'click' if ('referrer' in keys or 'google_play_instant' in keys) else 'session'
    law = desc10_keys(kind, dict.fromkeys(keys, 'x'))
    missing = [x for x in law if x not in keys]
    ni = ' '.join(s.get('nsign_in', []))
    jd = ' '.join(s.get('jca_mac_doFinal', []))
    m_arg3 = re.search(r'arg3_hex=([0-9a-f]{64})', ni)
    m_mac = re.search(r'\bhex=([0-9a-f]{64})', jd)
    same = bool(m_arg3 and m_mac and m_arg3.group(1) == m_mac.group(1))
    tok = 'push_token' in keys
    print('%-4d %-8s %-6d %-9s %-7s %d/%d present%s'
          % (i, kind, len(keys), same, tok, len(law) - len(missing), len(law),
             '' if not missing else ', missing=%s' % missing))
    rows.append((i, kind, len(keys), same, tok, sorted(set(keys) - set(law))))

print()
print('=== does the map carry the token / the oracle annotations? ===')
for i, kind, n, same, tok, extra in rows:
    interesting = [e for e in extra if e in ('push_token', 'key2_hex', 'key2_len',
                                             'map_order', 'algorithm')]
    print('  idx %-3d extra=%d  of interest=%s' % (i, len(extra), interesting))
print()
print('=== extras vs slice 99 §8.2 "tolerated" keys ===')
TOLERATED = {'ui_mode', 'foreground', 'offline_mode_enabled', 'needs_response_details',
             'attribution_deeplink', 'gps_adid_attempt', 'sent_at'}
for i, kind, n, same, tok, extra in rows:
    t = TOLERATED & set(extra)
    print('  idx %-3d tolerated in extras: %d/%d %s'
          % (i, len(t), len(TOLERATED), sorted(TOLERATED - t) or 'ALL'))
print()
print('=== raw key2_* annotation (idx 0) ===')
for r in signing(0).get('sign_input', []):
    if 'key2' in r:
        print('  %s' % r[:300])
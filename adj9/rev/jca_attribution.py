#!/usr/bin/env python3
"""Attribute JCA events inside nSign windows — separating nSign's own ops from
concurrent app-thread crypto falsely tagged by the module's global inNSign flag.

Run on device/events.json (parsed from device/adj9_full.log by device/parse_full.py).

Findings this script reproduces (2026-09-10):
  1. 11 nsign_in/nsign windows. Only 2 contain events (1631..1703, 3066..3121);
     both are the FIRST nSign of a fresh process. Two windows (2484, 3923) are
     provably logging-alive and contain ZERO jca events -> steady-state nSign
     performs no JCA at all (not even Mac). The other 7 are artifacts: JCA_CAP=1200
     exhausted (1205, 5546) or oracle suppressJca (1231, 1238, 1245, 1252, 1259).
  2. AES ops inside window 1631 (keys 5cde8cbc../856a7f1f.., in==out lengths) are
     androidx.security/Tink EncryptedSharedPreferences encrypting pref key names
     ("user_session", "session_token", "core_network_sec") on another thread;
     the same keys/ops appear OUTSIDE windows rooted at ks_getKey
     _androidx_security_master_key_. NOT nSign.
  3. The SHA1/SHA256/MD5 cascade over 36,91,91,61,294,294,73,550,550 is Google
     TLS chain verification (upload.video.google.com -> GTS WR2 -> GTS Root R1);
     the identical 9-tuple occurs outside windows. NOT nSign.
  4. Genuine nSign JCA (first call per process, cached afterwards):
     SHA1(app cert 745B, issuer Istanbul/Penti) -> AndroidKeyStore getKey(key2)
     -> Mac(key2)(canonical 1355B) whose output EQUALS arg3 (verified 2/2).
"""
import json, collections

EV = json.load(open(__file__.replace('jca_attribution.py', '..') + '/device/events.json'))

def field(e, name):
    for ln in e.get('body', '').split('\n'):
        ln = ln.replace('text: ', '')
        if ln.startswith(name + '='):
            return ln[len(name) + 1:]
    return None

def tagged(e):
    return '[inside nSign]' in e.get('body', '').split('\n')[0]

idx_in = [i for i, e in enumerate(EV) if e['type'] == 'nsign_in']
idx_out = [i for i, e in enumerate(EV) if e['type'] == 'nsign']
wins = [(i, next(o for o in idx_out if o > i)) for i in idx_in]
inside = lambda i: any(a < i < b for a, b in wins)

# -- 1. window census with JCA-cap / suppression state ------------------------
oracle_starts = {i for i, e in enumerate(EV) if e['type'] == 'oracle_start'}
print("windows:")
for a, b in wins:
    n = b - a - 1
    cap = sum(1 for j in range(a + 1) if j not in oracle_starts and EV[j]['type'].startswith('jca_')
              and not any(s <= j for s in oracle_starts if s < a))
    note = ''
    if n == 0:
        note = ' (see census notes in module docstring)'
    print(f"  [{a}..{b}] events={n:3d} dur={EV[b]['ts']-EV[a]['ts']:5d}ms arg3={field(EV[a],'arg3_hex')[:16]}")

# -- 2. tag consistency --------------------------------------------------------
tagged_idx = [i for i, e in enumerate(EV) if e['type'].startswith('jca_') and tagged(e)]
print(f"\ntagged events: {len(tagged_idx)}, all index-inside windows: "
      f"{all(inside(i) for i in tagged_idx)}  (flag agrees with index; attribution still unsafe)")

# -- 3. AES keys: where else do they occur? ------------------------------------
for key in ('5cde8cbc', '856a7f1f'):
    out_n = sum(1 for i, e in enumerate(EV)
                if e['type'] == 'jca_secretkeyspec_init'
                and (field(e, 'hex') or '').startswith(key) and not inside(i))
    in_n = sum(1 for i, e in enumerate(EV)
               if e['type'] == 'jca_secretkeyspec_init'
               and (field(e, 'hex') or '').startswith(key) and inside(i))
    print(f"SecretKeySpec({key}..): {in_n}x inside windows, {out_n}x outside -> app pref-layer key")

# -- 4. TLS cascade pattern outside windows ------------------------------------
lens = [(i, int(field(e, 'len'))) for i, e in enumerate(EV)
        if e['type'] == 'jca_md_update' and (field(e, 'len') or '').isdigit()]
pat = [36, 91, 91, 61, 294, 294, 73, 550, 550]
hits = [lens[k][0] for k in range(len(lens) - 8)
        if [lens[k + j][1] for j in range(9)] == pat]
print(f"\nGoogle TLS cascade {pat}: {len(hits)}x, inside windows: {[inside(i) for i in hits]}")

# -- 5. arg3 == internal Mac ----------------------------------------------------
for a, maci in [(1631, 1642), (3066, 3077)]:
    eq = field(EV[a], 'arg3_hex') == field(EV[maci], 'hex')
    print(f"win[{a}]: internal Mac(key2) == arg3 : {eq}")

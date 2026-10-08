"""verify the captured event map against the H record from the oracle."""
import json, sys
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import adj7_pure as sg

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\hanaf_map.json"))
V = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\hanaf_verify.json"))

for kind in ("session", "click", "attribution", "event"):
    cap = next(c for c in D['captures'] if c['kind_or_endpoint_hint'].startswith(kind))
    nsign = cap['nsign_map']
    ver = next(v for v in V if v['kind'] == kind)
    nonce12 = bytes.fromhex(ver['nonce12_hex'])
    # build claims using pool order from hanaf
    split = sg.CLAIM_POOL.index('session_count')
    profile, tail, block2 = (sg.CLAIM_POOL[:split],
                             sg.CLAIM_POOL[split:-2],
                             sg.CLAIM_POOL[-2:])
    parts = [str(nsign[k]) for k in profile if nsign.get(k) not in (None, '')]
    parts.append(sg.ADJ_SIGNING_ID)
    parts += [str(nsign[k]) for k in tail if nsign.get(k) not in (None, '')]
    parts += [str(nsign[k]) for k in block2 if nsign.get(k) not in (None, '')]
    claims = ''.join(parts).encode('latin1')
    H_real = sg.commitment_digest(claims, nonce12,
                                  b'C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF')
    print(kind, H_real.hex().upper() == ver['record_b'])
    print("  expected:", ver['record_b'])
    print("  computed:", H_real.hex().upper())

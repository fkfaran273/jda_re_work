"""_realpath.py — does the RUNNER's actual signer reproduce genuine creditsea blobs?

desc10_58.GOLD proved the LAW reproduces the genuine blobs using desc10_58's
own mint path.  The runner does NOT use that path -- it uses
signer_simple.sign_request (different region/mint code, penti constants).
Test the real path against the genuine blobs.
"""
import re, sys, os
CAP = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\adj9_cap_fresh.log'
b = open(CAP, 'rb').read().decode('utf-8', 'replace')
gen = {}
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw); k = k.group(1) if k else '?'
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    gen.setdefault(k, d)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea')
import desc10_58 as D
import signer_simple as sg
# apply the runner's overrides
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
_o = D.claims_for_law_58
def c58(val, kind):
    v = dict(val); v["client_sdk"] = "flutter5.8.0@android5.8.0"
    return _o(v, kind)
sg.claims_for_law = c58
for g in D.GOLD:
    kind = g["kind"]
    if kind not in gen: 
        print(kind, 'no genuine map'); continue
    params = {k: v for k, v in gen[kind].items()}
    blob, sec, info = sg.sign_request(params, kind, second=g["second"])
    h = blob.hex() if isinstance(blob, (bytes, bytearray)) else blob
    same = (h == g["blob_hex"])
    n = sum(1 for a, b in zip(bytes.fromhex(h), bytes.fromhex(g["blob_hex"])) if a == b)
    print('%-12s second=%d  status=%s  BYTE-EXACT=%-5s  %d/192' %
          (kind, g["second"], info.get("status") if isinstance(info, dict) else '?',
           same, n))

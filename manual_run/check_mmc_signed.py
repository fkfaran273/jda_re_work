"""check_mmc_signed.py -- the mcc/mnc signature theory, settled.

Theory: the real app SIGNS mcc/mnc when it has a SIM (our RE device had
none, so the claims law misses them).  Test: take the GENUINE declic
capture (SIM device, mcc 405/mnc 872 present, install JOINED), decode its
signature, and rebuild the claims block under our law -- without, and with,
mcc/mnc in the key order.  Whichever reproduces the genuine block is what
the app really signed.  Same for the penti golden saz capture (8 Sep).
"""
import base64
import datetime
import json
import re
import zipfile
import urllib.parse

import adj9_decode as D
import adj9_pure as P


def envelope_defaults(auth):
    """adj_signing_id / headers_id / native_version / adj_verification out
    of the Authorization header."""
    g = lambda k: (re.search(k + r'="([^"]*)"', auth) or [None, ""])[1]
    return {"adj_signing_id": g("adj_signing_id") or "1500000",
            "headers_id": g("headers_id") or "10",
            "native_version": g("native_version") or "5.0.0",
            "adj_verification": g("adj_verification")}


def check(name, blob, fields, kind, client_sdk, auth):
    if len(blob) != 192:
        print(name, 'blob is %d bytes -- not adj9' % len(blob))
        return
    env = envelope_defaults(auth)
    val = dict(fields)
    val.update({"activity_kind": kind, "client_sdk": client_sdk})
    val.update(env)
    # recover the signing second from the header law, near created_at
    dt = datetime.datetime.strptime(val["created_at"][:19],
                                    "%Y-%m-%dT%H:%M:%S")
    off = val["created_at"][-5:]
    tzsign = -1 if off[0] == "-" else 1
    tz_h, tz_m = tzsign * int(off[1:3]), tzsign * int(off[3:5])
    base = int((dt - datetime.timedelta(hours=tz_h, minutes=tz_m)
                ).replace(tzinfo=datetime.timezone.utc).timestamp())
    sec = next((base + i for i in range(-600, 600)
                if P.make_header(base + i) == blob[:16]), None)
    if sec is None:
        print(name, 'header law: no second found near created_at')
        return
    rec = D.whiten_body_inverse(blob[16:160], blob[:16])
    seed = int.from_bytes(rec[20:24], "big")
    head, cert, blk = rec[3:19], rec[25:45], rec[46:78]
    print(name)
    print('   second %s  seed %08x  cert %s (ours %s)'
          % (sec, seed, cert.hex()[:12], env))
    order = P.claim_key_order(val, kind)
    print('   our law (%d keys): mcc in law = %s'
          % (len(order), 'mcc' in order))
    padded, n = P.claims_padded(val, kind)
    got = P.record_block(head, seed, padded[:n], cert)
    print('   block, our law (no mcc/mnc):      %s'
          % ('MATCH' if got == blk else 'mismatch'))
    # hypothesis: mcc/mnc sorted into the profile
    law2 = [k for k in order]
    if 'mcc' not in law2:
        for k in ('mcc', 'mnc'):
            law2.append(k)
        law2 = [k for k in law2 if k != P.PIN]
        law2.sort()
        law2.append(P.PIN)
        tail_keys = [k for k in law2[len(order):]]  # keep block2/tail after?
    # simpler: rebuild explicitly -- profile+extras sorted, PIN, tail, block2
    prof, tail = P._GROUPS[kind]
    keys = ([k for k in sorted(set(prof) | {'mcc', 'mnc'}) if val.get(k)]
            + [P.PIN]
            + [k for k in sorted(tail) if val.get(k)]
            + [k for k in P.BLOCK2 if val.get(k)])
    raw = ''.join(val[k] for k in keys).encode('latin1')
    got2 = P.record_block(head, seed, raw, cert)
    print('   block, law + mcc/mnc sorted in:   %s'
          % ('MATCH' if got2 == blk else 'mismatch'))


# ---- the declic capture -----------------------------------------------------
z = zipfile.ZipFile(r'C:\Users\Apps\Downloads\declic_3oct_ctlogs_mi.saz')
for sid, kind in [('06', 'session'), ('07', 'click')]:
    c = z.read('raw/%s_c.txt' % sid).decode('utf-8', 'replace')
    head, _, body = c.partition('\r\n\r\n')
    auth = re.search(r'Authorization: (.+)', head).group(1)
    sdk = re.search(r'Client-SDK: (.+)', head).group(1).strip()
    fields = dict(urllib.parse.parse_qsl(body))
    blob = base64.b64decode(re.search(r'signature="([^"]+)"', auth).group(1))
    check('DEClic %s' % kind, blob, fields, kind, sdk, auth)

# ---- the penti golden saz (8 Sep, OnePlus, SIM) ------------------------------
g = json.load(open(r'..\adj9\rev\golden_saz.json'))
for sid, kind in [('s1', 'session'), ('s2', 'click')]:
    v = g[sid]
    auth = v.get('auth') or v.get('authorization') or v.get('headers', {}).get(
        'Authorization', '') if isinstance(v.get('headers'), dict) else v.get('auth', '')
    fields = v['params']
    sig = re.search(r'signature="([^"]+)"', auth or '').group(1)
    blob = base64.b64decode(sig)
    check('PENTI %s (8 Sep)' % kind, blob, fields, kind,
          'android5.7.0', auth)

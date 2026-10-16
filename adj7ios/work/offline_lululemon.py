# -*- coding: utf-8 -*-
"""Offline precondition for the lululemon replay rule: byte-exact mint of
every carved blob under adj7ios_pure (adj7ios/work/adj7ios_pure.py)."""
import json, os, re, sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7ios\work')
import adj7ios_pure as sg

CHLS = r"C:\Users\Apps\Downloads\lululemon_newapp_13may_ios11 (1).chls"
if not os.path.exists(CHLS):
    CHLS = r"C:\Users\Apps\Downloads\lululemon_newapp_13may_ios11.chls"
UA = "lululemonTurkiye/82 CFNetwork/3860.400.51 Darwin/25.3.0"
SDK = "react-native5.5.0@ios5.5.0"
HID, NV, ALGO, SID = "8", "3.62.0", "adj7", "1300000"

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj10ios')
from verify_chls import carve_chunk, find_map, parse_params

raw = open(CHLS, "rb").read().decode("latin-1")
sigs = list(re.finditer(r'Signature signature="([0-9A-Fa-f]{608})"', raw))
print('carved blobs:', len(sigs))
ok = 0
for m in sigs:
    back = raw[max(0, m.start() - 2500):m.start()]
    eps = [e for e in ("sdk_click", "session", "attribution", "event")
           if ("/" + e) in back]
    ep = eps[-1] if eps else "?"
    KIND = {"sdk_click": "click", "session": "session",
            "attribution": "attribution", "event": "event",
            "sdk_info": "info", "third_party_sharing":
            "third_party_sharing"}.get(ep, ep)
    mp = find_map(raw, m.start())
    params = parse_params(mp[1])
    sig_hex = m.group(1).upper()
    # second: brute-force in a window around sent_at second
    sent = params.get("sent_at")
    if not sent:
        continue
    mts = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)', sent)
    if mts:
        base = int(datetime.strptime(mts.group(1), "%Y-%m-%dT%H:%M:%S")
                   .replace(tzinfo=timezone.utc).timestamp()
                   - int(mts.group(2)) * 3600 - int(mts.group(3)) * 60)
    else:
        base = int(datetime.strptime(sent[:19], "%Y-%m-%dT%H:%M:%S")
                   .replace(tzinfo=timezone.utc).timestamp())
    SW = 300
    # nonce from the captured blob's record
    import hashlib
    blob = bytes.fromhex(sig_hex)
    # decrypt with SEED, IV=header to read nonce12 (adj7 iOS law)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(blob[:16])).decryptor()
        rec = dec.update(blob[16:272]) + dec.finalize()
        s = rec.split(b'\x00')[0].decode('latin1')
        ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
        rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
        import struct
        nonce12 = struct.pack('<Q', int(ra.strip())) + bytes.fromhex(rd)
    except Exception as e:
        print('  %-11s nonce-recover FAIL %r' % (ep, e)); continue
    hit = None
    for d in range(-SW, SW + 1):
        auth, blob2 = sg.sign_request(params, KIND, second=base + d,
                                      nonce12=nonce12, client_sdk=SDK)
        if blob2.hex().upper() == sig_hex:
            hit = base + d
            break
    print('  %-11s %s  (sent %s, second delta %s)'
          % (KIND, 'BYTE-EXACT' if hit is not None else 'MISMATCH',
             sent, (hit - base) if hit else None))
    if hit is not None:
        ok += 1
print('byte-exact: %d/%d' % (ok, len(sigs)))

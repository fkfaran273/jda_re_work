# -*- coding: utf-8 -*-
"""offline_steplaw_all.py -- re-run the offline byte-exact mint on every iOS
capture in the workspace WITH the same-second stream-step law:
  header = MINSTD stream seeded at the signing second; if the request is the
  2nd/3rd... sign within that same second, the stream ADVANCES (no reseed).
Reports each blob's (dsec, step) so a blob that previously needed step 1 is
visible."""
import glob
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

A31, M31 = sg._A31, sg._M31
PAT = 'signature="([0-9A-Fa-f]+)"'


def block(x):
    d = []
    for _ in range(8):
        x = (A31 * x) % M31
        d.append(x)
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b''.join(v.to_bytes(4, 'big') for v in w), x


def sec_of(sent):
    m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)',
                 sent)
    if not m:
        return int(datetime.strptime(sent[:19], '%Y-%m-%dT%H:%M:%S')
                   .replace(tzinfo=timezone.utc).timestamp())
    return int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')
               .replace(tzinfo=timezone.utc).timestamp()
               - int(m.group(2)) * 3600 - int(m.group(3)) * 60)


KIND = {'session': 'session', 'event': 'event', 'sdk_click': 'click',
        'attribution': 'attribution', 'sdk_info': 'info',
        'third_party_sharing': 'third_party_sharing'}


def run(dirpath, sdk, hid, nv):
    files = sorted(glob.glob(os.path.join(dirpath, '*_c.txt')))
    total = ok = 0
    for p in files:
        t = open(p, encoding='utf-8', errors='replace', newline='').read()
        a = re.search(PAT, t)
        if not a:
            continue
        sig = a.group(1).upper()
        head, _, body = t.partition('\r\n\r\n')
        line0 = t.split('\r\n', 1)[0]
        eps = [e for e in KIND if ('/' + e) in head or ('/' + e) in line0]
        ep = eps[-1] if eps else None
        if not ep:
            continue
        if line0.startswith('GET') and '?' in line0:
            q = line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
            params = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        else:
            params = dict(urllib.parse.parse_qsl(body.strip(),
                                                 keep_blank_values=True))
        if 'sent_at' not in params:
            continue
        total += 1
        blob = bytes.fromhex(sig)
        dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(blob[:16])).decryptor()
        rec = dec.update(blob[16:272]) + dec.finalize()
        s = rec.split(b'\x00')[0].decode('latin1')
        try:
            ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
            rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
            import struct
            nonce12 = struct.pack('<Q', int(ra.strip())) + bytes.fromhex(rd)
        except Exception:
            print('   %-28s record-parse FAIL' % os.path.basename(p)); continue
        sec = sec_of(params['sent_at'])
        kind = KIND[ep]
        hit = None
        for dsec in range(-300, 301):
            x = int(sec + dsec) % M31 or 1
            for step in range(3):
                h, x = block(x)
                if h == blob[:16]:
                    hit = (dsec, step)
                    break
            if hit:
                break
        whole = False
        if hit:
            dsec, step = hit
            x = int(sec + dsec) % M31 or 1
            h = None
            for _ in range(step + 1):
                h, x = block(x)
            claims = sg.build_claims(kind, params, client_sdk=sdk,
                                     include_block2=True)
            import hmac as _h, hashlib as _hh
            H = sg.commitment_digest(claims, nonce12)
            body_m = sg.cbc_encrypt(sg.build_record(H, nonce12), h)
            mine = h + body_m + _h.new(sg.DK37, body_m,
                                       _hh.sha256).digest()
            whole = mine.hex().upper() == sig
        if whole:
            ok += 1
        print('   %-28s %-20s dsec=%-4s step=%s %s'
              % (os.path.basename(p), ep, hit[0] if hit else None,
                 hit[1] if hit else None,
                 'BYTE-EXACT' if whole else 'MISMATCH'))
    print('   -> %d/%d byte-exact\n' % (ok, total))
    return ok, total


TOT = OK = 0
for name, sdk, hid, nv in (
        ('saz_berain/raw', 'ios5.5.2', '8', '3.62.0'),
        ('saz_hunchdating/raw', 'flutter5.5.0@ios5.5.0', '8', '3.62.0'),
        ('saz_new/raw', None, None, None)):
    if not os.path.isdir(os.path.join(HERE, name)):
        continue
    print('===', name)
    if sdk is None:
        # hanaf Android rows use the Android law -- skip here
        print('   (Android adj7 capture -- different header law)')
        continue
    o, t = run(os.path.join(HERE, name), sdk, hid, nv)
    OK += o; TOT += t
print('TOTAL iOS byte-exact: %d/%d' % (OK, TOT))

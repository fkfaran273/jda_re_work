"""check_theirs.py -- what went wrong in the AutoLabs penti run (calllog.txt)?

1. pull every Authorization signature out of the log, base64-decode, and
   check the blob is a well-formed 192-byte adj9 blob
2. recover the signing second from the header (bionic rand law)
3. decode the whitened record (adj9_decode) -> seed, head, cert, block
4. rebuild the claims string from the POSTed fields with OUR claims law and
   check the block law reproduces the decoded block
   -> if it matches, their signer is byte-exact ours and signing is NOT
      why the install went Organic
"""
import base64
import json
import re
import sys

import adj9_decode as D
import adj9_pure as P

LOG = r'C:\Users\Apps\Downloads\calllog.txt'
log = open(LOG, encoding='utf-8').read()

# the log carries JSON-ish dumps with escaped quotes: signature=\"...\"
sigs = re.findall(r'signature=\\"([A-Za-z0-9+/=]+)\\"', log)
print('signatures found:', len(sigs))

blobs = []
for s_ in sigs:
    b = base64.b64decode(s_)
    if not blobs or blobs[-1] != b:
        blobs.append(b)
print('unique blobs:', [len(b) for b in blobs])

# --- the POST bodies, anchored on the endpoint lines -----------------------
def data_after(marker):
    """The first Data:{...} JSON map after `marker` in the log."""
    i = log.find(marker)
    m = re.compile(r'Data:(\{.*?\})\n').search(log, i)
    if not m:
        return None
    try:
        return json.loads(m.group(1).replace("'", '"'))
    except Exception:
        return None


session_fields = data_after('post https://app.adjust.com/session')
click_fields = data_after('post https://app.adjust.com/sdk_click')
print('session fields:', bool(session_fields), ' click fields:', bool(click_fields))

CAMPAIGN = {
    "app_token": "jut9tib0eeps",
    "client_sdk": "android5.7.0",
    "adj_signing_id": "1500000",
    "headers_id": "10",
    "native_version": "5.0.0",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "cert_sha1": "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
}


def check_one(name, blob, fields, kind):
    if len(blob) != 192:
        print(name, 'BLOB IS %d BYTES -- not adj9!' % len(blob))
        return
    # recover the signing second from the header
    sec = None
    for t in range(1791000700, 1791000760):
        if P.make_header(t) == blob[:16]:
            sec = t
            break
    print('%s: header second = %s' % (name, sec))
    if sec is None:
        print(name, 'header does not match the bionic rand law around the log time!')
        return
    record = D.whiten_body_inverse(blob[16:160], blob[:16])
    seed = int(record[20:24].encode('hex'), 16) if hasattr(record, 'encode') \
        else int.from_bytes(record[20:24], 'big')
    head = record[3:19]
    cert = record[25:45]
    block = record[46:78]
    print('%s: seed %08x  cert %s  (cert ok: %s)'
          % (name, seed, cert.hex(),
             cert.hex() == CAMPAIGN['cert_sha1']))
    # rebuild the claims the way OUR law does, from the POSTed fields
    val = dict(fields)
    val.update({"activity_kind": kind,
                "client_sdk": CAMPAIGN['client_sdk'],
                "adj_signing_id": CAMPAIGN['adj_signing_id'],
                "headers_id": CAMPAIGN['headers_id'],
                "native_version": CAMPAIGN['native_version'],
                "adj_verification": CAMPAIGN['adj_verification']})
    try:
        padded, n = P.claims_padded(val, kind)
    except Exception as e:
        print(name, 'claims law error:', e)
        return
    got = P.record_block(head, seed, padded[:n], cert)
    print('%s: block law %s' % (name, 'MATCHES -- their signer is our law'
                                if got == block else 'MISMATCH'))
    digest_ok = P.record_digest(blob[16:160]) == blob[160:192]
    print('%s: digest law %s' % (name, 'MATCHES' if digest_ok else 'MISMATCH'))


check_one('session', blobs[0], session_fields, 'session')
if click_fields and len(blobs) > 1:
    check_one('click  ', blobs[1], click_fields, 'click')

# --- the click link ---------------------------------------------------------
link = re.search(r'LINK : (\S+)', log)
print()
print('click link has gps_adid param:', 'gps_adid=' in (link.group(1) if link else ''))
print('click link has idfa param  :', 'idfa=' in (link.group(1) if link else ''))
ref = re.search(r'Referrer:(\S+)', log)
print('reftag:', ref.group(1)[:60] if ref else None)
print('click_id in link == device_data adid:',
      'click_id=f37e0363' in (link.group(1) if link else ''))
print('install gps_adid == the idfa value:',
      bool(session_fields) and session_fields.get('gps_adid') == '73bcc6fa-5661-4f11-b88f-f774747caa4b')

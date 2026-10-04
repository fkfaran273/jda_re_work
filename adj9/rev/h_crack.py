# h_crack.py - what does the signature attest, and can WE compute it?
#  1. locate the 32-byte mac_doFinal (H) inside the golden 192-byte blob
#  2. brute-force (key, message, algo) against that H
import base64
import hashlib
import hmac
import json
import os
import struct

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
gi = W['golden_sign_input_idx']
ni = W['golden_nsign_idx']
blob_hex = F['target']['blob_hex']
blob = bytes.fromhex(blob_hex)
print('golden nsign idx=%d sign_input idx=%d' % (ni, gi))
print('blob %d B' % len(blob))
print('nsigns:', len(W['nsigns']), ' mac_doFinal:', len(W['mac_doFinal']),
      ' sign_inputs:', len(W['sign_inputs']))
nsign = bytes.fromhex(W['nsigns'][ni]['hex'])
print('nsign %d B == blob: %s' % (len(nsign), nsign == blob))
mac = bytes.fromhex(W['mac_doFinal'][gi]['hex'])
print('mac_doFinal[%d] = %s  (%d B)' % (gi, mac.hex(), len(mac)))

# ---- 1. is the mac inside the blob? --------------------------------------
pos = blob.find(mac)
print('mac inside blob at byte offset:', pos if pos >= 0 else 'NOT FOUND')
if pos < 0:
    # maybe stored as dwords reversed, or a sub-slice
    for off in range(0, len(blob) - 32 + 1, 4):
        if blob[off:off + 32] == mac:
            print('  found at dword offset', off // 4)
            break
    else:
        # search for any 8-byte window of the mac
        for n in (8, 16, 24):
            for off in range(0, 33 - n):
                if blob.find(mac[off:off + n]) >= 0:
                    print('  partial %dB of mac from its offset %d present at blob %d'
                          % (n, off, blob.find(mac[off:off + n])))
# also dump all 48 dwords so we can eyeball
print('\nblob dwords:')
for i in range(0, 48, 4):
    print('  [%2d] %s' % (i, ' '.join('%08x' % d for d in
                                      struct.unpack('>4I', blob[i * 4:i * 4 + 16]))))

# ---- 2. what message was signed? ----------------------------------------
si = W['sign_inputs'][gi]
tostr = si.get('toString') or si.get('text') or ''
order = si.get('order') or ''
D10 = [d for d in F['descs'] if d['build_idx'] == 10][0]['data_hex']
d10 = bytes.fromhex(D10)
print('\nmessage candidates:')
print('  desc10 %d B' % len(d10))
print('  toString %d B' % len(tostr))
print('  order %d B' % len(order))
print('  canonical(0) %s' % str(W['canonicals'][gi])[:120])
canon = W['canonicals'][gi].get('text') or ''
print('  canonical %d B' % len(canon))
hdr16 = blob[:16]
print('  header16', hdr16.hex())

msgs = {
    'desc10': d10,
    'desc10+utf8(noop)': d10,
    'toString': tostr.encode(),
    'order': order.encode(),
    'canonical': canon.encode(),
    'hdr16+desc10': hdr16 + d10,
    'desc10+hdr16': d10 + hdr16,
    'blob16..192(body)': blob[16:],
    'full_blob': blob,
    'hdr16': hdr16,
}
keys = {
    'empty': b'',
    'key2': b'key2',
    'app_token': b'jut9tib0eeps',
    'adj_verification': b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'verif_b64dec': base64.b64decode('KlcAG2cbAAsKSl1KVi0FGiJbDHMI'),
    'app_token+verif': b'jut9tib0eeps' + b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'verif+app_token': b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI' + b'jut9tib0eeps',
    'package': b'com.penti.app',
    'token+package': b'jut9tib0eepscom.penti.app',
    'sha256(app_token)': hashlib.sha256(b'jut9tib0eeps').digest(),
    'sha256(verif)': hashlib.sha256(b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI').digest(),
}
hits = []
for kn, k in keys.items():
    for mn, m in msgs.items():
        for an, h in (('hmac-sha256', lambda k, m: hmac.new(k, m, hashlib.sha256).digest()),
                      ('sha256', lambda k, m: hashlib.sha256(m).digest()),
                      ('hmac-sha1', lambda k, m: hmac.new(k, m, hashlib.sha1).digest())):
            try:
                out = h(k, m)
            except Exception:
                continue
            if out[:len(mac)] == mac or out == mac:
                hits.append((an, kn, mn))
                print('  *** MATCH %s key=%s msg=%s' % (an, kn, mn))
print('\nHITS:', hits or 'none (brute force %d combos)' % (len(keys) * len(msgs) * 3))

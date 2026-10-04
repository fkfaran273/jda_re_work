# cert_d9.py - is d9 (constant across all 10 signings) a certificate digest?
import hashlib
import json
import os
import struct

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
D9 = 'fad0f10d60f93c17937b2f1eb6c09691ae7d74bd'
D8 = 'bffffffffffffd1f0007000000000000'
print('d9 =', D9, '(%d B)' % (len(D9) // 2))
print('d8 =', D8)
print()

cert = open(os.path.join(REV, 'cert_s0_0.der'), 'rb').read()
print('cert_s0_0.der: %d bytes' % len(cert))
for algo in ('sha1', 'sha256', 'sha512', 'md5'):
    h = hashlib.new(algo, cert)
    print('  %-7s %s' % (algo, h.hexdigest()))
    if h.hexdigest()[:32] in D9 or h.hexdigest().startswith('fad0'):
        print('    ^^ MATCHES d9 window')
print()

# d9 magic + remainder
magic, rest = D9[:8], D9[8:]
print('d9 magic=%s rest=%s' % (magic, rest))
print('rest (16 B) as hex =', rest)

# try: SHA-256 truncated to 16 vs rest; SHA-1 truncated; cert pubkey
try:
    from cryptography import x509
    c = x509.load_der_x509_certificate(cert)
    spki = c.public_key().public_bytes(
        __import__('cryptography.hazmat.primitives.serialization',
                   fromlist=['x']).Encoding.DER,
        __import__('cryptography.hazmat.primitives.serialization',
                   fromlist=['x']).PublicFormat.SubjectPublicKeyInfo)
    print('  SPKI %d B sha1=%s' % (len(spki), hashlib.sha1(spki).hexdigest()))
except Exception as e:
    print('  (no cryptography module: %s)' % type(e).__name__)

# brute the obvious: any digest of cert (or its tail 700 etc) containing d9's rest
cands = {}
for trim in range(0, 40):
    for algo in ('sha1', 'sha256', 'md5'):
        cands['%s(cert[%d:])' % (algo, trim)] = hashlib.new(algo, cert[trim:]).hexdigest()
        cands['%s(cert[:-%d])' % (algo, trim)] = (
            hashlib.new(algo, cert[:len(cert) - trim]).hexdigest() if trim else '')
hits = [k for k, v in cands.items() if v and rest in v]
print('  d9-rest found inside digest:', hits or 'NONE')

# and the golden blob's other constants
FIN = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
d9b = [x for x in FIN['descs'] if x['build_idx'] == 9][0]['data_hex']
print()
print('fin_descs d9 =', d9b, ' == all_signings d9:', d9b == D9)
print('blob hex len', len(FIN['target']['blob_hex']) // 2)
blob = bytes.fromhex(FIN['target']['blob_hex'])
print('blob contains d9?', bytes.fromhex(D9) in blob)
print('blob contains d8?', bytes.fromhex(D8) in blob)
i = blob.find(bytes.fromhex(D9))
print('d9 at blob offset', i)
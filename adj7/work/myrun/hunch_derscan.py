import hashlib
d = open('fresh_hunch_base.apk', 'rb').read()
print('apk len', len(d))
try:
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.hazmat.backends import default_backend
    hits = 0
    for i in range(len(d) - 4):
        if d[i] == 0x30 and d[i+1] == 0x82:
            ln = (d[i+2] << 8) | d[i+3]
            if 500 < ln < 3000:
                blob = d[i:4+i+ln]
                try:
                    c = load_der_x509_certificate(blob, default_backend())
                    print('DER @0x%x len %d sha1 %s subj %s' % (i, ln, hashlib.sha1(blob).hexdigest(), c.subject.rfc4514_string()[:60]))
                    hits += 1
                    if hits > 6: break
                except Exception:
                    pass
    print('hits', hits)
except ImportError as e:
    print('no crypto lib', e)

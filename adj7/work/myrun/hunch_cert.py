import zipfile, hashlib
# cert SHA1 (same method as hanaf proof: DER scan by SHA1)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import re
z = zipfile.ZipFile('fresh_hunch_base.apk')
names = z.namelist()
rsa = [n for n in names if n.startswith('META-INF/') and (n.endswith('.RSA') or n.endswith('.DSA') or n.endswith('.EC'))]
print('cert files:', rsa)
for r in rsa:
    d = z.read(r)
    print(r, len(d))
    print(' sha1:', hashlib.sha1(d).hexdigest())
# libsigner hash + pool key
z2 = zipfile.ZipFile('fresh_hunch_arm64.apk')
so = [n for n in z2.namelist() if n.endswith('.so')]
print('so:', so)
for n in so:
    if 'signer' in n:
        d = z2.read(n)
        open('fresh_hunch_libsigner.so', 'wb').write(d)
        print(n, len(d), hashlib.sha256(d).hexdigest()[:16])

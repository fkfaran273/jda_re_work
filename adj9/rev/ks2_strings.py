# ks2_strings.py - what protects soft-KeyMint key blobs? (strings of keystore2)
import re

D = open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\keystore2.bin', 'rb').read()
print('keystore2 %d bytes' % len(D))
strs = [(m.start(), m.group().decode('latin1'))
        for m in re.finditer(rb'[\x20-\x7e]{5,160}', D)]
print('strings:', len(strs))
KEYS = ('seed', 'Seed', 'super', 'Super', 'SUPER', 'aes', 'AES', 'encrypt', 'Encrypt',
        'keymint', 'KeyMint', 'KeyMaster', 'soft', 'Soft', 'SOFT',
        'ondevice-signing', 'user_0', 'persistent', 'blob', 'Blob',
        'iv', 'nonce', 'tag', 'software', 'clearOnExit', 'km_uuid')
seen = set()
for off, s in strs:
    if any(k in s for k in KEYS) and s not in seen and len(s) > 6:
        seen.add(s)
        print('  0x%06x  %s' % (off, s[:140]))
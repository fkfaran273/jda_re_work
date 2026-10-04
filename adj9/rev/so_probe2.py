# so_probe2.py - dynsym + strings + crypto constant scan on libsigner.so
import os
import re
import struct

SO = r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
data = open(SO, 'rb').read()
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3A)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size = struct.unpack_from('<IIQQQQ', data, o)
    link, info = struct.unpack_from('<II', data, o + 40)
    secs.append(dict(name=name, typ=typ, addr=addr, off=off, size=size,
                     link=link, info=info))
shstr = secs[e_shstrndx]
def nm(n):
    e = data.index(b'\0', shstr['off'] + n)
    return data[shstr['off'] + n:e].decode()
for s in secs:
    s['nm'] = nm(s['name'])

print('=== .dynsym (DYNSYM) ===')
for s in secs:
    if s['typ'] == 11 and s['size']:
        strtab = secs[s['link']]
        cnt = s['size'] // 24
        print('  %s: %d entries' % (s['nm'], cnt))
        for j in range(cnt):
            o = s['off'] + j * 24
            stn, sti, sto, shx = struct.unpack_from('<IBBH', data, o)
            val, sz = struct.unpack_from('<QQ', data, o + 8)
            e = data.index(b'\0', strtab['off'] + stn)
            name = data[strtab['off'] + stn:e].decode()
            print('    %-44s val=0x%08x sz=%-6d type=%d' % (name, val, sz, sti & 0xf))

print()
print('=== strings (len>=5) ===')
strs = [(m.start(), m.group().decode('latin1'))
        for m in re.finditer(rb'[\x20-\x7e]{5,200}', data)]
print('  total strings: %d' % len(strs))
KEYS = ('adjust', 'sig', 'sign', 'Sign', 'key', 'Key', 'hmac', 'Hmac', 'HMAC',
        'SHA', 'sha', 'AES', 'aes', 'crypt', 'Crypt', 'Ljava', '()V', '()',
        'Keystore', 'keystore', 'Certificate', 'attest', 'Attest', 'Base64',
        'klc', 'Klc', 'nonce', 'Nonce', 'salt', 'Salt', 'device', 'android')
seen = set()
for off, s in strs:
    if any(k in s for k in KEYS) and s not in seen:
        seen.add(s)
        print('  0x%06x  %s' % (off, s[:150]))
print('  (%d interesting)' % len(seen))

print()
print('=== crypto constants scan ===')
PATS = {
    'SHA256_IV_BE': bytes.fromhex('6a09e667bb67ae853c6ef372a54ff53a'),
    'SHA256_IV_LE': bytes.fromhex('67e6096a85ae67bb72f36e3c3af54fa5'),
    'SHA1_IV_BE': bytes.fromhex('67452301efcdab8998badcfe10325476c3d2e1f0'),
    'SHA1_IV_LE': bytes.fromhex('0123456789abcdef'),
    'MD5_IV_LE': bytes.fromhex('0123456789abcdeffedcba9876543210'),
    'AES_SBOX': bytes.fromhex('637c777bf26b6fc53001672bfed7ab76'),
    'AES_TE0': bytes.fromhex('c66363a5f87c7c84ee777799f67b7b8d'),
    'CHACHA_SIGMA': b'expand 32-byte k',
    'BLAKE2_IV': bytes.fromhex('6a09e667f3bcc908bb67ae8584caa73b'),
    'KLC_VERIF': b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'D9_MAGIC': bytes.fromhex('fad0f10d'),
    'D8_CONST': bytes.fromhex('bffffffffffffd1f'),
}
for name, pat in PATS.items():
    hits = [m.start() for m in re.finditer(re.escape(pat), data)]
    print('  %-14s %d hits %s' % (name, len(hits),
                                  ['0x%x' % h for h in hits[:6]]))
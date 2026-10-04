# lkc_syms.py - exports of libkeystore2_crypto.so (what to hook for the HMAC key)
import struct
import sys

P = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\lkc.so'
D = open(P, 'rb').read()
print('%s  %d bytes' % (P.split('\\')[-1], len(D)))
e_shoff = struct.unpack_from('<Q', D, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', D, 0x3A)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size = struct.unpack_from('<IIQQQQ', D, o)
    link, info = struct.unpack_from('<II', D, o + 40)
    secs.append(dict(nm=name, typ=typ, addr=addr, off=off, size=size, link=link))
shstr = secs[e_shstrndx]
for s in secs:
    e = D.index(b'\0', shstr['off'] + s['nm'])
    s['name'] = D[shstr['off'] + s['nm']:e].decode()
sec = {s['name']: s for s in secs}
strt = sec.get('.dynstr') or sec.get('.strtab')
dsym = sec['.dynsym']
cnt = dsym['size'] // 24
out = []
for j in range(cnt):
    o = dsym['off'] + j * 24
    stn, sti, sto, shx = struct.unpack_from('<IBBH', D, o)
    val, sz = struct.unpack_from('<QQ', D, o + 8)
    if stn == 0:
        continue
    e = D.index(b'\0', strt['off'] + stn)
    name = D[strt['off'] + stn:e].decode()
    out.append((name, val, sz, shx, sti))
print('dynsym entries: %d (defined: %d)'
      % (len(out), len([x for x in out if x[3] != 0])))
print()
KEY = ('HMAC', 'hmac', 'SHA256', 'sha256', 'SHA1', 'AES_gcm', 'aes_gcm', 'gcm',
       'HKDF', 'EVP', 'CMAC', 'cmac', 'Digest')
print('=== relevant exports ===')
for name, val, sz, shx, sti in out:
    if any(k in name for k in KEY):
        print('  %-40s 0x%06x sz=%-5d shndx=%-4d type=%d'
              % (name, val, sz, shx, sti & 0xf))
print()
print('=== all defined exports (if few) ===')
defs = [x for x in out if x[3] != 0]
if len(defs) < 60:
    for name, val, sz, shx, sti in defs:
        print('  %-40s 0x%06x' % (name, val))
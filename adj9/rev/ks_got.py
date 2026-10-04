# ks_got.py - map target imports to their GOT slot VAs (for hooking by pointer)
import json
import struct

P = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\keystore2.bin'
D = open(P, 'rb').read()
e_shoff = struct.unpack_from('<Q', D, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', D, 0x3A)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size = struct.unpack_from('<IIQQQQ', D, o)
    link, info = struct.unpack_from('<II', D, o + 40)
    secs.append(dict(nm=name, typ=typ, addr=addr, off=off, size=size,
                     link=link, info=info))
shstr = secs[e_shstrndx]
for s in secs:
    e = D.index(b'\0', shstr['off'] + s['nm'])
    s['name'] = D[shstr['off'] + s['nm']:e].decode()
sec = {s['name']: s for s in secs}

# needed libs
dyn = sec['.dynamic']
NEEDED = {}
strt = sec['.dynstr']
o = dyn['off']
while o < dyn['off'] + dyn['size']:
    tag, val = struct.unpack_from('<QQ', D, o)
    o += 16
    if tag == 0:
        break
    if tag == 1:
        e = D.index(b'\0', strt['off'] + val)
        NEEDED.setdefault('NEEDED', []).append(D[strt['off'] + val:e].decode())
    if tag == 14:
        NEEDED['SONAME'] = val
print('NEEDED:', NEEDED.get('NEEDED'))
print()

# dynsym
dsym = sec['.dynsym']
names = {}
cnt = dsym['size'] // 24
for j in range(cnt):
    o = dsym['off'] + j * 24
    stn, sti, sto, shx = struct.unpack_from('<IBBH', D, o)
    if stn == 0:
        continue
    e = D.index(b'\0', strt['off'] + stn)
    names[j] = D[strt['off'] + stn:e].decode()

TARGETS = ('AES_gcm_decrypt', 'AES_gcm_encrypt', 'HKDFExpand', 'HKDFExtract',
           'ECDHComputeKey')
va = {}
for relsec in ('.rela.plt', '.rela.dyn'):
    s = sec.get(relsec)
    if not s:
        continue
    k = s['size'] // 24
    for j in range(k):
        o = s['off'] + j * 24
        r_off, r_info, r_add = struct.unpack_from('<QQq', D, o)
        sym = r_info >> 32
        nm = names.get(sym)
        if nm in TARGETS:
            va[nm] = r_off
            print('%-16s %-10s got_va=0x%x  addend=%d' % (nm, relsec, r_off, r_add))
print()
print(json.dumps(va))
open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ks_got.json', 'w').write(
    json.dumps(va))
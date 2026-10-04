# ks2_syms.py - can we hook the AES-GCM unwrap inside keystore2? (symbol hunt)
import struct

D = open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\keystore2.bin', 'rb').read()
e_shoff = struct.unpack_from('<Q', D, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', D, 0x3A)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size = struct.unpack_from('<IIQQQQ', D, o)
    link, info = struct.unpack_from('<II', D, o + 40)
    secs.append(dict(name=name, typ=typ, addr=addr, off=off, size=size,
                     link=link, info=info))
shstr = secs[e_shstrndx]
def nm(n):
    e = D.index(b'\0', shstr['off'] + n)
    return D[shstr['off'] + n:e].decode()
for s in secs:
    s['nm'] = nm(s['name'])

print('=== symbol tables ===')
for s in secs:
    if s['typ'] in (2, 11) and s['size']:
        strtab = secs[s['link']]
        cnt = s['size'] // 24
        print('%s: %d syms' % (s['nm'], cnt))
        hits = []
        for j in range(cnt):
            o = s['off'] + j * 24
            stn, sti, sto, shx = struct.unpack_from('<IBBH', D, o)
            val, sz = struct.unpack_from('<QQ', D, o + 8)
            if stn == 0:
                continue
            e = D.index(b'\0', strtab['off'] + stn)
            name = D[strtab['off'] + stn:e].decode()
            if any(k in name for k in ('AES_gcm', 'aes_gcm', 'gcm_decrypt',
                                       'EVP_AEAD', 'gcm_encrypt', 'hkdf',
                                       'HKDF', 'ecdh', 'ECDH', 'unwrap')):
                hits.append((name, val, sz))
        for name, val, sz in hits:
            print('   %-46s 0x%08x sz=%d' % (name, val, sz))
        if not hits:
            print('   (no AES-GCM/HKDF/ECDH symbols exposed)')
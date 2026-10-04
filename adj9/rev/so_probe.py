# so_probe.py - offline static recon of libsigner.so (ELF64 ARM64, no deps).
# Goal: locate the native entry points that build d2 and d4(H), and any key material.
import os
import struct
import sys

SO = r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
data = open(SO, 'rb').read()
print('%s  %d bytes' % (os.path.basename(SO), len(data)))
assert data[:4] == b'\x7fELF'
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3A)
print('sections: %d  shoff=0x%x' % (e_shnum, e_shoff))

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
print()
print('name                 addr         off          size')
for s in secs:
    if s['nm'] and s['size']:
        print('  %-18s 0x%08x   0x%08x   %8d' % (s['nm'], s['addr'], s['off'], s['size']))

print()
print('=== symbol tables ===')
for s in secs:
    if s['typ'] == 2 and s['size']:          # SYMTAB
        strtab = secs[s['link']]
        cnt = s['size'] // 24
        print('  %s: %d syms' % (s['nm'], cnt))
        named = []
        for j in range(cnt):
            o = s['off'] + j * 24
            stn, sti, sto, shx = struct.unpack_from('<IBBH', data, o)
            val, sz = struct.unpack_from('<QQ', data, o + 8)
            if stn == 0:
                continue
            e = data.index(b'\0', strtab['off'] + stn)
            name = data[strtab['off'] + stn:e].decode()
            named.append((name, val, sz, sti))
        interesting = [x for x in named
                       if x[0].startswith('Java_') or 'JNI' in x[0] or 'hmac' in x[0].lower()
                       or 'sign' in x[0].lower() or 'sha' in x[0].lower()
                       or 'Key' in x[0] or 'crypt' in x[0].lower()]
        for name, val, sz, sti in interesting[:60]:
            print('    %-60s 0x%08x  %d' % (name[:60], val, sz))
        if not interesting:
            print('    (none matching Java_/JNI/sign/hmac/sha/key/crypt) -- exports:')
            for name, val, sz, sti in named[:40]:
                print('      %-58s 0x%08x' % (name[:58], val))
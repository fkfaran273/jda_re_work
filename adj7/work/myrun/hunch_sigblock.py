import struct, hashlib
d = open('fresh_hunch_base.apk', 'rb').read()
# find EOCD
eocd = d.rfind(b'\x50\x4b\x05\x06')
assert eocd > 0
cd_off = struct.unpack('<I', d[eocd+16:eocd+20])[0]
# signing block magic just before central dir
magic = b'APK Sig Block 42'
assert d[cd_off-16:cd_off] == magic, d[cd_off-16:cd_off]
sb_size = struct.unpack('<Q', d[cd_off-24:cd_off-16])[0]
sb_start = cd_off - 24 - sb_size + 8  # block incl leading size? layout: uint64 size, pairs..., uint64 size, magic
# pairs start after first uint64
pos = cd_off - 24 - sb_size + 8
end = cd_off - 24
found = {}
while pos < end:
    ln = struct.unpack('<Q', d[pos:pos+8])[0]
    iid = struct.unpack('<I', d[pos+8:pos+12])[0]
    found.setdefault(iid, []).append((pos, ln))
    pos += 8 + ln
print('block ids:', {hex(k): len(v) for k, v in found.items()})
# v2 id 0x7109873a
for pos, ln in found.get(0x7109873a, []):
    p = pos + 12
    nsigners = struct.unpack('<I', d[p:p+4])[0]; p += 4
    print('signers:', nsigners)
    for _ in range(nsigners):
        slen = struct.unpack('<I', d[p:p+4])[0]; p += 4
        send = p + slen
        sdlen = struct.unpack('<I', d[p:p+4])[0]; p += 4  # signed data len
        # signed data: digests, certs, ...
        q = p
        ndig = struct.unpack('<I', d[q:q+4])[0]; q += 4
        for _ in range(ndig):
            dl = struct.unpack('<I', d[q:q+4])[0]; q += 4
            q += 4 + struct.unpack('<I', d[q+4:q+8])[0]  # sig alg + digest (skip precisely below)
        # redo carefully: each digest = uint32 len, int32 alg, uint32 dlen, bytes
        q = p + 4
        for _ in range(ndig):
            dl = struct.unpack('<I', d[q:q+4])[0]
            alg = struct.unpack('<i', d[q+4:q+8])[0]
            dlen = struct.unpack('<I', d[q+8:q+12])[0]
            q += 4 + dl
        ncert = struct.unpack('<I', d[q:q+4])[0]; q += 4
        print('certs:', ncert)
        for _ in range(ncert):
            cl = struct.unpack('<I', d[q:q+4])[0]; q += 4
            cert = d[q:q+cl]; q += cl
            print(' cert DER len', cl, 'sha1', hashlib.sha1(cert).hexdigest(), 'sha256', hashlib.sha256(cert).hexdigest()[:32])
        p = send

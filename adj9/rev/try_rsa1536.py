import re, glob, base64, collections
logs=glob.glob("cap/*.log")
blobs=collections.OrderedDict()
for lf in logs:
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"key2_hex=([0-9a-f]{384})", data):
        blobs.setdefault(bytes.fromhex(m.group(1)), lf)
    for m in re.finditer(r'signature="([A-Za-z0-9+/=]{300,360})"', data):
        try: b=base64.b64decode(m.group(1))
        except: continue
        if len(b)==192: blobs.setdefault(b, lf)
bs=list(blobs.keys())

# 1) UTF-8 feature of RSA: m^65537 mod n. If raw RSA-1536 with e=65537,
#    ciphertext = M^65537 mod n for plaintext M < n. Try common structure:
#    M = 0x00 || 0x02 pad... but that's for 2048-bit. For "signature over data"
#    with PKCS1 v1.5, M = 0x0001 FF..FF 00 DigestInfo. M would start 0x0001ff...
#    Then C = M^65537 mod n, and C mod 2^k is random. Top byte <0x80 aligns
#    with forcing M < 2^1535 by prepending 0x00... but that byte would be stripped.
# 2) Check: does any blob, treated as big-endian int, share structure?
#    RSA output is < n; if n is exactly 2^1535 - something, C's top nibble <8.
#    P(top byte < 0x80) for uniform mod odd n ≈ (2^1527 % ... ) ~ 0.5 only if n<2^1535.
#    We observe 26/26 top-bytes <0x80 => P(no) = 2^-26 unless structural.
#    => consistent with signature computed as I2OSP(1536/8=192) of a value < 2^1535.
# 3) Also test RSA "NO_PADDING"? Then C=M; M would need < n, but M is arbitrary -> no.
# 4) Test GCD-like: check if C values share factor? can't without n.
# 5) Blobs as little-endian int? Check LE top byte (last byte) distribution:
last=[b[191] for b in bs]
print("last-byte >=0x80 count:", sum(1 for x in last if x>=0x80), "/", len(bs))
# 6) Check bytes 16..23 high-bit pattern of FIRST ct block across blobs:
for i in range(16,24):
    hi=sum(1 for b in bs if b[i]&0x80)
    print("byte%d hi=%d/%d"%(i,hi,len(bs)))
# 7) Correlation: any two blobs sharing 16-byte prefix AND any longer run?
from collections import defaultdict
pre=defaultdict(list)
for idx,b in enumerate(bs):
    pre[b[:16]].append(idx)
dups={k:v for k,v in pre.items() if len(v)>1}
print("shared 16B prefixes:", {k.hex():v for k,v in dups.items()})

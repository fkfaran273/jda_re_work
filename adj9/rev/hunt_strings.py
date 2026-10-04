# hunt_strings.py — search libsigner.so for XOR-0x40 encodings of known strings
import struct
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
targets=[b"putInt",b"java/nio/ByteBuffer",b"SecureRandom",b"nextInt",b"HmacSHA256",
         b"AndroidKeyStore",b"secret_key",b"signing_id",b"signing",b"key2",
         b"key1",b"rand",b"srand",b"android_id",b"raw_",b"sha",b"SHA",b"AES",
         b"WRAP",b"wrap",b"RSA",b"ECB",b"GCM",b"RSA/ECB/PKCS1Padding",
         b"SecretKeySpec",b"IvParameterSpec",b"adjust_keys",b"encrypted_key",
         b"ByteBuffer",b"order",b"position",b"array",b"header",b"envelope",
         b"Signature",b"java/security",b"javax/crypto",b"java/lang/Integer",
         b"java/lang/Long",b"java/lang/String",b"valueOf",b"toHexString",
         b"getMessageDigest",b"X509",b"trust",b"BKS",b"BouncyCastle"]
def xor40(b): return bytes(c^0x40 for c in b)
for t in targets:
    enc=xor40(t)
    hits=[]
    start=0
    while True:
        idx=data.find(enc,start)
        if idx<0: break
        hits.append(idx); start=idx+1
        if len(hits)>3: break
    plain=data.find(t)
    tag=[]
    if hits: tag.append("ENC@0x%x" % hits[0])
    if plain>=0: tag.append("plain@0x%x"%plain)
    print("%-28s %s"%(t.decode(), " ".join(tag) if tag else "-"))

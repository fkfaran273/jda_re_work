import re, glob, base64, collections
# collect blobs
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

K1=bytes.fromhex("f065595e09288254f06195ac44cb3e1917c217bca57fea117de05149475ac05b")
K2=bytes.fromhex("3cd000451739baaac19dcc1f3f686d0dc302cacdd32be061eb842100c4f28f48")

# pure-python AES (no deps guaranteed? try Crypto first)
try:
    from Crypto.Cipher import AES
    have=True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        have=True
    except ImportError:
        have=False
print("crypto lib:", have)
if have:
    def dec(key, iv, ct, mode):
        if mode=="CBC": c=AES.new(key, AES.MODE_CBC, iv)
        elif mode=="ECB": c=AES.new(key, AES.MODE_ECB)
        elif mode=="CTR":
            from Crypto.Util import Counter
            c=AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv,"big")))
        return c.decrypt(ct)
    for kname,K in (("f065",K1),("3cd0",K2)):
        for mode in ("CBC","ECB","CTR"):
            ok=0; samples=[]
            for b in bs[:25]:
                iv=b[:16]; ct=b[16:]
                pt=dec(K,iv,ct,mode)
                padok = 1<=pt[-1]<=16 and pt[-pt[-1]:]==bytes([pt[-1]])*pt[-1]
                printable=sum(1 for x in pt if 32<=x<127)/len(pt)
                if padok or printable>0.8:
                    ok+=1; samples.append((padok,round(printable,2),pt[:48]))
            print(kname, mode, "hits:", ok, samples[:3])

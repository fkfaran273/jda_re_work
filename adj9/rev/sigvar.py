import re, glob, hashlib, hmac
from collections import defaultdict
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), bytes.fromhex(m.group(5))))
bysec=defaultdict(list)
for sec,b in rows: bysec[sec].append(b)
# H(Key, sec) -- 31-bit masked
K1=bytes.fromhex("f065595e09288254f06195ac44cb3e1917c217bca57fea117de05149475ac05b")
K2=bytes.fromhex("3cd000451739baaac19dcc1f3f686d0dc302cacdd32be061eb842100c4f28f48")
import struct
def cand_gen():
    for kn,K in (("K1",K1),("K2",K2),("empty",b""),("sec",b"")):
        for hname,hf in (("sha1",hashlib.sha1),("sha256",hashlib.sha256),("md5",hashlib.md5)):
            for sname,ser in (("be32",lambda s:struct.pack(">I",s)),("ascii",lambda s:str(s).encode())):
                def mk(K=K,hf=hf,ser=ser,mask=True):
                    def f(sec):
                        key=K if kn not in("empty","sec") else (sec.to_bytes(4,"big") if kn=="sec" else b"")
                        d=hmac.new(key,ser(sec),hf).digest()
                        w=struct.unpack(">4I",d[:16])
                        return b"".join(struct.pack(">I",x&0x7fffffff) for x in w)
                    return f
                yield "hmac[%s]_%s_%s"%(kn,hname,sname),mk()
hits=0
for name,f in cand_gen():
    ok=0
    for sec,bs in bysec.items():
        if f(sec)==bs[0][:16]: ok+=1
    if ok: print("HIT",name,ok); hits+=1
print("done",hits)

import json
from Crypto.Cipher import AES
c=json.load(open("rev/corpus.json"))
blobs=[bytes.fromhex(x['hex']) for x in c['blobs']]
def pr(b):
    ok=sum(1 for x in b if 32<=x<127 or x in (9,10,13))
    return ok/max(1,len(b))
cands={
 "const32":bytes.fromhex("b1c22b0c02505175fdc8651d3a623c0499fcec04941db33f1f83aae7701faa16"),
 "d3key":b"Quoh8uafohgh7CahM2h",
 "adjver":b"KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
 "apptoken":b"jut9tib0eeps",
}
def keysizes(k):
    out=[]
    for n in (16,24,32):
        if len(k)>=n: out.append((n,k[:n]))
        else: out.append((n,k+b"\0"*(n-len(k))))
    return out
best=[]
for bn,b in enumerate(blobs[:3]):
    body=b[16:]; hdr=b[:16]
    for cn,ck in cands.items():
        for n,k in keysizes(ck):
            for mode,iv in (("ECB",None),("CBC0",b"\0"*16),("CBC",hdr),("CBCb",body[:16])):
                try:
                    if mode=="ECB": ci=AES.new(k,AES.MODE_ECB); pt=ci.decrypt(body)
                    else: ci=AES.new(k,AES.MODE_CBC,iv); pt=ci.decrypt(body)
                except Exception as e:
                    continue
                r=pr(pt)
                best.append((r,bn,cn,n,mode,pt[:32].hex()))
best.sort(reverse=True)
for r,bn,cn,n,mode,h in best[:12]:
    print("print=%.2f blob=%d key=%s-%d %s %s"%(r,bn,cn,n,mode,h))
print("... total tried",len(best))

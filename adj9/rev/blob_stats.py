import re, glob, base64, collections, os
logs = glob.glob("cap/*.log")
blobs = collections.OrderedDict()
# 1) key2_hex= in sign_input/nsign events (192-byte native return)
# 2) authorization_header signature="<base64>"
for lf in logs:
    try:
        data = open(lf,"rb").read().decode("utf-8","ignore")
    except: continue
    for m in re.finditer(r"key2_hex=([0-9a-f]{384})", data):
        b = bytes.fromhex(m.group(1))
        blobs.setdefault(b, lf)
    for m in re.finditer(r'signature="([A-Za-z0-9+/=]{300,360})"', data):
        try:
            b = base64.b64decode(m.group(1))
        except: continue
        if len(b)==192: blobs.setdefault(b, lf)
print("unique 192-byte blobs:", len(blobs))
bs = list(blobs.keys())
n = len(bs[0])
print("len:", n)
# per-position stats
hi = [0]*n
mn=[255]*n; mx=[0]*n; dist=[set() for _ in range(n)]
for b in bs:
    for i,x in enumerate(b):
        if x&0x80: hi[i]+=1
        if x<mn[i]: mn[i]=x
        if x>mx[i]: mx[i]=x
        dist[i].add(x)
print("pos0: min=%02x max=%02x hi=%d/%d distinct=%d"%(mn[0],mx[0],hi[0],len(bs),len(dist[0])))
print("pos1: min=%02x max=%02x hi=%d distinct=%d"%(mn[1],mx[1],hi[1],len(dist[1])))
print("any position with hi==0 (always<0x80):", [i for i in range(n) if hi[i]==0][:20])
print("constant positions (distinct==1):", [i for i in range(n) if len(dist[i])==1][:40], "...")
print("positions with distinct==len(bs) (all unique):", sum(1 for i in range(n) if len(dist[i])==len(bs)))

print("\n=== first 32 bytes of each unique blob (hex) ===")
for i,b in enumerate(bs):
    print("%2d"%i, b[:16].hex(), "  ", b[16:32].hex())

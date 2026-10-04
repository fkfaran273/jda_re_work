import re, glob, base64, struct, collections
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
n=192
hi=[0]*n
for b in bs:
    for i,x in enumerate(b):
        if x&0x80: hi[i]+=1
allzero=[i for i in range(n) if hi[i]==0]
print("ALL positions with hi==0:", allzero)
print("total blobs:", len(bs))
print("%3s  int0       int1       int2       int3"%"#")
for i,b in enumerate(bs):
    ints=[struct.unpack(">I", b[k:k+4])[0] for k in (0,4,8,12)]
    print("%2d  %10d %10d %10d %10d"%(i,*ints))
# also look at bytes 0,4,8,12 individually min/max
for k in (0,4,8,12):
    vals=[b[k] for b in bs]
    print("byte%d range %02x..%02x"%(k,min(vals),max(vals)))

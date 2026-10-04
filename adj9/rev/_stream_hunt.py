import json,struct,sys
sys.path.insert(0,"rev")
from header_gen import Random3, make_header
c=json.load(open("rev/corpus.json"))
blobs=[(x['ts'],bytes.fromhex(x['hex'])) for x in c['blobs']]

def stream(seed,n):
    R=Random3(seed); return [R.next() for _ in range(n)]

# 1) sanity: find the second whose header matches, then search for body in stream
for ts,b in blobs[:4]:
    hdr=b[:16]; body=b[16:]
    sec0=ts//1000
    found=None
    for sec in range(sec0-4,sec0+2):
        if make_header(sec)==hdr: found=sec; break
    print("ts=%d sec0=%d hdrsec=%s"%(ts,sec0,found))
    if found is None: continue
    S=stream(found,200000)
    # as BE words
    be=b"".join(struct.pack(">I",w) for w in S)
    le=b"".join(struct.pack("<I",w) for w in S)
    # also raw 31-bit words as LE (w<2^31 so BE/LE differ)
    for label,blob in (("BE",be),("LE",le)):
        i=blob.find(body)
        print("   body in %s stream at byte %d (draw %s)"%(label,i,i//4 if i>=0 else None))
    # search first 16 bytes of body
    print("   body[:8]=%s"%body[:8].hex())
    print("   draws[8:12]=%s"%[hex(w) for w in S[8:12]])

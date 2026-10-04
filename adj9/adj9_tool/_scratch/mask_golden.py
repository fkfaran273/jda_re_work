import sys, os, struct, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE); REV=os.path.join(TOOL,'..','rev')
sys.path.insert(0,TOOL)
import adj9_signer as A

def d0_source(d4):
    d4b=b"".join(w.to_bytes(4,"big") for w in d4)
    return [int.from_bytes(d4b[i:i+2],"little") for i in range(16,32,2)]
def sel(mask,source):
    v=0
    for bit in range(8):
        if (mask>>bit)&1: v^=source[7-bit]
    return v & 0xFFFF
def halfwords(d0):
    hs=[]
    for w in d0:
        wb=w.to_bytes(4,"big"); hs.append(wb[0]|(wb[1]<<8)); hs.append(wb[2]|(wb[3]<<8))
    return hs

# Golden attribution vector
d=json.load(open(os.path.join(REV,"saz_blobs.json")))
u=[x for x in d['units'] if x['activity_kind']=='attribution'][0]
sec=u['signing_second']
print("golden attribution signing_second =", sec)
head = A.head_for_kind('attribution')   # -> HEAD_RESIGN
print("head_for_kind('attribution') =", head, "(model HEAD_RESIGN)")
pid=A.DEFAULT_PID
V=(sec ^ 340000)&0xFFFFFFFF    # a representative fill-instant
d0,d2,d4 = A.region(V,pid,head=head)
src=d0_source(d4)
hs=halfwords(d0)
print("V=%08x pid=%d d2=%08x" % (V,pid,d2))
print("region() d0[0]=%08x d0[1]=%08x" % (d0[0],d0[1]))
print("region() first 8 halfwords:", " ".join("%04x"%x for x in hs[:8]))
print()
# What masks reproduce region()'s own halfwords? Is 0x63/0x59 there?
for pos in range(6):
    cand=[m for m in range(256) if sel(m,src)==hs[pos]]
    print("region halfword[%d]=%04x <- masks %s" % (pos,hs[pos],["%02x"%m for m in cand]))
print()
# Test the 0x63/0x59 CLAIM: if W0 (=d0[0] high? or the first halfword) and X used masks 0x63/0x59
w0_063 = sel(0x63,src); x_059 = sel(0x59,src)
print("mask 0x63 -> halfword %04x ; mask 0x59 -> halfword %04x" % (w0_063, x_059))
print("region's actual halfword[0]=%04x halfword[1]=%04x" % (hs[0],hs[1]))
print("Does region halfword[0]==sel(0x63)? %s   halfword[1]==sel(0x59)? %s" % (hs[0]==w0_063, hs[1]==x_059))
# If the claim held, d0[0] would pack sel(0x63),sel(0x59) as first word
claim_word0 = (w0_063 | (x_059<<16)) & 0xFFFFFFFF   # LE packing: low half=0x63, high=0x59
print("d0[0] if claim held (pack 0x63,0x59): %08x   actual: %08x  match=%s" % (claim_word0, d0[0], claim_word0==d0[0]))

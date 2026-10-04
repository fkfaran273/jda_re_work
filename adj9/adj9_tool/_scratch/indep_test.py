import sys, os, struct, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import adj9_signer as A

def d0b(d0): return b"".join(w.to_bytes(4,"big") for w in d0)
def d4b(d4): return b"".join(w.to_bytes(4,"big") for w in d4)

print("HEAD_FIRST =", A.HEAD_FIRST)
print("HEAD_RESIGN=", A.HEAD_RESIGN)
print()

# 1) test laws on the GOLDEN attribution vector. Need V,pid. Not in params.
#    But region() is pure. Try the DEFAULT_PID and a spread of V around the
#    signing second. Report whether laws hold structurally.
d = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 '..','rev','saz_blobs.json')))
u = [x for x in d['units'] if x['activity_kind']=='attribution'][0]
sec = u['signing_second']
print("golden attribution signing_second =", sec)

# try head_for_kind('attribution') -> ordinal 3 -> HEAD_RESIGN
for head_name, head in (("HEAD_FIRST", A.HEAD_FIRST), ("HEAD_RESIGN", A.HEAD_RESIGN)):
    for pid in (A.DEFAULT_PID, 0):
        # a few V candidates
        Vs = [sec, (sec ^ 322000) & 0xFFFFFFFF, (sec ^ 358000)&0xFFFFFFFF]
        for V in Vs:
            d0, d2, d4 = A.region(V, pid, head=head)
            laws = A.region_laws(d0b(d0), d4b(d4))
            # mask relationship between d0 words 0/1 and d4
            print("head=%s pid=%d V=%08x d2=%08x" % (head_name,pid,V,d2))
            print("   d0[0]=%08x d0[1]=%08x d0[2]=%08x d0[3]=%08x" % (d0[0],d0[1],d0[2],d0[3]))
            print("   d4[6]=%08x  d4[6]>>16=%04x d4[6]&0xffff=%04x" % (d4[6], d4[6]>>16, d4[6]&0xffff))
            print("   L1_tile_Rrep:", laws['L1_tile_Rrep'], "hits(p,R):", laws['L1_hits'])
            print("   L2_d4_6_hi_eq_R:", laws['L2_d4_6_hi_eq_R'])
            print("   L3_X_eq_U3:", laws['L3_X_eq_U3'])
            print()
        break  # only first V per pid to keep output tight? no, keep all 3

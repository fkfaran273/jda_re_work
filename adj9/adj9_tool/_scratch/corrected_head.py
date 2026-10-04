import sys, os, struct, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE); REV=os.path.join(TOOL,'..','rev')
sys.path.insert(0,TOOL)
import adj9_signer as A

rows=json.load(open(os.path.join(REV,"all_signings.json"),encoding="utf-8"))
def words(hx):
    b=bytes.fromhex(hx); return [int.from_bytes(b[i:i+4],'big') for i in range(0,len(b),4)]

# Corrected heads derived from captured selectors:
# HEAD_FIRST rows: sel0=0x22 sel1=0x2E then default 0x40|(i&7) from i=2
# HEAD_RESIGN row9: sel0=0x2B sel1=0x07 sel2=0x22 sel3=0x2E then default from i=4
TRUE_FIRST  = (0x22, 0x2E)
TRUE_RESIGN = (0x2B, 0x07, 0x22, 0x2E)

def region_corrected(seed, head):
    d4 = A._d4_words(seed)
    d0 = A._d0_words(d4, head=head)
    d2 = int.from_bytes(seed.to_bytes(4,"little"),"big")
    return d0,d2,d4

# Determine which rows are FIRST vs RESIGN by trying both heads and seeing which matches
print("Testing CORRECTED heads against captured d0/d4 (seed from captured d2):")
print()
res={"TRUE_FIRST":0,"TRUE_RESIGN":0,"model_FIRST":0,"model_RESIGN":0}
for idx,r in enumerate(rows):
    d2w=int(r["d2"],16)
    seed=((d2w&0xff)<<24)|((d2w>>8&0xff)<<16)|((d2w>>16&0xff)<<8)|(d2w>>24&0xff)
    want_d0=words(r["d0"]); want_d4=words(r["d4"])
    # corrected
    d0f,_,d4f = region_corrected(seed, TRUE_FIRST)
    d0r,_,d4r = region_corrected(seed, TRUE_RESIGN)
    mf = list(d0f)==want_d0 and list(d4f)==want_d4
    mr = list(d0r)==want_d0 and list(d4r)==want_d4
    # model heads
    m0f,_,m4f = region_corrected(seed, A.HEAD_FIRST)
    m0r,_,m4r = region_corrected(seed, A.HEAD_RESIGN)
    modf = list(m0f)==want_d0; modr=list(m0r)==want_d0
    if mf: res["TRUE_FIRST"]+=1
    if mr: res["TRUE_RESIGN"]+=1
    if modf: res["model_FIRST"]+=1
    if modr: res["model_RESIGN"]+=1
    print("row %2d: TRUE_FIRST=%-5s TRUE_RESIGN=%-5s | model_FIRST=%-5s model_RESIGN=%-5s" % (
        idx, mf, mr, modf, modr))
print()
print("Totals over %d captured rows:" % len(rows))
for k,v in res.items(): print("  %s: %d" % (k,v))

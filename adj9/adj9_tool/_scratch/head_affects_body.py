import sys, os, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE); REV=os.path.join(TOOL,'..','rev')
sys.path.insert(0,TOOL)
import adj9_signer as A

d=json.load(open(os.path.join(REV,"saz_blobs.json")))
u=[x for x in d['units'] if x['activity_kind']=='attribution'][0]
val=A.claims_from_wire(u['params'],'attribution')
sec=u['signing_second']
V=(sec ^ 345678)&0xFFFFFFFF
pid=A.DEFAULT_PID
# two different heads at the SAME V
def mint(head):
    d0,d2,d4=A.region(V,pid,head=head)
    reg=(d0,d2,d4)
    blob,info=A.mint_blob(val,'attribution',second=sec,V=V,pid=pid,region=reg,head=head)
    return blob
b_model=mint(A.HEAD_RESIGN)     # model's assumption
b_old   =mint((0x22,0x2E))      # corrected FIRST head (old-EMIT family)
print("V=%08x pid=%d" % (V,pid))
print("model HEAD_RESIGN body:", b_model[16:].hex()[:64],"...")
print("corrected (0x22,0x2E) body:", b_old[16:].hex()[:64],"...")
print("bodies differ (body bytes):", sum(a!=b for a,b in zip(b_model[16:],b_old[16:])), "/176")
print("=> head choice changes the 176-byte body:", b_model[16:]!=b_old[16:])

import json, struct, sys
import mint_pipeline as MP
from fin_vm2 import FinEx

rows=json.load(open("all_signings.json"))
blobs=[bytes.fromhex(h) for h in json.load(open("_genuine_blobs.json"))]
sec_of={k:int(v) for k,v in json.load(open("_blob_seconds.json")).items()}
# index blobs by header
by_hdr={}
for b in blobs: by_hdr.setdefault(b[:16].hex(),[]).append(b)

def descs_from_row(r):
    d0=bytes.fromhex(r["d0"]); d2=bytes.fromhex(r["d2"]); d4=bytes.fromhex(r["d4"])
    d8=bytes.fromhex(r["d8"]); d9=bytes.fromhex(r["d9"]); d10=bytes.fromhex(r["d10"])
    unpadded=len(d10.rstrip(b"\x00"))
    by_idx={
        0:(36,0,d0), 9:(5,0,d9), 8:(4,0,d8), 4:(8,0,d4), 2:(1,0,d2),
        7:(1,0,struct.pack(">I",unpadded)), 10:(len(d10)//4,0,d10),
        5:(1,0,b"\x00\x00\x00\x00"), 6:(1,0,b"\x00\x00\x00\x00"),
        1:(0,0,b""), 3:(0,0,b""),
    }
    return [by_idx[i] for i in MP.VA_ORDER]

# quick speed test
import time
t0=time.time()
d0=descs_from_row(rows[0])
blob,info=MP.finex_mint(d0, 1788938789, max_steps=20_000_000)
print("one mint: %.2fs status=%s"%(time.time()-t0, info["status"]))

exact=0; tested=0; body_hits=0
budget=40  # try first N blobs
for b in blobs[:budget]:
    S=sec_of.get(b[:16].hex())
    if S is None: continue
    for ri,r in enumerate(rows):
        tested+=1
        try:
            ours,_=MP.finex_mint(descs_from_row(r), S, max_steps=20_000_000)
        except Exception as e:
            continue
        if ours==b:
            exact+=1; print("EXACT 192B MATCH row%d second=%d"%(ri,S))
        elif ours[16:]==b[16:]:
            body_hits+=1; print("BODY MATCH (hdr differs) row%d second=%d"%(ri,S))
print("\ntested %d mints over %d blobs x %d rows"%(tested,min(budget,len(blobs)),len(rows)))
print("EXACT full-blob matches:",exact," body-only matches:",body_hits)

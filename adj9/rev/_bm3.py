import json, struct, time
import mint_pipeline as MP
rows=json.load(open("all_signings.json"))
blobs=json.load(open("_genuine_blobs.json"))
sec_of=json.load(open("_blob_seconds.json"))
def descs(r):
    d0=bytes.fromhex(r["d0"]);d2=bytes.fromhex(r["d2"]);d4=bytes.fromhex(r["d4"])
    d8=bytes.fromhex(r["d8"]);d9=bytes.fromhex(r["d9"]);d10=bytes.fromhex(r["d10"])
    up=len(d10.rstrip(b"\x00"))
    by={0:(36,0,d0),9:(5,0,d9),8:(4,0,d8),4:(8,0,d4),2:(1,0,d2),
        7:(1,0,struct.pack(">I",up)),10:(len(d10)//4,0,d10),
        5:(1,0,b"\0\0\0\0"),6:(1,0,b"\0\0\0\0"),1:(0,0,b""),3:(0,0,b"")}
    return [by[i] for i in MP.VA_ORDER]
# rows 4,5,6,7 come from whcap_hits4-7 (~00:38-00:46). Nearby blob seconds:
#   00:37:55(1789240075) 00:40:28(1789240228) 00:42:20(1789240340) 00:45:12(1789240512)
targets=[(4,1789240075),(5,1789240228),(6,1789240340),(7,1789240512),
         (4,1789240076),(5,1789240229),(6,1789240341),(7,1789240512)]
def getblob(hdr): return [bytes.fromhex(b) for b in blobs if b[:32]==hdr]
found=0
for ri,S in targets:
    try: ours,_=MP.finex_mint(descs(rows[ri]),S,max_steps=20_000_000)
    except Exception as e:
        print("row%d sec%d ERR %s"%(ri,S,str(e)[:50])); continue
    for gb in getblob(ours[:16].hex()):
        if ours==gb:
            found+=1; print(">>> EXACT 192B MATCH row%d second=%d"%(ri,S))
        else:
            d=[i for i in range(192) if ours[i]!=gb[i]]
            print("    row%d sec%d diff=%d"%(ri,S,len(d)))
print("additional exact matches:",found)

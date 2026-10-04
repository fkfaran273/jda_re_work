import sys, os, struct, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE); REV=os.path.join(TOOL,'..','rev')
sys.path.insert(0,TOOL)
import adj9_signer as A

rows=json.load(open(os.path.join(REV,"all_signings.json"),encoding="utf-8"))
def words(hx):
    b=bytes.fromhex(hx); return [int.from_bytes(b[i:i+4],'big') for i in range(0,len(b),4)]
def d0_source(d4):
    d4b=b"".join(w.to_bytes(4,"big") for w in d4)
    return [int.from_bytes(d4b[i:i+2],"little") for i in range(16,32,2)]
def sel(mask,source):
    v=0
    for bit in range(8):
        if (mask>>bit)&1: v^=source[7-bit]
    return v & 0xFFFF

# Captured row 0
r=rows[0]
d2w=int(r["d2"],16)
seed=((d2w&0xff)<<24)|((d2w>>8&0xff)<<16)|((d2w>>16&0xff)<<8)|(d2w>>24&0xff)
cap_d0=words(r["d0"]); cap_d4=words(r["d4"])
src=d0_source(cap_d4)
print("row0 seed=%08x" % seed)
print("captured d0 first words:", " ".join("%08x"%x for x in cap_d0[:6]))
print("d4 source halfwords:", " ".join("%04x"%x for x in src))
# captured d0 halfwords (LE packing of 16-bit whitener outputs)
cap_half=[]
for w in cap_d0:
    wb=w.to_bytes(4,"big")
    cap_half.append(wb[0]|(wb[1]<<8))  # value at even output index (LE half)
    cap_half.append(wb[2]|(wb[3]<<8))  # value at odd output index
print("captured d0[0..6] as 16-bit whitener outputs:", " ".join("%04x"%x for x in cap_half[:12]))
print()
# For every 8-bit mask, compute selector value, see which masks give cap_half[0], cap_half[1]
for idx in (0,1,2,3):
    target=cap_half[idx]
    masks=[m for m in range(256) if sel(m,src)==target]
    print("cap_half[%d]=%04x reproduced by masks:" % (idx,target),
          ["%02x"%m for m in masks], " (0x63=%02x 0x59=%02x present? %s %s)"%(0x63,0x59,0x63 in masks,0x59 in masks))
print()
# What does model A produce for the first 8 halfwords?
a_d0,a_d2,a_d4=A.region(seed,0)
a_half=[]
for w in a_d0:
    wb=w.to_bytes(4,"big"); a_half.append(wb[0]|(wb[1]<<8)); a_half.append(wb[2]|(wb[3]<<8))
print("modelA d0 halfwords[0..8]:", " ".join("%04x"%x for x in a_half[:8]))
print("cap   d0 halfwords[0..8]:", " ".join("%04x"%x for x in cap_half[:8]))
# Which cap_half index does each modelA half equal?
print("modelA alignment: for each a_half[i], which cap_half[j] equals it?")
for i in range(6):
    js=[j for j in range(12) if a_half[i]==cap_half[j]]
    print("  a_half[%d]=%04x -> cap_half idx %s"%(i,a_half[i],js))

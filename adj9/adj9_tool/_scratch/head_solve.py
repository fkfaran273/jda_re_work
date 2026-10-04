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
def halfwords(d0):
    hs=[]
    for w in d0:
        wb=w.to_bytes(4,"big"); hs.append(wb[0]|(wb[1]<<8)); hs.append(wb[2]|(wb[3]<<8))
    return hs

print("For each captured row, which SELECTOR (0x00..0x7f) reproduces d0 halfwords 0..3?")
print("selector s -> mask (s<<1)+3. model uses selector list; 0x63/0x59 are MASKS (sel 0x30/0x2b).")
print()
all_sel0=set(); all_sel1=set(); all_sel2=set(); all_sel3=set()
for idx,r in enumerate(rows):
    d2w=int(r["d2"],16)
    seed=((d2w&0xff)<<24)|((d2w>>8&0xff)<<16)|((d2w>>16&0xff)<<8)|(d2w>>24&0xff)
    cap_d0=words(r["d0"]); cap_d4=words(r["d4"])
    src=d0_source(cap_d4); hs=halfwords(cap_d0)
    sels=[]
    for pos in range(4):
        cand=[s for s in range(256) if sel((s<<1)+3,src)==hs[pos]]
        # selectors are used as x1 in _whitener_word, mask=(x1<<1)+3; x1 typically 0x00..0x7f
        sels.append(cand)
    all_sel0|=set(sels[0]); all_sel1|=set(sels[1]); all_sel2|=set(sels[2]); all_sel3|=set(sels[3])
    print("row %d: pos0 sel=%s pos1 sel=%s pos2 sel=%s pos3 sel=%s" % (
        idx, sels[0], sels[1], sels[2][:4], sels[3][:4]))
print()
print("Union of selectors pos0:", sorted(hex(x) for x in all_sel0))
print("Union of selectors pos1:", sorted(hex(x) for x in all_sel1))
print("Union of selectors pos2:", sorted(hex(x) for x in all_sel2))
print("Union of selectors pos3:", sorted(hex(x) for x in all_sel3))
print()
# Check: does 0x63 or 0x59 (as MASKS) reproduce ANY captured d0 halfword?
print("Does mask 0x63 (=sel 0x30) or 0x59 (=sel 0x2b) appear as pos0/pos1?")
print("  0x30 in pos0 sel?", 0x30 in all_sel0, " 0x2b in pos1 sel?", 0x2b in all_sel1)

# decmap2.py — full decrypt-block harvest with correct FDE map
import sys,os,pickle,re
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import capstone
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
from elf import ELF
import fdetab
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
t=e.byname[".text"]
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
code=e.data[t["offset"]:t["offset"]+t["size"]]
insns=list(md.disasm(code,t["addr"]))
# decoded strings table
sd={}
for line in open("data_strings_decoded2.txt",encoding="utf-8",errors="replace"):
    p=line.split(None,2)
    if len(p)==3 and p[0].startswith("0x"):
        try: sd[int(p[0],16)]=p[2].rstrip("\n")
        except: pass
DATA_LO,DATA_HI=0x151000,0x156000
# pass: track adrp pages; find (adrp X,page) then ldr/str [X,disp] into .data
adrp={}
sites=[]  # (code_va, str_va, size)
for i,ins in enumerate(insns):
    if ins.mnemonic=="adrp":
        adrp[ins.operands[0].reg]=ins.operands[1].imm
    elif ins.mnemonic in ("ldr","str") and len(ins.operands)==2:
        ops=ins.operands
        if ops[1].type==ARM64_OP_MEM and ops[1].mem.index==0 and ops[1].mem.base in adrp:
            va=adrp[ops[1].mem.base]+ops[1].mem.disp
            if DATA_LO<=va<DATA_HI:
                sites.append((ins.address,va,ins.mnemonic,ins.reg_name(ops[0].reg),ins.op_str))
    if ins.mnemonic not in ("adrp",) and ins.operands and ins.operands[0].type==ARM64_OP_REG:
        # writing to the register kills adrp mapping UNLESS it's a load dest is fine but reg no longer holds page
        if ins.mnemonic not in ("ldr",):
            adrp.pop(ins.operands[0].reg,None)
        elif ins.mnemonic=="ldr":
            adrp.pop(ins.operands[0].reg,None)
print("data refs:",len(sites))
# decrypt pattern: ldr V,[base,disp] ... movi vK,#key ... eor V,V,vK ... str V,[base,disp]
# find ldr/str pairs on same va with an eor in between
dec=[]
for idx,(a,va,m,rn,ops) in enumerate(sites):
    if m!="ldr": continue
    # look ahead for matching str at same va within 30 sites
    for j in range(idx+1,min(idx+30,len(sites))):
        a2,va2,m2,rn2,ops2=sites[j]
        if va2==va and m2=="str":
            # check eor and movi between code a and a2 in insns
            lo_i=None
            # find instruction indices
            # linear scan insns between a and a2
            key=None
            seg=insns[max(0,i_lo(a,insns)):i_lo(a2,insns)+1] if False else None
            # simpler: scan window by address
            for ins in insns:
                if a<=ins.address<a2:
                    if ins.mnemonic=="movi" and ins.operands[1].type==ARM64_OP_IMM and 0<=ins.operands[1].imm<256:
                        # ensure it's a vector movi (v reg)
                        rn0=ins.reg_name(ins.operands[0].reg)
                        if rn0.startswith("v"):
                            key=ins.operands[1].imm
            if key is not None:
                fn=fdetab.func_of(a)
                dec.append((a,va,key,fn))
            break
def i_lo(addr,insns):
    # binary search
    import bisect
    addrs=[x.address for x in insns]
    return bisect.bisect_left(addrs,addr)
print("decrypt blocks:",len(dec))
pickle.dump(dec,open("dec_sites.pkl","wb"))
# annotate with decoded strings
for a,va,k,fn in sorted(dec):
    s=sd.get(va) or ("+".join(sd.get(va2,"?") for va2 in [va]) if False else None)
    # try partial: string at va, or va may point into an entry
    if s is None:
        best=None
        for sva,txt in sd.items():
            if sva<=va<sva+len(txt)+1:
                best="%s[+%d]"%(txt[:40],va-sva); break
        s=best or "(unparsed)"
    print("0x%06x -> .data 0x%06x key=0x%02x  fn=0x%x  %r"%(a,va,k,fn or 0,s[:70]))

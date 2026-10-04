# decmap.py — harvest ALL in-place string decrypt blocks: (va, key, site) -> containing function
# Pattern variants:
#   adrp xR,page ; movi vK.16b,#key ; ldr qM,[xR,#off] ; eor vM,vM,vK ; str qM,[xR,#off]
#   also d-register forms (movz/mov key into dN, eor v, ldr d)
# and byte-16 forms. We scan a window around every adrp into .data pages and look for
# any (ldr X,[base,disp]) ... (eor X) ... (str X,[base,disp]) where base regs derive from adrp.
import struct,pickle,sys,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import capstone
from capstone.arm64 import *
from elf import ELF
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
t=e.byname[".text"]
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
# function boundaries from .eh_frame_hdr FDE table: reuse earlier approach (fn_147630 header said FDE func 0x1452d0..0x149630)
# parse eh_frame_hdr binary search table
hdr=e.byname.get(".eh_frame_hdr")
fde=[]
if hdr:
    off=hdr["offset"]; va=hdr["addr"]
    b=e.data[off:off+hdr["size"]]
    ver=b[0]; eef=b[1]&0xf; fde_count=b[4] | b[5]<<8 | b[6]<<16 | b[7]<<24
    enc=b[1]>>4 &0xf; tbenc=b[2]; cntenc=b[3]
    # assume enc=0x1b (DW_EH_PE_pcrel|sdata4) table entries: sdata4 initial_loc, sdata4 fde_ptr
    p=8
    import struct as st
    for i in range(fde_count):
        loc,fdep=st.unpack_from("<ii",b,p); p+=8
        fde.append((va+p+loc, va+p+fdep))  # pcrel from position AFTER the field
    # fix: each field pcrel base = address of the 4 bytes themselves +4? For sdata4 pcrel: base = addr of field + 4
print("FDE entries:",len(fde),file=sys.stderr)
# recompute correctly: DW_EH_PE_pcrel sdata4: value = (field_addr + 4) + signed
fde2=[]
p=8
for i in range(fde_count):
    loc,fdep=st.unpack_from("<ii",b,p)
    fa=va+p
    fde2.append(((fa+4+loc),(fa+8+fdep)))
    p+=8
def func_of(addr):
    # FDE table entries: (func_start, fde_ptr); find func containing addr
    lo,hi=0,len(fde2)-1
    # build sorted list of starts
    pass
starts=sorted(set(x[0] for x in fde2))
import bisect
def func_of(addr):
    i=bisect.bisect_right(starts,addr)-1
    return starts[i] if i>=0 else None
print("distinct FDE funcs:",len(starts),file=sys.stderr)
# scan
DATA_LO,DATA_HI=0x151000,0x156000
sites={}
code=e.data[t["offset"]:t["offset"]+t["size"]]
insns=list(md.disasm(code,t["addr"]))
print("insns:",len(insns),file=sys.stderr)
# track adrp per reg within 40-insn window; collect (base_reg->page)
adrp_map={}
decrypt_sites=[]
for idx,ins in enumerate(insns):
    if ins.mnemonic=="adrp":
        adrp_map[ins.operands[0].reg]=ins.operands[1].imm
        continue
    if ins.mnemonic in ("ldr","str") and len(ins.operands)>=2:
        ops=ins.operands
        if ops[1].type==ARM64_OP_MEM and ops[1].mem.index==0:
            base=ops[1].mem.base
            if base in adrp_map:
                va=adrp_map[base]+ops[1].mem.disp
                if DATA_LO<=va<DATA_HI:
                    key=None
                    regname=ins.reg_name(ops[0].reg)
                    # find movi/mov key within +-12 insns and eor in between for ldr
                    if ins.mnemonic=="ldr":
                        # find eor reg,reg,vK then str reg
                        for j in range(idx+1,min(idx+13,len(insns))):
                            i2=insns[j]
                            if i2.mnemonic=="movi" and len(i2.operands)>=2 and i2.operands[1].type==ARM64_OP_IMM:
                                key=i2.operands[1].imm & 0xff if i2.operands[1].imm<256 else (i2.operands[1].imm & 0xff00)>>8
                                # for .16b movi the imm is the byte
                                key=i2.operands[1].imm
                                break
                            if i2.mnemonic=="eor":
                                # operand 2 might be vK; look back for movi
                                for j2 in range(idx+1,j):
                                    i3=insns[j2]
                                    if i3.mnemonic=="movi" and i3.operands[1].type==ARM64_OP_IMM and i3.operands[1].imm<256:
                                        key=i3.operands[1].imm
                                if key is None:
                                    # eor with vector: check operands[2] register; find its movi before
                                    if len(i2.operands)==3 and i2.operands[2].type==ARM64_OP_REG:
                                        vr=i2.operands[2].reg
                                        for j2 in range(idx+1,j):
                                            i3=insns[j2]
                                            if i3.mnemonic=="movi" and i3.operands[0].reg==vr and i3.operands[1].type==ARM64_OP_IMM and i3.operands[1].imm<256:
                                                key=i3.operands[1].imm
                                break
                    if key is not None:
                        decrypt_sites.append((ins.address,va,key,regname))
    # prune adrp_map on writes
    if len(ins.operands)>=1 and ins.operands[0].type==ARM64_OP_REG and ins.mnemonic not in ("adrp","ldr","str","eor","movi"):
        adrp_map.pop(ins.operands[0].reg,None)
    elif ins.mnemonic in("ldr","str"):
        # dest reg written (ldr) - base still valid
        if ins.mnemonic=="ldr":
            pass
print("decrypt sites:",len(decrypt_sites),file=sys.stderr)
pickle.dump(decrypt_sites,open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/dec_sites.pkl","wb"))
for a,va,k,rn in decrypt_sites[:20]:
    print("0x%x decrypts 0x%x key=0x%02x reg=%s fn=%s"%(a,va,k,rn,hex(func_of(a)) if func_of(a) else "?"))

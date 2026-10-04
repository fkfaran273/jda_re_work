from capstone import *
from collections import Counter
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
TVA,TOFF,TSZ=0x8be0,0x8be0,0x13fdd4
code=elf[TOFF:TOFF+TSZ]
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
targets={0x144214:"driver",0x1441e4:"fold_wrap",0x144074:"fold_xor",0x143b20:"slot_search"}
callers={k:[] for k in targets}
nb=0
for ins in md.disasm(code,TVA):
    if ins.mnemonic=="bl":
        nb+=1
        try: t=int(ins.op_str.lstrip("#"),16)
        except: continue
        if t in targets: callers[t].append(ins.address)
print("total bl in .text:",nb)
for k,name in targets.items():
    print("%-12s %#x callers: %s"%(name,k,[hex(c) for c in callers[k]]))
# nSign internal bl targets
cnt=Counter()
for ins in md.disasm(code,TVA):
    if 0xdab84<=ins.address<0xdc7ec and ins.mnemonic=="bl":
        try: t=int(ins.op_str.lstrip("#"),16)
        except: continue
        cnt[t]+=1
print("--- nSign bl targets ---")
for t,c in sorted(cnt.items(),key=lambda x:-x[1]):
    print("  %#x x%d"%(t,c))

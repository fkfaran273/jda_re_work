# thunk_id.py — identify JNI vtable function for each small thunk
import sys,os,struct
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import capstone
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_MEM,ARM64_OP_IMM
from elf import ELF
import fdetab
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
JNI={4:"GetVersion",6:"FindClass",15:"ExceptionOccurred",17:"ExceptionClear",21:"NewGlobalRef",23:"DeleteLocalRef",27:"AllocObject",28:"NewObject",31:"GetObjectClass",32:"IsInstanceOf",33:"GetMethodID",34:"CallObjectMethod",37:"CallBooleanMethod",43:"CallCharMethod",46:"CallShortMethod",49:"CallIntMethod",52:"CallLongMethod",61:"CallVoidMethod",94:"GetFieldID",95:"GetObjectField",100:"GetIntField",101:"GetLongField",111:"GetStaticMethodID",112:"CallStaticObjectMethod",115:"CallStaticBooleanMethod",121:"CallStaticVoidMethod",124:"CallStaticIntMethod",159:"NewString",163:"NewStringUTF",164:"GetStringUTFLength",165:"GetStringUTFChars",166:"ReleaseStringUTFChars",167:"GetArrayLength",168:"NewObjectArray",169:"GetObjectArrayElement",170:"SetObjectArrayElement",172:"NewByteArray",175:"NewIntArray",180:"GetByteArrayElements",188:"ReleaseByteArrayElements",196:"GetByteArrayRegion",204:"SetByteArrayRegion",208:"SetLongArrayRegion",224:"ExceptionCheck"}
def dump_fn(start,end):
    off=e.vaddr_to_off(start)
    code=e.data[off:e.vaddr_to_off(end)]
    out=[]
    for ins in md.disasm(code,start):
        out.append(ins)
    return out
thunks={0x147630:None,0x147734:None,0x146558:None,0x146650:None,0x14784c:None,0x147304:None,0x146ed8:None}
for start in sorted(thunks):
    end=None
    # find next FDE start after
    import bisect
    i=bisect.bisect_right(fdetab.starts,start)
    if i<len(fdetab.starts): end=fdetab.starts[i]
    else: end=start+0x200
    ins=dump_fn(start,end)
    # find: ldr xN,[xM] ; ... ldr xK,[xN,#imm] ; br xK  (env deref then vtable slot)
    seq=[]
    for ins in ins:
        seq.append((ins.mnemonic,ins.op_str,ins.address))
    # locate 'br x' and track backwards the loaded offset
    idx=None
    for j,(m,ops,a) in enumerate(seq):
        if m=="br": idx=j; break
    if idx is None:
        print("thunk 0x%x: no br (size %d)"%(start,end-start)); continue
    # find last 'ldr xK,[xN,#imm]' before br where base != dest
    slot=None
    for j in range(idx-1,max(-1,idx-25),-1):
        m,ops,a=seq[j]
        if m=="ldr" and "#0x" in ops and "])" in ops.replace(" ",""):
            # parse ldr xK,[xN,#imm]
            import re
            mm=re.match(r"ldr\s+(\w+),\s*\[(\w+),?\s*(?:#(0x[0-9a-f]+|-?\d+))?\]",ops.replace(" ",""))
            if mm and mm.group(3) is not None:
                slot=int(mm.group(3),16) if mm.group(3).startswith("0x") else int(mm.group(3))
                break
    if slot is None:
        # maybe ldr xN,[xM] then ldr xK,[xN,#imm]
        print("thunk 0x%x..0x%x: br at 0x%x, slot not found; seq=%s"%(start,end,seq[idx][2],[s[0] for s in seq[:idx+1]][:30]))
        continue
    jni=JNI.get(slot//8,"idx_%d/8=?"%slot)
    print("thunk 0x%06x..0x%06x  size=%3d  slot=0x%03x -> JNI #%d = %s"%(start,end,end-start,slot,slot//8,jni))

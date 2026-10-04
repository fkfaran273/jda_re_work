# thunk_id2.py — identify JNI calls in each thunk via vtable-offset histogram method (from jni_scan.py)
import sys,os,re
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import capstone
from elf import ELF
import fdetab
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
JNI={4:"GetVersion",6:"FindClass",15:"ExceptionOccurred",16:"ExceptionDescribe",17:"ExceptionClear",21:"NewGlobalRef",22:"DeleteGlobalRef",23:"DeleteLocalRef",25:"NewLocalRef",27:"AllocObject",28:"NewObject",31:"GetObjectClass",32:"IsInstanceOf",33:"GetMethodID",34:"CallObjectMethod",37:"CallBooleanMethod",49:"CallIntMethod",52:"CallLongMethod",55:"CallFloatMethod",58:"CallDoubleMethod",61:"CallVoidMethod",94:"GetFieldID",95:"GetObjectField",100:"GetIntField",101:"GetLongField",111:"GetStaticMethodID",112:"CallStaticObjectMethod",115:"CallStaticBooleanMethod",118:"CallStaticIntMethod",121:"CallStaticVoidMethod",124:"CallStaticIntMethod",159:"NewString",163:"NewStringUTF",164:"GetStringUTFLength",165:"GetStringUTFChars",166:"ReleaseStringUTFChars",167:"GetArrayLength",168:"NewObjectArray",169:"GetObjectArrayElement",170:"SetObjectArrayElement",172:"NewByteArray",173:"NewCharArray",175:"NewIntArray",176:"NewLongArray",180:"GetByteArrayElements",183:"GetIntArrayElements",188:"ReleaseByteArrayElements",191:"ReleaseIntArrayElements",196:"GetByteArrayRegion",199:"GetIntArrayRegion",200:"GetLongArrayRegion",203:"SetBooleanArrayRegion",204:"SetByteArrayRegion",207:"SetIntArrayRegion",208:"SetLongArrayRegion",224:"ExceptionCheck"}
import bisect
def fn_range(a):
    i=bisect.bisect_right(fdetab.starts,a)
    end=fdetab.starts[i] if i<len(fdetab.starts) else 0x149000
    i2=bisect.bisect_right(fdetab.starts,a)-1
    return fdetab.starts[i2],end
for start in (0x147630,0x147734,0x146558,0x146650,0x14784c,0x147304,0x146ed8):
    s,end=fn_range(start)
    off=e.vaddr_to_off(s)
    code=e.data[off:e.vaddr_to_off(end)]
    hits=[]
    regs={}
    for ins in md.disasm(code,s):
        m=ins.mnemonic; ops=ins.op_str
        if m=="ldr" and re.match(r"^\w+,\s*\[\w+\]$",ops.replace(" ","")):
            # reg = [reg] — env deref: env pointer
            mm=re.match(r"(\w+),\[(\w+)\]",ops.replace(" ",""))
            if mm: regs[mm.group(1)]=("env",ins.address)
        elif m=="ldr" and ("#0x" in ops):
            mm=re.match(r"(\w+),\[(\w+),#(0x[0-9a-f]+|\d+)\]",ops.replace(" ",""))
            if mm:
                dst,base,imm=mm.group(1),mm.group(2),mm.group(3)
                v=int(imm,16) if imm.startswith("0x") else int(imm)
                if base in regs:
                    hits.append((ins.address,v,JNI.get(v//8,"idx%d"%(v//8))))
        elif m=="blr":
            pass
    print("thunk 0x%x..0x%x (size %d):"%(s,end,end-s))
    for a,v,n in hits: print("   0x%x  slot=0x%x -> %s"%(a,v,n))

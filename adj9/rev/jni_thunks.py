# Decode JNI thunk wrappers in libsigner.so: each thunk is ldr x8,[x0]; ldr x8,[x8,#off]; br x8
# JNIEnv vtable offset/8 = function index -> name
import struct, sys
sys.path.insert(0,"C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from capstone import *

so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
e_shoff=struct.unpack_from("<Q",data,0x28)[0]
e_shentsize=struct.unpack_from("<H",data,0x3a)[0]
e_shnum=struct.unpack_from("<H",data,0x3c)[0]
e_shstrndx=struct.unpack_from("<H",data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    off=e_shoff+i*e_shentsize
    name,typ,flags,addr,offset,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",data,off)
    secs.append((name,typ,flags,addr,offset,size,link,info,align,entsize))
shstr=secs[e_shstrndx]
def sname(n):
    e=data.index(b"\0",shstr[4]+n)
    return data[shstr[4]+n:e].decode()
secmap=[(sname(s[0]),s[3],s[4],s[6],s[5]) for s in secs]
def v2o(v):
    for sn,addr,off,link,size in secmap:
        if addr<=v<addr+size and addr!=0 and not sn.startswith((".dyn",".rela",".gnu",".symtab",".strtab",".debug",".eh")):
            return off+(v-addr)
    return v

JNI=["reserved0","reserved1","reserved2","reserved3","GetVersion","DefineClass","FindClass",
"FromReflectedMethod","FromReflectedField","ToReflectedMethod","GetSuperclass","IsAssignableFrom",
"ToReflectedField","Throw","ThrowNew","ExceptionOccurred","ExceptionDescribe","ExceptionClear",
"FatalError","PushLocalFrame","PopLocalFrame","NewGlobalRef","DeleteGlobalRef","DeleteLocalRef",
"IsSameObject","NewLocalRef","EnsureLocalCapacity","AllocObject","NewObject","NewObjectV","NewObjectA",
"GetObjectClass","IsInstanceOf","GetMethodID",
"CallObjectMethod","CallObjectMethodV","CallObjectMethodA",
"CallBooleanMethod","CallBooleanMethodV","CallBooleanMethodA",
"CallByteMethod","CallByteMethodV","CallByteMethodA",
"CallCharMethod","CallCharMethodV","CallCharMethodA",
"CallShortMethod","CallShortMethodV","CallShortMethodA",
"CallIntMethod","CallIntMethodV","CallIntMethodA",
"CallLongMethod","CallLongMethodV","CallLongMethodA",
"CallFloatMethod","CallFloatMethodV","CallFloatMethodA",
"CallDoubleMethod","CallDoubleMethodV","CallDoubleMethodA",
"CallVoidMethod","CallVoidMethodV","CallVoidMethodA",
# 64..93 nonvirtual (10 types x3)
"CallNonvirtualObjectMethod","CallNonvirtualObjectMethodV","CallNonvirtualObjectMethodA",
"CallNonvirtualBooleanMethod","CallNonvirtualBooleanMethodV","CallNonvirtualBooleanMethodA",
"CallNonvirtualByteMethod","CallNonvirtualByteMethodV","CallNonvirtualByteMethodA",
"CallNonvirtualCharMethod","CallNonvirtualCharMethodV","CallNonvirtualCharMethodA",
"CallNonvirtualShortMethod","CallNonvirtualShortMethodV","CallNonvirtualShortMethodA",
"CallNonvirtualIntMethod","CallNonvirtualIntMethodV","CallNonvirtualIntMethodA",
"CallNonvirtualLongMethod","CallNonvirtualLongMethodV","CallNonvirtualLongMethodA",
"CallNonvirtualFloatMethod","CallNonvirtualFloatMethodV","CallNonvirtualFloatMethodA",
"CallNonvirtualDoubleMethod","CallNonvirtualDoubleMethodV","CallNonvirtualDoubleMethodA",
"CallNonvirtualVoidMethod","CallNonvirtualVoidMethodV","CallNonvirtualVoidMethodA",
"GetFieldID","GetObjectField","GetBooleanField","GetByteField","GetCharField","GetShortField",
"GetIntField","GetLongField","GetFloatField","GetDoubleField",
"SetObjectField","SetBooleanField","SetByteField","SetCharField","SetShortField","SetIntField",
"SetLongField","SetFloatField","SetDoubleField",
"GetStaticMethodID",
"CallStaticObjectMethod","CallStaticObjectMethodV","CallStaticObjectMethodA",
"CallStaticBooleanMethod","CallStaticBooleanMethodV","CallStaticBooleanMethodA",
"CallStaticByteMethod","CallStaticByteMethodV","CallStaticByteMethodA",
"CallStaticCharMethod","CallStaticCharMethodV","CallStaticCharMethodA",
"CallStaticShortMethod","CallStaticShortMethodV","CallStaticShortMethodA",
"CallStaticIntMethod","CallStaticIntMethodV","CallStaticIntMethodA",
"CallStaticLongMethod","CallStaticLongMethodV","CallStaticLongMethodA",
"CallStaticFloatMethod","CallStaticFloatMethodV","CallStaticFloatMethodA",
"CallStaticDoubleMethod","CallStaticDoubleMethodV","CallStaticDoubleMethodA",
"CallStaticVoidMethod","CallStaticVoidMethodV","CallStaticVoidMethodA",
"GetStaticFieldID","GetStaticObjectField","GetStaticBooleanField","GetStaticByteField",
"GetStaticCharField","GetStaticShortField","GetStaticIntField","GetStaticLongField",
"GetStaticFloatField","GetStaticDoubleField",
"SetStaticObjectField","SetStaticBooleanField","SetStaticByteField","SetStaticCharField",
"SetStaticShortField","SetStaticIntField","SetStaticLongField","SetStaticFloatField",
"SetStaticDoubleField","NewString","GetStringLength","GetStringChars","ReleaseStringChars",
"NewStringUTF","GetStringUTFLength","GetStringUTFChars","ReleaseStringUTFChars","GetArrayLength",
"NewObjectArray","GetObjectArrayElement","SetObjectArrayElement",
"NewBooleanArray","NewByteArray","NewCharArray","NewShortArray","NewIntArray","NewLongArray",
"NewFloatArray","NewDoubleArray",
"GetBooleanArrayElements","GetByteArrayElements","GetCharArrayElements","GetShortArrayElements",
"GetIntArrayElements","GetLongArrayElements","GetFloatArrayElements","GetDoubleArrayElements",
"ReleaseBooleanArrayElements","ReleaseByteArrayElements","ReleaseCharArrayElements",
"ReleaseShortArrayElements","ReleaseIntArrayElements","ReleaseLongArrayElements",
"ReleaseFloatArrayElements","ReleaseDoubleArrayElements",
"GetBooleanArrayRegion","GetByteArrayRegion","GetCharArrayRegion","GetShortArrayRegion",
"GetIntArrayRegion","GetLongArrayRegion","GetFloatArrayRegion","GetDoubleArrayRegion",
"SetBooleanArrayRegion","SetByteArrayRegion","SetCharArrayRegion","SetShortArrayRegion",
"SetIntArrayRegion","SetLongArrayRegion","SetFloatArrayRegion","SetDoubleArrayRegion",
"RegisterNatives","UnregisterNatives","MonitorEnter","MonitorExit","GetJavaVM",
"GetStringRegion","GetStringUTFRegion","GetPrimitiveArrayCritical","ReleasePrimitiveArrayCritical",
"GetStringCritical","ReleaseStringCritical","NewWeakGlobalRef","DeleteWeakGlobalRef",
"ExceptionCheck","NewDirectByteBuffer","GetDirectBufferAddress","GetDirectBufferCapacity",
"GetObjectRefType"]

md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
thunks=[0x147630,0x147734,0x147304,0x146ed8,0x1472e8,0x146558,0x14784c,0x146650]
if len(sys.argv)>1: thunks=[int(x,16) for x in sys.argv[1:]]
for t in thunks:
    o=v2o(t)
    print("=== thunk 0x%x ==="%t)
    for ins in md.disasm(data[o:o+24],t):
        print("  0x%x  %s %s"%(ins.address,ins.mnemonic,ins.op_str))
        if ins.mnemonic=="br": break
    # find the vtable offset: pattern ldr x8,[x8,#imm]
    code=data[o:o+24]
    off=None
    for ins in md.disasm(code,t):
        if ins.mnemonic=="ldr" and "#0x" in ins.op_str and ("[x8" in ins.op_str or "[x0" in ins.op_str):
            try: off=int(ins.op_str.split("#")[1].rstrip("]"),16)
            except: pass
        if ins.mnemonic=="br":
            break
    if off is not None:
        idx=off//8
        nm=JNI[idx] if idx<len(JNI) else "?idx%d"%idx
        print("  -> vtable +0x%x => idx %d = %s"%(off,idx,nm))

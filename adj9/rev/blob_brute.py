"""blob_brute.py - brute-force single-byte XOR keys over the data string area,
segmenting at zero runs; report printable decodes and binary (key-material) blobs.
Also: scan for JNIEnv function-table slot loads across .text.
"""
import sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

data = open(LIB, "rb").read()
DELTA = 0x7E20
LO, HI = 0x151C00, 0x15540A

def printable_ratio(b):
    if not b:
        return 0
    return sum(1 for c in b if 32 <= c < 127 or c == 0) / len(b)

# segment: split at runs of >=4 zeros; also treat each 8-byte aligned group
segs = []
i = LO
while i < HI:
    fo = i - DELTA
    # find run of 4 zeros
    j = i
    seg_start = i
    while j < HI:
        fo2 = j - DELTA
        if data[fo2:fo2 + 4] == b"\x00\x00\x00\x00":
            break
        j += 1
    if j > seg_start:
        segs.append((seg_start, j))
    i = j + 4

CRIBS = [b"com/", b"java/", b"Ljava", b"([B)", b"ro.", b"(I)", b"sign", b"get", b"os/", b"key", b".so", b"()L"]

print("=== printable single-byte-XOR decodes ===")
for (a, b) in segs:
    raw = data[a - DELTA:b - DELTA]
    if len(raw) < 3:
        continue
    best = None
    for k in range(256):
        dec = bytes(c ^ k for c in raw)
        r = printable_ratio(dec)
        if best is None or r > best[0]:
            best = (r, k, dec)
    r, k, dec = best
    txt = "".join(chr(c) if 32 <= c < 127 else ("\x00" if c == 0 else ".") for c in dec)
    tag = "STR" if r >= 0.95 else ("mid" if r >= 0.8 else "BIN")
    print("0x%x-0x%x len=%-3d key=%02x %s %r" % (a, b, len(raw), k, tag, txt))

print()
print("=== JNIEnv slot loads across .text ===")
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
JNIFN = {}
# index -> name (JNI 1.6 layout, 4 reserved)
names = """GetVersion DefineClass FindClass FromReflectedMethod FromReflectedField ToReflectedMethod
GetSuperclass IsAssignableFrom ToReflectedField Throw ThrowNew ExceptionOccurred ExceptionDescribe
ExceptionClear FatalError PushLocalFrame PopLocalFrame NewGlobalRef DeleteGlobalRef DeleteLocalRef
IsSameObject NewLocalRef EnsureLocalCapacity AllocObject NewObject NewObjectV NewObjectA
GetObjectClass IsInstanceOf GetMethodID
CallObjectMethod CallObjectMethodV CallObjectMethodA CallBooleanMethod CallBooleanMethodV CallBooleanMethodA
CallByteMethod CallByteMethodV CallByteMethodA CallCharMethod CallCharMethodV CallCharMethodA
CallShortMethod CallShortMethodV CallShortMethodA CallIntMethod CallIntMethodV CallIntMethodA
CallLongMethod CallLongMethodV CallLongMethodA CallFloatMethod CallFloatMethodV CallFloatMethodA
CallDoubleMethod CallDoubleMethodV CallDoubleMethodA CallVoidMethod CallVoidMethodV CallVoidMethodA
CallNonvirtualObjectMethod CallNonvirtualObjectMethodV CallNonvirtualObjectMethodA
CallNonvirtualBooleanMethod CallNonvirtualBooleanMethodV CallNonvirtualBooleanMethodA
CallNonvirtualByteMethod CallNonvirtualByteMethodV CallNonvirtualByteMethodA
CallNonvirtualCharMethod CallNonvirtualCharMethodV CallNonvirtualCharMethodA
CallNonvirtualShortMethod CallNonvirtualShortMethodV CallNonvirtualShortMethodA
CallNonvirtualIntMethod CallNonvirtualIntMethodV CallNonvirtualIntMethodA
CallNonvirtualLongMethod CallNonvirtualLongMethodV CallNonvirtualLongMethodA
CallNonvirtualFloatMethod CallNonvirtualFloatMethodV CallNonvirtualFloatMethodA
CallNonvirtualDoubleMethod CallNonvirtualDoubleMethodV CallNonvirtualDoubleMethodA
CallNonvirtualVoidMethod CallNonvirtualVoidMethodV CallNonvirtualVoidMethodA
GetFieldID GetObjectField GetBooleanField GetByteField GetCharField GetShortField GetIntField
GetLongField GetFloatField GetDoubleField
SetObjectField SetBooleanField SetByteField SetCharField SetShortField SetIntField SetLongField
SetFloatField SetDoubleField
GetStaticMethodID CallStaticObjectMethod CallStaticObjectMethodV CallStaticObjectMethodA
CallStaticBooleanMethod CallStaticBooleanMethodV CallStaticBooleanMethodA
CallStaticByteMethod CallStaticByteMethodV CallStaticByteMethodA
CallStaticCharMethod CallStaticCharMethodV CallStaticCharMethodA
CallStaticShortMethod CallStaticShortMethodV CallStaticShortMethodA
CallStaticIntMethod CallStaticIntMethodV CallStaticIntMethodA
CallStaticLongMethod CallStaticLongMethodV CallStaticLongMethodA
CallStaticFloatMethod CallStaticFloatMethodV CallStaticFloatMethodA
CallStaticDoubleMethod CallStaticDoubleMethodV CallStaticDoubleMethodA
CallStaticVoidMethod CallStaticVoidMethodV CallStaticVoidMethodA
GetStaticFieldID GetStaticObjectField GetStaticBooleanField GetStaticByteField GetStaticCharField
GetStaticShortField GetStaticIntField GetStaticLongField GetStaticFloatField GetStaticDoubleField
SetStaticObjectField SetStaticBooleanField SetStaticByteField SetStaticCharField SetStaticShortField
SetStaticIntField SetStaticLongField SetStaticFloatField SetStaticDoubleField
NewString GetStringLength GetStringChars ReleaseStringChars NewStringUTF GetStringUTFLength
GetStringUTFChars ReleaseStringUTFChars GetArrayLength NewObjectArray GetObjectArrayElement
SetObjectArrayElement NewBooleanArray NewByteArray NewCharArray NewShortArray NewIntArray
NewLongArray NewFloatArray NewDoubleArray
GetBooleanArrayElements GetByteArrayElements GetCharArrayElements GetShortArrayElements
GetIntArrayElements GetLongArrayElements GetFloatArrayElements GetDoubleArrayElements
ReleaseBooleanArrayElements ReleaseByteArrayElements ReleaseCharArrayElements ReleaseShortArrayElements
ReleaseIntArrayElements ReleaseLongArrayElements ReleaseFloatArrayElements ReleaseDoubleArrayElements
GetBooleanArrayRegion GetByteArrayRegion GetCharArrayRegion GetShortArrayRegion GetIntArrayRegion
GetLongArrayRegion GetFloatArrayRegion GetDoubleArrayRegion
SetBooleanArrayRegion SetByteArrayRegion SetCharArrayRegion SetShortArrayRegion SetIntArrayRegion
SetLongArrayRegion SetFloatArrayRegion SetDoubleArrayRegion
RegisterNatives UnregisterNatives MonitorEnter MonitorExit GetJavaVM
GetStringRegion GetStringUTFRegion GetPrimitiveArrayCritical ReleasePrimitiveArrayCritical
GetStringCritical ReleaseStringCritical NewWeakGlobalRef DeleteWeakGlobalRef ExceptionCheck
NewDirectByteBuffer GetDirectBufferAddress GetDirectBufferCapacity GetObjectRefType""".split()
for idx, nm in enumerate(names):
    JNIFN[(idx + 4) * 8] = "%d:%s" % (idx + 4, nm)
JNIFN[0x20] = "4:GetVersion(JavaVM reserved)"  # dummy

page = {}
slot_sites = {}
off = 0x1000
while off < 0x14da68:
    got = False
    for ins in md.disasm(data[off:0x14da68], off):
        got = True
        off = ins.address + ins.size
        m, ops = ins.mnemonic, ins.operands
        try:
            w = set(ins.regs_access()[1])
        except Exception:
            w = set()
        for r in w:
            if not (m in ("adrp", "adr", "add") and ops and r == ops[0].reg):
                page.pop(r, None)
        if m in ("adrp", "adr"):
            page[ops[0].reg] = ops[1].imm
        elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            if ops[1].reg in page:
                page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
        elif m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            b = ops[1].mem.base
            d = ops[1].mem.disp
            if b in page and d in JNIFN:
                slot_sites.setdefault(d, []).append(ins.address)
    if not got:
        off += 4

for slot in sorted(slot_sites):
    nm = JNIFN.get(slot, "?")
    sites = slot_sites[slot]
    print("%s (0x%x): %d sites: %s" % (nm, slot, len(sites), " ".join(hex(s) for s in sites[:14])))

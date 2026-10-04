"""Static call-graph + JNI-call + string-reference recovery for libsigner.so.

Usage: python callgraph.py <entry_vma> [depth]
"""
import sys, os, struct
from collections import deque, defaultdict
import capstone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
import strings as S

LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"

# JNINativeInterface function-table index -> name (aarch64: offset = idx*8)
JNI = {
    4: "GetVersion", 5: "DefineClass", 6: "FindClass", 7: "FromReflectedMethod",
    8: "FromReflectedField", 9: "ToReflectedMethod", 10: "GetSuperclass",
    11: "IsAssignableFrom", 12: "ToReflectedField", 13: "Throw", 14: "ThrowNew",
    15: "ExceptionOccurred", 16: "ExceptionDescribe", 17: "ExceptionClear",
    18: "FatalError", 19: "PushLocalFrame", 20: "PopLocalFrame",
    21: "NewGlobalRef", 22: "DeleteGlobalRef", 23: "DeleteLocalRef",
    24: "IsSameObject", 25: "NewLocalRef", 26: "EnsureLocalCapacity",
    27: "AllocObject", 28: "NewObject", 29: "NewObjectV", 30: "NewObjectA",
    31: "GetObjectClass", 32: "IsInstanceOf", 33: "GetMethodID",
    34: "CallObjectMethod", 35: "CallObjectMethodV", 36: "CallObjectMethodA",
    37: "CallBooleanMethod", 38: "CallBooleanMethodV", 39: "CallBooleanMethodA",
    40: "CallByteMethod", 41: "CallByteMethodV", 42: "CallByteMethodA",
    43: "CallCharMethod", 44: "CallCharMethodV", 45: "CallCharMethodA",
    46: "CallShortMethod", 47: "CallShortMethodV", 48: "CallShortMethodA",
    49: "CallIntMethod", 50: "CallIntMethodV", 51: "CallIntMethodA",
    52: "CallLongMethod", 53: "CallLongMethodV", 54: "CallLongMethodA",
    55: "CallFloatMethod", 56: "CallFloatMethodV", 57: "CallFloatMethodA",
    58: "CallDoubleMethod", 59: "CallDoubleMethodV", 60: "CallDoubleMethodA",
    61: "CallVoidMethod", 62: "CallVoidMethodV", 63: "CallVoidMethodA",
    94: "GetFieldID", 95: "GetObjectField", 96: "GetBooleanField",
    97: "GetByteField", 98: "GetCharField", 99: "GetShortField",
    100: "GetIntField", 101: "GetLongField", 102: "GetDoubleField",
    111: "GetStaticMethodID", 112: "CallStaticObjectMethod",
    113: "CallStaticObjectMethodV", 114: "CallStaticObjectMethodA",
    142: "GetStaticFieldID", 143: "GetStaticObjectField",
    159: "NewString", 160: "GetStringLength", 161: "GetStringChars",
    162: "ReleaseStringChars", 163: "NewStringUTF", 164: "GetStringUTFLength",
    165: "GetStringUTFChars", 166: "ReleaseStringUTFChars",
    167: "GetArrayLength", 168: "NewObjectArray", 169: "GetObjectArrayElement",
    170: "SetObjectArrayElement", 171: "NewBooleanArray", 172: "NewByteArray",
    173: "NewCharArray", 174: "NewShortArray", 175: "NewIntArray",
    176: "NewLongArray", 177: "NewFloatArray", 178: "NewDoubleArray",
    179: "GetBooleanArrayElements", 180: "GetByteArrayElements",
    181: "GetCharArrayElements", 182: "GetShortArrayElements",
    183: "GetIntArrayElements", 184: "GetLongArrayElements",
    185: "GetFloatArrayElements", 186: "GetDoubleArrayElements",
    187: "ReleaseBooleanArrayElements", 188: "ReleaseByteArrayElements",
    189: "ReleaseCharArrayElements", 190: "ReleaseShortArrayElements",
    191: "ReleaseIntArrayElements", 192: "ReleaseLongArrayElements",
    193: "ReleaseFloatArrayElements", 194: "ReleaseDoubleArrayElements",
    195: "GetBooleanArrayRegion", 196: "GetByteArrayRegion",
    197: "GetCharArrayRegion", 198: "GetShortArrayRegion",
    199: "GetIntArrayRegion", 200: "GetLongArrayRegion",
    201: "GetFloatArrayRegion", 202: "GetDoubleArrayRegion",
    203: "SetBooleanArrayRegion", 204: "SetByteArrayRegion",
    205: "SetCharArrayRegion", 206: "SetShortArrayRegion",
    207: "SetIntArrayRegion", 208: "SetLongArrayRegion",
    209: "SetFloatArrayRegion", 210: "SetDoubleArrayRegion",
    211: "RegisterNatives", 212: "UnregisterNatives", 213: "MonitorEnter",
    214: "MonitorExit", 215: "GetJavaVM", 216: "GetStringRegion",
    217: "GetStringUTFRegion", 218: "GetPrimitiveArrayCritical",
    219: "ReleasePrimitiveArrayCritical", 220: "GetStringCritical",
    221: "ReleaseStringCritical", 222: "NewWeakGlobalRef",
    223: "DeleteWeakGlobalRef", 224: "ExceptionCheck",
    225: "NewDirectByteBuffer", 226: "GetDirectBufferAddress",
    227: "GetDirectBufferCapacity", 228: "GetObjectRefType",
}


class Analyzer:
    def __init__(self, path=LIB):
        self.e = ELF(path)
        self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.code_start = None
        self.code_end = None
        for s in self.e.sections:
            if s["name"] in (".text",) or (s["flags"] & 0x4 and s["flags"] & 0x2):
                if s["addr"] and (self.code_start is None or s["addr"] < self.code_start):
                    self.code_start = s["addr"]
                    self.code_end = s["addr"] + s["size"]
        # string tables
        self.obf = {}
        self.plain = {}
        for sec in (".data", ".data.rel.ro", ".rodata", ".bss"):
            s = self.e.byname.get(sec)
            if not s or s["type"] == 8:
                continue
            blob = self.e.data[s["offset"]:s["offset"] + s["size"]]
            if sec in (".data", ".data.rel.ro"):
                for va, txt, clen, key in S.scan(blob, s["addr"], minlen=2):
                    self.obf[va] = (txt, key)
            for va, txt in S.scan_plain(blob, s["addr"], minlen=4):
                self.plain[va] = txt
        self.funcs = {}

    def sref(self, va):
        if va in self.obf:
            return f"[obf] {self.obf[va][0]!r} (key=0x{self.obf[va][1]:02x})"
        if va in self.plain:
            return f"[asc] {self.plain[va]!r}"
        return None

    def func_size(self, va):
        for s in self.e.dynsyms:
            if s["value"] == va and s["size"]:
                return s["size"]
        return None

    def analyze(self, va, size=None, window=0x6000):
        if va in self.funcs:
            return self.funcs[va]
        n = size or self.func_size(va) or window
        n = min(n, window)
        blob = self.e.read(va, n)
        if blob is None:
            return None
        rec = dict(va=va, calls=[], imports=set(), jni=[], srefs=[], blr=[],
                   ninsn=0, size=n)
        pending = {}
        for ins in self.md.disasm(blob, va):
            rec["ninsn"] += 1
            m = ins.mnemonic
            ops = ins.operands
            if m == "adrp" and len(ops) == 2 and ops[0].type == capstone.arm64.ARM64_OP_REG:
                pending[ops[0].reg] = ops[1].imm
            elif m == "adr" and len(ops) == 2:
                t = ops[1].imm
                sr = self.sref(t)
                if sr:
                    rec["srefs"].append((ins.address, sr))
            elif m in ("add",) and len(ops) == 3 and \
                    ops[0].type == capstone.arm64.ARM64_OP_REG and \
                    ops[1].type == capstone.arm64.ARM64_OP_REG and \
                    ops[2].type == capstone.arm64.ARM64_OP_IMM:
                if ops[1].reg in pending:
                    t = pending[ops[1].reg] + ops[2].imm
                    sr = self.sref(t)
                    if sr:
                        rec["srefs"].append((ins.address, sr))
            elif m == "bl" and ops and ops[0].type == capstone.arm64.ARM64_OP_IMM:
                t = ops[0].imm
                if t in self.e.plt_map:
                    rec["imports"].add(self.e.plt_map[t])
                elif self.code_start and self.code_start <= t < self.code_end:
                    rec["calls"].append(t)
            elif m == "blr" and ops and ops[0].type == capstone.arm64.ARM64_OP_REG:
                rec["blr"].append((ins.address, ins.reg_name(ops[0].reg)))
            elif m in ("ldr", "ldrb", "ldrsw") and len(ops) >= 2 and \
                    ops[0].type == capstone.arm64.ARM64_OP_REG and \
                    ops[1].type == capstone.arm64.ARM64_OP_MEM:
                mem = ops[1].mem
                if mem.index == 0 and mem.disp % 8 == 0:
                    idx = mem.disp // 8
                    if idx in JNI:
                        rec["jni"].append((ins.address, ins.reg_name(ops[0].reg),
                                           mem.disp, JNI[idx]))
        self.funcs[va] = rec
        return rec

    def walk(self, entry, maxdepth=3, maxfuncs=400):
        seen = {}
        q = deque([(entry, 0)])
        while q:
            va, d = q.popleft()
            if va in seen or len(seen) > maxfuncs:
                continue
            r = self.analyze(va)
            if not r:
                continue
            seen[va] = (d, r)
            if d >= maxdepth:
                continue
            for c in r["calls"]:
                if c not in seen:
                    q.append((c, d + 1))
            _ = maxdepth
        return seen

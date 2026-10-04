"""Find the envelope OUTPUT anchor inside the nSign CFG.

nSign must hand a 192-byte byte[] back to Java. In JNI that is done through the
JNINativeInterface function table (indirect call: ldr xN,[xEnv,#off]; blr xN),
so PLT-based import analysis never sees it. We scan the already-crawled nSign
instruction set for loads at the JNI offsets of the array/buffer functions,
then dump the surrounding instructions to read the size/length arguments.

Also dumps .rodata (only 336 B in this lib) looking for cipher constants.
"""
import os
import sys
import pickle
import struct

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

# JNINativeInterface index * 8 -> name (curated: everything buffer/array related)
JNI = {
    0x30: "FindClass",
    0x108: "GetMethodID",
    0x110: "CallObjectMethod",
    0x118: "CallBooleanMethod",
    0x138: "CallByteMethod",
    0x168: "CallVoidMethod",
    0x1F0: "CallStaticObjectMethod",
    0x2A8: "GetFieldID",
    0x518: "NewString",
    0x538: "NewStringUTF",
    0x558: "GetArrayLength",
    0x560: "NewObjectArray",
    0x578: "SetObjectArrayElement",
    0x580: "NewByteArray",
    0x5C0: "GetByteArrayElements",
    0x5C8: "ReleaseByteArrayElements",
    0x600: "GetIntArrayElements",
    0x640: "GetByteArrayRegion",
    0x680: "SetByteArrayRegion",
    0x6C0: "GetObjectArrayElement",
    0x2C0: "GetObjectField",
    0x8A0: "GetPrimitiveArrayCritical",
    0x8A8: "ReleasePrimitiveArrayCritical",
}

# the envelope size we are hunting for
ENV_LEN = 192


def main():
    e = ELF(LIB)
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)
    print("nSign path: %d instructions" % len(inset))

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    lo = e.byname[".text"]["addr"]
    hi = lo + e.byname[".text"]["size"]

    hits = {name: [] for name in JNI.values()}
    # walk the contiguous instruction addresses we know are reachable
    # (disassembling windows is faster than per-address)
    for start in sorted(inset):
        if not (lo <= start < hi):
            continue
        off = e.vaddr_to_off(start)
        if off is None:
            continue
        for ins in md.disasm(e.data[off:off + 4], start):
            if ins.mnemonic != "ldr":
                break
            ops = ins.operands
            if len(ops) != 2:
                break
            mem = ops[1]
            if mem.type != capstone.arm64.ARM64_OP_MEM:
                break
            imm = mem.mem.disp
            name = JNI.get(imm)
            if name:
                hits[name].append(ins.address)
            break

    print("\n=== JNI call sites on the nSign path ===")
    for name, addrs in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        if addrs:
            print("  %-32s %3d site(s)  first @ 0x%x" % (name, len(addrs), addrs[0]))

    # dump context around the array-output functions
    for name in ("NewByteArray", "SetByteArrayRegion", "GetByteArrayElements",
                 "ReleaseByteArrayElements", "GetByteArrayRegion"):
        addrs = hits.get(name) or []
        if not addrs:
            continue
        print("\n### %s — %d site(s)" % (name, len(addrs)))
        for a in addrs[:12]:
            print("  ---- 0x%x" % a)
            ctx_lo = max(lo, a - 40)
            o = e.vaddr_to_off(ctx_lo)
            for ins in md.disasm(e.data[o:o + 96], ctx_lo):
                mark = "  <<<" if ins.address == a else ""
                txt = "%-8s %s" % (ins.mnemonic, ins.op_str)
                # flag 192 / buffer-size immediates
                if "0xc0" in ins.op_str or "#192" in ins.op_str or "#0xc0" in ins.op_str:
                    txt += "   <== 192!"
                print("    0x%x: %s%s" % (ins.address, txt, mark))
                if ins.address > a + 32:
                    break

    # .rodata: only 336 bytes, dump it
    ro = e.section_bytes(".rodata")
    print("\n=== .rodata (%d bytes) ===" % len(ro))
    for i in range(0, len(ro), 16):
        chunk = ro[i:i + 16]
        print("  %04x  %-48s  %s" % (i, chunk.hex(),
                                     "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    vals = list(ro)
    if len(set(vals)) == len(vals) and len(vals) >= 128:
        print("  -> .rodata is a bijection of %d values: possible S-box" % len(vals))


if __name__ == "__main__":
    main()

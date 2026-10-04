"""Parse a flattened obfuscated function: extract dispatch table + block summaries.
Usage: python parse_flat.py <start_va_hex> <end_va_hex> [dispatch_va_hex]
"""
import sys, re
import capstone

LIB = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
data = open(LIB, "rb").read()

import struct
# minimal vaddr->offset via program headers
e_phoff, = struct.unpack_from("<Q", data, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", data, off)
    if p_type == 1:
        segs.append((p_vaddr, p_offset, p_filesz))

def v2o(va):
    for v, o, f in segs:
        if v <= va < v + f:
            return o + (va - v)
    return None

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
disp_va = int(sys.argv[3], 16) if len(sys.argv) > 3 else None

insns = {}
order = []
off = v2o(start)
for ins in md.disasm(data[off:off + (end - start)], start):
    insns[ins.address] = ins
    order.append(ins.address)

def fmt(i):
    return f"0x{i.address:x}  {i.mnemonic:8s} {i.op_str}"

# ---- track 64-bit constants: mov xN, #imm / movk xN, #imm, lsl #16/32/48 ----
def track_consts(addrs, reg_init=None):
    """Return {reg: value} after replaying mov/movk over the given address list."""
    regs = dict(reg_init or {})
    for a in addrs:
        i = insns.get(a)
        if i is None:
            continue
        m = re.match(r"^mov\s+(x|w)(\d+|zr)\s+#(0x[0-9a-f]+|\d+)$", i.op_str) if i.mnemonic == "mov" else None
        if i.mnemonic == "mov":
            mm = re.match(r"^(x|w)(\d+), #(0x[0-9a-f]+|\d+)$", i.op_str)
            if mm:
                pre, num, imm = mm.group(1), int(mm.group(2)), int(mm.group(3), 0)
                if pre == 'x':
                    regs[num] = imm
                else:
                    regs[num] = regs.get(num, 0) & ~0xFFFFFFFF | imm
            continue
        if i.mnemonic == "movk":
            mm = re.match(r"^(x|w)(\d+), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?$", i.op_str)
            if mm:
                pre, num, imm, sh = mm.group(1), int(mm.group(2)), int(mm.group(3), 0), int(mm.group(4) or 0)
                if pre == 'x':
                    cur = regs.get(num, 0)
                    regs[num] = cur | (imm << sh)
                else:
                    cur = regs.get(num, 0)
                    regs[num] = (cur & ~(0xFFFF << sh)) | (imm << sh)
            continue
        if i.mnemonic == "movz" or i.mnemonic == "movn":
            continue
    return regs

# ---- 1. walk the dispatch chain ----
def parse_dispatch(head):
    table = []  # (const, target, cmp_site)
    a = head
    seen = set()
    while True:
        if a in seen or a not in insns:
            break
        seen.add(a)
        i = insns[a]
        # skip mov/movk prelude, find cmp x9, xN
        if i.mnemonic == "cmp" and i.op_str.startswith("x9, x"):
            r = int(i.op_str.split(", ")[1][1:])
            # backtrack within chain segment to collect mov/movk for both regs
            back = []
            b = a
            while len(back) < 40:
                b -= 4
                if b not in insns:
                    break
                bi = insns[b]
                if bi.mnemonic in ("mov", "movk"):
                    back.append(b)
                elif bi.mnemonic == "cmp":
                    break
                elif bi.mnemonic.startswith("b."):
                    break
            regs = track_consts(sorted(back))
            const = regs.get(r)
            nxt = a + 4
            ni = insns.get(nxt)
            if ni and ni.mnemonic.startswith("b.") and const is not None:
                tgt = int(ni.op_str.replace("#", ""), 16)
                table.append((const, tgt, a))
                a = nxt + 4
                continue
            elif ni and ni.mnemonic.startswith("b."):
                tgt = int(ni.op_str.replace("#", ""), 16)
                table.append((None, tgt, a))
                a = nxt + 4
                continue
            else:
                a = nxt
                continue
        a = a + 4
    return table

if disp_va:
    table = parse_dispatch(disp_va)
    print(f"=== DISPATCH TABLE (from 0x{disp_va:x}) ===")
    for const, tgt, site in table:
        cs = f"0x{const:016x}" if const is not None else "?"
        print(f"  cmp@0x{site:x}  const {cs} -> 0x{tgt:x}")

# ---- 2. block summaries ----
REAL = {"bl", "blr", "adrp", "adr", "svc", "mrs", "casab", "casalb", "stlrb", "stlr", "ldar", "ldaxr", "ldur", "str", "strb", "stur", "strh", "ldr", "ldrb", "ldrsw", "ldr", "eor", "add", "sub", "orr", "and", "tst", "cmp", "cset", "csel", "scvtf", "ldr", "fmov", "movi", "ldp", "stp", "nop", "b", "b.eq", "b.ne", "b.gt", "b.lt", "b.le", "b.ge", "b.hi", "b.ls", "ret", "sxtw", "uxtw", "ldr", "ldrsh", "ldrb", "ldrsb"}

def block_summary(head, maxn=80):
    out = []
    a = head
    for _ in range(maxn):
        i = insns.get(a)
        if i is None:
            break
        out.append(fmt(i))
        if i.mnemonic in ("ret",):
            break
        if i.mnemonic == "b" and not i.op_str.startswith("#"):
            t = int(i.op_str.replace("#", ""), 16)
            if t != a + 4:
                out.append(f"    -> b 0x{t:x}")
                break
        a += 4
    return out

if __name__ == "__main__" and disp_va is None:
    pass

"""Extract the TRUE state machine of a flattened obfuscated fn.
Dispatcher pattern: pass head compares x10 vs x26; then latches x9=x10 and chains
cmp x9, xK / b.eq <tgt>. Sites that b.eq back to the dispatcher head have already
loaded the NEXT tag into x10 -> real transition = that x10 value.
"""
import sys, re, struct
import capstone

LIB = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
data = open(LIB, "rb").read()
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

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
head = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
entry_tag = int(sys.argv[4], 16) if len(sys.argv) > 4 else None

insns = {}
seq = []
off = v2o(start)
for ins in md.disasm(data[off:off + (end - start)], start):
    insns[ins.address] = (ins.mnemonic, ins.op_str)
    seq.append(ins.address)

def val_of_reg(reg, upto):
    """scan back from upto for mov/movk building reg"""
    v = 0
    seen = set()
    for a in reversed([x for x in seq if x < upto]):
        mn, ops = insns[a]
        m = re.match(rf"^{reg}, #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?$", ops) if mn == "movk" else None
        if m:
            sh = int(m.group(2) or 0)
            if sh not in seen:
                v |= int(m.group(1), 0) << sh
                seen.add(sh)
            continue
        m = re.match(rf"^{reg}, #(0x[0-9a-f]+|\d+)$", ops) if mn == "mov" else None
        if m:
            if 0 not in seen:
                v |= int(m.group(1), 0)
                seen.add(0)
            continue
        if mn.startswith("b.") or mn == "b":
            break
    return v, seen

# prelude register values (for compares against x20..x26)
prelude = {}
for a in [x for x in seq if x < head]:
    mn, ops = insns[a]
    if mn in ("mov", "movk"):
        m = re.match(r"^(x\d+), ", ops)
        if m:
            r = m.group(1)
            val, seen = val_of_reg(r, a + 4)
            if seen:
                prelude[r] = val

print("prelude:", {k: f"0x{v:016x}" for k, v in sorted(prelude.items())})

# walk dispatcher chain
sites = []  # (const, cmp_site, btarget)
a = head
chain_end = None
while a in insns:
    mn, ops = insns[a]
    if mn == "cmp" and ops.startswith("x9, "):
        rname = "x" + ops.split(", ")[1][1:]
        const = prelude.get(rname)
        if const is None:
            const, _ = val_of_reg(rname, a)
        tgt = None
        nxt = seq[seq.index(a) + 1]
        nmn, nops = insns[nxt]
        if nmn.startswith("b."):
            tgt = int(nops.replace("#", ""), 16)
            sites.append((const, a, tgt))
            a = seq[seq.index(nxt) + 1]
            continue
        a = nxt
        continue
    if mn == "cmp" and ops.startswith("x10, "):
        rname = "x" + ops.split(", ")[1][1:]
        const = prelude.get(rname)
        tgt = None
        nxt = seq[seq.index(a) + 1]
        nmn, nops = insns[nxt]
        if nmn.startswith("b."):
            tgt = int(nops.replace("#", ""), 16)
            sites.append((const, a, tgt))
            a = seq[seq.index(nxt) + 1]
            continue
        a = nxt
        continue
    if mn in ("b", "ret"):
        chain_end = a
        break
    a = seq[seq.index(a) + 1]

print(f"chain from 0x{head:x} to 0x{chain_end:x}: {len(sites)} sites")

def x10_at(cmp_site):
    """value of x10 loaded in this site's preamble"""
    val, seen = val_of_reg("x10", cmp_site)
    return val if seen else None

table = {}
for const, site, tgt in sites:
    if const is None:
        continue
    if tgt == head:
        real = x10_at(site)
        table[const] = ("bounce", real, site)
    else:
        table[const] = ("block", tgt, site)

print("\n=== TRANSITIONS ===")
for const, (kind, tgt, site) in sorted(table.items()):
    ts = f"0x{tgt:x}" if tgt is not None else "?"
    print(f"  tag 0x{const:016x} @0x{site:x} -> {kind} {ts}")

# walk from entry tag
print("\n=== EXECUTION TRACE from entry tag ===")
if entry_tag:
    tag = entry_tag
    seen = set()
    steps = 0
    while tag is not None and steps < 200:
        steps += 1
        ent = table.get(tag)
        if ent is None:
            print(f"  0x{tag:016x} -> NOT IN TABLE (stop)")
            break
        kind, tgt, site = ent
        print(f"  step {steps}: tag 0x{tag:016x} @0x{site:x} -> {kind} 0x{tgt:x}" if tgt is not None
              else f"  step {steps}: tag 0x{tag:016x} @0x{site:x} -> {kind} ?")
        if kind == "block" or tag in seen:
            break
        seen.add(tag)
        tag = tgt

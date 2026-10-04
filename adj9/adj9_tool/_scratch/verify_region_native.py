import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SO = Path(r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so")
OUT = Path(__file__).with_name("verify_region_native.txt")
START = {
    "lcg_step": 0x13DFD0,
    "get8random": 0x13E0E4,
    "seed_wrapper": 0x143794,
    "ctx_init": 0x1437EC,
    "pair_consume": 0x1439C4,
    "shuffle16": 0x143C88,
    "transpose16": 0x143D98,
    "whitener": 0x144074,
    "whitener_tail": 0x1441E4,
    "nSign_hub": 0xDA99C,
}

data = SO.read_bytes()
assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1
phoff = struct.unpack_from("<Q", data, 0x20)[0]
phentsize = struct.unpack_from("<H", data, 0x36)[0]
phnum = struct.unpack_from("<H", data, 0x38)[0]
segments = []
for i in range(phnum):
    off = phoff + i * phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    if p_type != 1:
        continue
    p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off + 8)
    segments.append((p_vaddr, p_vaddr + p_filesz, p_offset, p_flags, p_memsz))

def read_va(va, size):
    for lo, hi, off, _flags, _memsz in segments:
        if lo <= va and va + size <= hi:
            pos = off + va - lo
            return data[pos:pos + size]
    raise ValueError(hex(va))

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

def insns(va, size):
    return list(md.disasm(read_va(va, size), va))

def xrefs(target):
    lo, hi, off, flags, _ = next(s for s in segments if s[3] & 1)
    found = []
    for rel in range(0, hi - lo, 4):
        word = struct.unpack_from("<I", data, off + rel)[0]
        opcode = (word >> 26) & 0x3f
        if opcode == 0x25:  # BL
            imm26 = word & 0x03ffffff
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            kind = "bl"
        elif opcode == 0x05:  # B
            imm26 = word & 0x03ffffff
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            kind = "b"
        else:
            continue
        addr = lo + rel
        if addr + (imm26 << 2) == target:
            found.append((addr, kind, word.to_bytes(4, "little").hex()))
    return found

lines = [f"SO size={len(data)} sha256 pending", "SEGMENTS:"]
for lo, hi, off, flags, memsz in segments:
    lines.append(f"  va={lo:#x}..{hi:#x} off={off:#x} flags={flags:#x} memsz={memsz:#x}")
lines.append("")
lines.append("DIRECT BRANCH XREFS:")
for name, addr in START.items():
    lines.append(f"  {name} {addr:#x}: {xrefs(addr)}")

# Fixed ranges chosen to include surrounding returns and avoid mistaking tail calls for RET.
ranges = {
    "lcg_step": (0x13DFD0, 0x13E030),
    "seed_wrapper": (0x143794, 0x1437EC),
    "ctx_init_full": (0x1437EC, 0x143C88),
    "pair_consume": (0x1439C4, 0x143A60),
    "shuffle16": (0x143C88, 0x143D98),
    "transpose16": (0x143D98, 0x144074),
    "whitener_and_tail": (0x144074, 0x144224),
    "get8random_full": (0x13E0E4, 0x13E870),
    "nSign_seed_call_context": (0xDB100, 0xDB1E0),
}
for name, (start, end) in ranges.items():
    lines.append("")
    lines.append(f"== {name} {start:#x}..{end:#x} ==")
    for i in insns(start, end-start):
        raw = i.bytes.hex()
        lines.append(f"{i.address:#010x}  {raw:<10} {i.mnemonic:<7} {i.op_str}")

OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(OUT)

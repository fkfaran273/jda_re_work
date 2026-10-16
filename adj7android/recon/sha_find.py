# Find the SHA-256 implementation: scan .text movz/movk immediates for the
# K-constant sequence, and collect 64-bit constant-building pairs.
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

d = open(r"..\apks\lib\hanaf\libsigner.so", "rb").read()
TEXT_OFF = 0xa090
TEXT_SZ = 0x108c3c

K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174]
IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
code = d[TEXT_OFF:TEXT_OFF + TEXT_SZ]
imm_at = {}          # addr -> (mnemonic, imm, shift)
words = {}           # addr -> assembled 32-bit value from movz+movk pairs
pending = {}
for ins in md.disasm(code, 0xa090):
    m = ins.mnemonic
    if m in ("movz", "movk"):
        try:
            parts = ins.op_str.split(",")
            reg = parts[0].strip()
            imm = int(parts[1].strip().replace("#", ""), 0)
            shift = 0
            if len(parts) >= 3 and "lsl" in parts[2]:
                shift = int(parts[2].strip().split("#")[1], 0)
        except Exception:
            continue
        imm_at[ins.address] = (m, imm, shift, reg)
        if m == "movz":
            pending[reg] = (imm << shift) & 0xFFFFFFFFFFFFFFFF
            words[ins.address] = (imm << shift) & 0xFFFFFFFFFFFFFFFF
        elif m == "movk":
            base = pending.get(reg, 0)
            val = (base | (imm << shift)) & 0xFFFFFFFFFFFFFFFF
            pending[reg] = val
            words[ins.address] = val
    elif m in ("mov", "orr", "add") and "w" in ins.op_str[:1]:
        pass

# hunt for the K sequence among assembled word values (consecutive addresses)
addr_list = sorted(words)
vals = [words[a] for a in addr_list]
Kset = set(K) | set(IV)
hits = {}
for i, v in enumerate(vals):
    v32 = v & 0xFFFFFFFF
    if v32 in Kset:
        hits.setdefault(hex(v32), []).append(hex(addr_list[i]))
for kv, addrs in sorted(hits.items()):
    print("const %s at %s" % (kv, addrs[:6]))
if not hits:
    print("no SHA constants found as movz/movk immediates")

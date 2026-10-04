import sys
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
print("so size", hex(len(data)))
# ELF: find .text. Parse program headers simply.
import struct
assert data[:4]==b"\x7fELF"
ei_class=data[4]  # 2 = ELF64
e_phoff=struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize=struct.unpack_from("<H", data, 0x36)[0]
e_phnum=struct.unpack_from("<H", data, 0x38)[0]
text=None
for i in range(e_phnum):
    off=e_phoff+i*e_phentsize
    p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align=struct.unpack_from("<IIQQQQQQ", data, off)
    if p_flags&1:  # executable
        text=(p_offset,p_vaddr,p_filesz)
        break
print("text", text)
o,va,sz=text
code=data[o:o+sz]
# ARMv8 crypto insns have specific encodings (32-bit):
# AESE  x: 0100 1110 1100 0000 0010 0Rm 0 0 100 Rn Rd  -> base 0x4E284800
# AESD  x: 0x4E285800
# AESMC x: 0x4E286800
# AESIMC:0x4E287800
# SHA1C  0x5E000000.. base 0x5E000000
# SHA1H  0x5E280800? actually SHA1H Rd,Rn,Rm 0x5E280800 base? Let me just scan for opcode prefixes.
# We scan 4-byte little-endian words and mask top 12 bits.
marks={0x4E2:["AESE/AESD/AESMC family"],0x5E0:["SHA1/SHA2 family"]}
from collections import Counter
c=Counter()
for i in range(0,len(code)-4,4):
    w=struct.unpack_from("<I", code, i)[0]
    top=w>>20  # top 12 bits
    if (w & 0xFFE00000)==0x4E200000: c["aes_family"]+=1
    if (w & 0xFFE00000)==0x5E000000: c["sha_family"]+=1
    if (w & 0xBF200000)==0x0E200000:  # crypto (aese etc more precisely)
        pass
print("aes_family (0x4E2xxxxx) count:", c["aes_family"])
print("sha_family (0x5E0xxxxx) count:", c["sha_family"])
# Also scan for AESE exact: enc = 0x4E284800 | (Rn<<5) | Rm<<16 ... too loose. Summarize by exact encodings:
exact=Counter()
for i in range(0,len(code)-4,4):
    w=struct.unpack_from("<I", code, i)[0]
    if (w & 0xFFE00000)==0x4E200000:
        exact[hex(w & 0xFFE0FE00)]+=1
    if (w & 0xFFE00000)==0x5E000000:
        exact[hex(w & 0xFFE0FE00)]+=1
for k,v in exact.most_common(20):
    print(k,v)

#!/usr/bin/env python3
import sys
sys.path.insert(0,'.')
from _fold_exact import dis, data, secs
dis(0x143794, 20, 'ctx_wrapper 0x143794')
# find the hub function start: scan backwards from 0xdb160 for 'sub sp, sp, #0x210'
import struct
# locate .text section
for nm,(a,o,s) in secs.items():
    if a <= 0xdb160 < a+s and s:
        base_a, base_o = a, o
        break
code = data[base_o:base_o+s]
target = 0xdb160
for va in range(target, base_a, -4):
    off = va - base_a
    w = struct.unpack_from('<I', code, off)[0]
    # sub sp,sp,#imm  : 0xD10xxxFF-ish  (SUBS/ADD imm) ; use capstone instead
    pass
# simpler: disassemble 0x200 bytes before 0xdb160 and look for prologue
dis(0xdb000, 0x60, 'before hub (look for sub sp)')

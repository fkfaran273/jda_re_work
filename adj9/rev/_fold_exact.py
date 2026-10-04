#!/usr/bin/env python3
"""Fresh disassembly of the adj9 fold/ctx machinery to settle the two-ctx question."""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

LIB = r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
data = open(LIB, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# section headers -> .text va==off
import struct as st
e_shoff = st.unpack_from('<Q', data, 0x28)[0]
e_shentsize = st.unpack_from('<H', data, 0x3a)[0]
e_shnum = st.unpack_from('<H', data, 0x3c)[0]
e_shstrndx = st.unpack_from('<H', data, 0x3e)[0]
def sh(i):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size = st.unpack_from('<IIQQQQ', data, o)
    return name, typ, flags, addr, off, size
shstr = sh(e_shstrndx)
secs = {}
for i in range(e_shnum):
    n, t, f, a, o, s = sh(i)
    nm = data[shstr[4] + n: data.index(b'\0', shstr[4] + n)].decode()
    secs[nm] = (a, o, s)

def dis(va, n, tag):
    print('\n===== %s @ 0x%x =====' % (tag, va))
    # find containing section
    for nm, (a, o, s) in secs.items():
        if a <= va < a + s and s:
            off = o + (va - a)
            code = data[off:off + n * 4]
            for ins in md.disasm(code, va):
                print('  0x%06x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
            return
    print('  not in a mapped section')

if __name__ == '__main__':
    targets = {
        '0x13e0e4 get8random': (0x13e0e4, 60),
        '0x13e030 lcg_init': (0x13e030, 60),
        '0x13dfd0 park_miller': (0x13dfd0, 26),
        '0x143c88 shuffle16': (0x143c88, 60),
        '0x143794 ctx_wrapper': (0x143794, 24),
        '0x1437ec ctx_init': (0x1437ec, 60),
        '0x143b20 search_slot': (0x143b20, 70),
        '0x144074 fold16': (0x144074, 70),
        '0x1441e4 fold_wrapper': (0x1441e4, 16),
        '0x144214 driver': (0x144214, 40),
    }
    for tag, (va, n) in targets.items():
        dis(va, n, tag)

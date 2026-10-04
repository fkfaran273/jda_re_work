# resolve ALL 74 PLT stubs -> import symbols, via .rela.plt + .dynsym
import struct
from elftools.elf.elffile import ELFFile

SO = r"C:\Users\Apps\Downloads\com.penti.app\split_config.arm64_v8a.apk"
OFF = 0x54000

f = open(SO, 'rb')
f.seek(OFF)
data = f.read(0x149000)
import io
elf = ELFFile(io.BytesIO(data))

def sec(name):
    s = elf.get_section_by_name(name)
    return s

plt = sec('.plt')
relaplt = sec('.rela.plt')
dynsym = sec('.dynsym')
dynstr = sec('.dynstr')

print("plt sh_addr=0x%x size=0x%x entry=0x%x" % (plt['sh_addr'], plt['sh_size'], plt['sh_entsize']))
print("relaplt entries:", relaplt.num_relocations())

# plt header is 32 bytes; stub i at plt_addr + 32 + i*16
base = plt['sh_addr'] + 32
table = {}
for i in range(relaplt.num_relocations()):
    r = relaplt.get_relocation(i)
    sym = dynsym.get_symbol(r['r_info_sym'])
    nm = sym.name
    table[base + i * 16] = nm

# also .rela.dyn for completeness? skip.
for a in sorted(table):
    print("0x%06x  %s" % (a, table[a]))

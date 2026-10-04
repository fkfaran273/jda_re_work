"""Minimal ELF64 (aarch64) reader: sections, dynamic symbols, PLT import map.
Only what's needed to statically reverse libsigner.so."""
import struct

DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 1, 2, 3, 4, 5, 6
DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 7, 8, 9, 10, 11
DT_JMPREL, DT_PLTREL, DT_REL, DT_RELSZ, DT_RELENT = 23, 20, 17, 18, 19

SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM, SHT_DYNAMIC = 2, 3, 11, 6


class ELF:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        assert d[:4] == b"\x7fELF", "not an ELF"
        self.bits = 64 if d[4] == 2 else 32
        e_shoff, = struct.unpack_from("<Q", d, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)
        self.sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            (name, typ, flags, addr, offset, size, link, info,
             align, entsize) = struct.unpack_from("<IIQQQQIIQQ", d, off)
            self.sections.append(dict(name_off=name, type=typ, flags=flags,
                                      addr=addr, offset=offset, size=size,
                                      link=link, info=info, entsize=entsize))
        shstr = self.sections[e_shstrndx]
        self.shstr = d[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for s in self.sections:
            s["name"] = self._cstr(self.shstr, s["name_off"])
        self.byname = {s["name"]: s for s in self.sections}

        # program headers -> vaddr<->file offset mapping
        e_phoff, = struct.unpack_from("<Q", d, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
        self.segments = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
             p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", d, off)
            self.segments.append(dict(type=p_type, flags=p_flags, offset=p_offset,
                                      vaddr=p_vaddr, filesz=p_filesz,
                                      memsz=p_memsz, align=p_align))
        self._parse_dynamic()
        self._parse_symbols()
        self._parse_plt()

    # ---------- helpers ----------
    @staticmethod
    def _cstr(buf, off):
        end = buf.find(b"\x00", off)
        return buf[off:end].decode("utf-8", "replace") if end >= 0 else ""

    def vaddr_to_off(self, va):
        for s in self.sections:
            if s["addr"] and s["type"] != 8 and s["addr"] <= va < s["addr"] + s["size"]:
                return s["offset"] + (va - s["addr"])
        for p in self.segments:
            if p["type"] == 1 and p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
                return p["offset"] + (va - p["vaddr"])
        return None

    def read(self, va, n):
        off = self.vaddr_to_off(va)
        if off is None:
            return None
        return self.data[off:off + n]

    def section_bytes(self, name):
        s = self.byname.get(name)
        if not s:
            return b""
        return self.data[s["offset"]:s["offset"] + s["size"]]

    # ---------- dynamic ----------
    def _parse_dynamic(self):
        self.dyn = []
        for p in self.segments:
            if p["type"] == 2:  # PT_DYNAMIC
                base, sz = p["offset"], p["filesz"]
                for i in range(sz // 16):
                    tag, val = struct.unpack_from("<QQ", self.data, base + i * 16)
                    if tag == DT_NULL:
                        break
                    self.dyn.append((tag, val))
        d = dict()
        for t, v in self.dyn:
            d.setdefault(t, v)
        self.dt = d
        self.dynstr = None
        if DT_STRTAB in d:
            self.dynstr = self.read(d[DT_STRTAB], 0x100000)
            if self.dynstr is not None:
                self.dynstr = self.dynstr[:self.dynstr.find(b"\x00\x00") + 1] \
                    if b"\x00\x00" in self.dynstr else self.dynstr

    def _parse_symbols(self):
        self.dynsyms = []
        if DT_SYMTAB not in self.dt:
            return
        strtab_va = self.dt.get(DT_STRTAB)
        symtab_va = self.dt[DT_SYMTAB]
        off = self.vaddr_to_off(symtab_va)
        # count symbols: hash table nchain, or until we run out; use .dynsym size if present
        n = 0
        if ".dynsym" in self.byname:
            n = self.byname[".dynsym"]["size"] // 24
        else:
            n = 4096
        for i in range(n):
            b = self.data[off + i * 24:off + i * 24 + 24]
            if len(b) < 24:
                break
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack("<IBBHQQ", b)
            name = self._cstr(self.dynstr, st_name) if self.dynstr is not None else ""
            self.dynsyms.append(dict(name=name, info=st_info, shndx=st_shndx,
                                     value=st_value, size=st_size))

    def _parse_plt(self):
        """map PLT stub vaddr -> imported symbol name"""
        self.plt_map = {}
        self.imports = {}
        if DT_JMPREL not in self.dt or ".rela.plt" not in self.byname:
            return
        rela = self.byname[".rela.plt"]
        plt = self.byname.get(".plt")
        if not plt:
            return
        cnt = rela["size"] // 24
        ent = plt["addr"] + 32  # aarch64 PLT0 is 32 bytes
        for i in range(cnt):
            b = self.data[rela["offset"] + i * 24: rela["offset"] + i * 24 + 24]
            r_off, r_info, r_add = struct.unpack("<QQq", b)
            sym = r_info >> 32
            name = self.dynsyms[sym]["name"] if sym < len(self.dynsyms) else "?"
            va = ent + 16 * i
            self.plt_map[va] = name
            self.imports[name] = va

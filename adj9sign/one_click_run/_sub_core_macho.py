"""_sub_core_macho.py — minimal Mach-O / FAT reader (stdlib-only).

Parses 64-bit Mach-O headers (thin or fat), exposes:
  slices(path)            -> list of (cpu_type_name, arch, offset, size, data-accessor)
  Segments of a thin slice: (name, vmaddr, vmsize, fileoff, filesize, sections[])
Used by _sub_core_constscan.py / _sub_core_strdiff.py / _sub_core_objc.py.
"""
import struct

CPU_NAMES = {7: "x86_64", 7 | 0x80000000: "x86_64", 12: "arm",
             12 | 0x01000000: "arm64", 0x0100000C: "arm64"}


class Slice:
    def __init__(self, path, name, offset, size):
        self.path = path
        self.name = name          # e.g. "arm64", "x86_64"
        self.offset = offset      # absolute file offset of thin Mach-O start
        self.size = size
        self._data = None
        self.segments = []        # filled by parse()

    @property
    def data(self):
        if self._data is None:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                self._data = f.read(self.size)
        return self._data

    def parse(self):
        d = self.data
        magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = \
            struct.unpack_from("<IiiIIIII", d, 0)
        if magic not in (0xFEEDFACF, 0xCFFAEDFE):
            raise ValueError(f"not 64-bit Mach-O: magic={magic:#x}")
        self.cputype = cputype
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = d[off + 8:off + 16].rstrip(b"\x00").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", d, off + 24)
                nsects = struct.unpack_from("<I", d, off + 64)[0]
                sects = []
                so = off + 72
                for _s in range(nsects):
                    sn = d[so:so + 16].rstrip(b"\x00").decode(errors="replace")
                    sg = d[so + 16:so + 32].rstrip(b"\x00").decode()
                    addr, sz = struct.unpack_from("<QQ", d, so + 32)
                    foff = struct.unpack_from("<I", d, so + 48)[0]
                    sects.append({"sect": sn, "seg": sg, "addr": addr,
                                  "size": sz, "fileoff": foff})
                    so += 80
                self.segments.append({"name": segname, "vmaddr": vmaddr,
                                      "vmsize": vmsize, "fileoff": fileoff,
                                      "filesize": filesize, "sections": sects})
            off += cmdsize
        return self

    def sections(self):
        for seg in self.segments:
            for s in seg["sections"]:
                yield seg, s

    def sec_of(self, fileoff):
        """Map a file offset to (segment, section) names."""
        for seg in self.segments:
            if seg["fileoff"] <= fileoff < seg["fileoff"] + seg["filesize"]:
                for s in seg["sections"]:
                    if s["fileoff"] <= fileoff < s["fileoff"] + s["size"]:
                        return f"{seg['name']},{s['sect']}"
                return f"{seg['name']},-"
        return "?"

    def va_of(self, fileoff):
        for seg in self.segments:
            if seg["fileoff"] <= fileoff < seg["fileoff"] + seg["filesize"]:
                return seg["vmaddr"] + (fileoff - seg["fileoff"])
        return None


def slices(path):
    """Return parsed Slice objects (thin or fat container)."""
    with open(path, "rb") as f:
        head = f.read(4096)
    magic = struct.unpack_from("<I", head, 0)[0]
    out = []
    if magic == 0xFEEDFACF:  # thin 64
        out.append(Slice(path, "native", 0, _fsize(path)))
    elif head[:4] == b"\xca\xfe\xba\xbe":  # fat big-endian
        nfat = struct.unpack_from(">I", head, 4)[0]
        for i in range(nfat):
            cputype, cpusub, off, size, align = struct.unpack_from(
                ">iiIII", head, 8 + 20 * i)
            arch = CPU_NAMES.get(cputype, hex(cputype))
            # fat entry for arm64 sometimes recorded as cputype 12 (arm);
            # re-read the thin header to be sure
            sub = head[off + 4:off + 8]
            ct = struct.unpack_from("<I", sub, 0)[0] if len(sub) == 4 else 0
            with open(path, "rb") as f:
                f.seek(off)
                mh = f.read(8)
            if len(mh) == 8 and struct.unpack_from("<I", mh, 0)[0] == 0xFEEDFACF:
                ct = struct.unpack_from("<I", mh, 4)[0]
                arch = CPU_NAMES.get(ct, hex(ct))
            out.append(Slice(path, arch, off, size))
    else:
        raise ValueError(f"unsupported magic {magic:#x} in {path}")
    return [s.parse() for s in out]


def _fsize(path):
    import os
    return os.path.getsize(path)

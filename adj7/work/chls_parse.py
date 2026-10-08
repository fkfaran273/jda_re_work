# -*- coding: utf-8 -*-
"""chls_parse.py -- full Java-serialization parse of a Charles .chls session
(fixed parser: object-field type strings may be TC_REFERENCE backrefs;
TC_ENDBLOCKDATA surfaces as an EndBlock sentinel to custom-data loops).

    from chls_parse import parse_chls
    root, reader = parse_chls(path)
"""
import sys

TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_CLASS = 0x76
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78
TC_RESET = 0x79
TC_BLOCKDATALONG = 0x7A
TC_EXCEPTION = 0x7B
TC_LONGSTRING = 0x7C
TC_PROXYCLASSDESC = 0x7D
TC_ENUM = 0x7E

SC_WRITE_METHOD = 0x01
SC_BLOCK_DATA = 0x08
SC_SERIALIZABLE = 0x02


class EndBlock(Exception):
    pass


class R(object):
    def __init__(self, data):
        self.d = data
        self.i = 0
        self.handles = {}
        self.next_handle = 0x7E0000

    def u1(self):
        v = self.d[self.i]; self.i += 1; return v

    def u2(self):
        v = int.from_bytes(self.d[self.i:self.i+2], "big"); self.i += 2; return v

    def u4(self):
        v = int.from_bytes(self.d[self.i:self.i+4], "big"); self.i += 4; return v

    def u8(self):
        v = int.from_bytes(self.d[self.i:self.i+8], "big"); self.i += 8; return v

    def assign(self, obj):
        h = self.next_handle; self.next_handle += 1
        self.handles[h] = obj
        return h

    def raw_utf(self, n):
        s = self.d[self.i:self.i+n].decode("utf-8", "replace")
        self.i += n
        return s

    def read_content(self):
        t = self.u1()
        if t == TC_OBJECT:
            self.i -= 1
            return self.read_object()
        if t == TC_BLOCKDATA:
            ln = self.u1()
            b = self.d[self.i:self.i+ln]; self.i += ln
            return ("BLOCKDATA", b)
        if t == TC_BLOCKDATALONG:
            ln = self.u4()
            b = self.d[self.i:self.i+ln]; self.i += ln
            return ("BLOCKDATA", b)
        if t == TC_ENDBLOCKDATA:
            self.i -= 1
            return None
        raise ValueError("read_content: unexpected tag 0x%02x at %d" % (t, self.i-1))

    def read_object(self):
        t = self.u1()
        if t == TC_OBJECT:
            return self.read_newobject()
        if t == TC_STRING:
            ln = self.u2()
            s = self.raw_utf(ln)
            self.assign(s)
            return s
        if t == TC_LONGSTRING:
            ln = self.u8()
            s = self.raw_utf(ln)
            self.assign(s)
            return s
        if t == TC_ARRAY:
            return self.read_array()
        if t == TC_CLASSDESC or t == TC_PROXYCLASSDESC:
            self.i -= 1
            return self.read_classdesc()
        if t == TC_CLASS:
            cd = self.read_classdesc()
            self.assign(cd)
            return ("CLASS", cd)
        if t == TC_REFERENCE:
            h = self.u4()
            if h in self.handles:
                return self.handles[h]
            raise ValueError("dangling handle 0x%x at %d" % (h, self.i))
        if t == TC_NULL:
            return None
        if t == TC_ENUM:
            cd = self.read_classdesc()
            h = self.assign(("ENUM", cd, None))
            name = self.read_object()
            self.handles[h] = ("ENUM", cd, name)
            return self.handles[h]
        if t == TC_RESET:
            self.handles.clear(); self.next_handle = 0x7E0000
            return ("RESET",)
        if t == TC_BLOCKDATA or t == TC_BLOCKDATALONG:
            self.i -= 1
            return self.read_content()
        if t == TC_ENDBLOCKDATA:
            self.i -= 1
            raise EndBlock()
        if t == TC_EXCEPTION:
            raise ValueError("TC_EXCEPTION")
        raise ValueError("unknown tag 0x%02x at %d" % (t, self.i-1))

    def read_classdesc(self):
        t = self.u1()
        if t == TC_REFERENCE:
            h = self.u4()
            return self.handles[h]
        if t == TC_NULL:
            return None
        if t != TC_CLASSDESC and t != TC_PROXYCLASSDESC:
            raise ValueError("classdesc: tag 0x%02x at %d" % (t, self.i-1))
        h = None
        if t == TC_PROXYCLASSDESC:
            h = self.assign(None)
            n_ifaces = self.u4()
            ifaces = [self.raw_utf(self.u2()) for _ in range(n_ifaces)]
            cd = {"proxy": True, "ifaces": ifaces, "name": "(proxy)"}
            self.handles[h] = cd
            self.read_classannotation()
            cd["super"] = self.read_classdesc()
            return cd
        name = self.raw_utf(self.u2())
        suid = self.u8()
        h = self.assign(None)
        flags = self.u1()
        n_fields = self.u2()
        fields = []
        for _ in range(n_fields):
            tc = self.u1()
            fname = self.raw_utf(self.u2())
            if tc in b"BCDFIJSZ":
                fields.append((chr(tc), fname))
            else:  # 'L' or '[' -- the TYPE STRING may be a TC_REFERENCE backref
                cls = self.read_object()
                fields.append((chr(tc), fname, cls))
        self.handles[h] = None
        self.read_classannotation()
        super_cd = self.read_classdesc()
        cd = {"name": name, "suid": suid, "flags": flags, "fields": fields,
              "super": super_cd}
        self.handles[h] = cd
        return cd

    def read_classannotation(self):
        while True:
            t = self.u1()
            if t == TC_ENDBLOCKDATA:
                return
            if t == TC_BLOCKDATA:
                ln = self.u1(); self.i += ln
                continue
            if t == TC_BLOCKDATALONG:
                ln = self.u4(); self.i += ln
                continue
            self.i -= 1
            try:
                self.read_object()
            except EndBlock:
                return

    def read_array(self):
        cd = self.read_classdesc()
        h = self.assign(None)
        n = self.u4()
        cls = cd["name"] if isinstance(cd, dict) else ""
        prim = {"[B": ("B", 1), "[S": ("S", 2), "[I": ("I", 4),
                "[J": ("J", 8), "[Z": ("Z", 1), "[C": ("C", 2),
                "[F": ("F", 4), "[D": ("D", 8)}.get(cls)
        if prim:
            tc, w = prim
            out = [self.read_prim(tc) for _ in range(n)]
        else:
            out = []
            for _ in range(n):
                out.append(self.read_object())
        self.handles[h] = out
        return out

    def read_newobject(self):
        cd = self.read_classdesc()
        obj = {"__class__": cd["name"] if isinstance(cd, dict) else "?",
               "__fields__": {}}
        self.assign(obj)
        self.read_classdata(cd, obj)
        return obj

    def read_classdata(self, cd, obj):
        chain = []
        c = cd
        while c and isinstance(c, dict) and not c.get("proxy"):
            chain.append(c)
            c = c.get("super")
        for c in reversed(chain):
            fields = {}
            for f in c["fields"]:
                if f[0] in "BCDFIJSZ":
                    fields[f[1]] = self.read_prim(f[0])
                else:
                    fields[f[1]] = self.read_object()
            obj["__fields__"].update(fields)
            if c["flags"] & SC_WRITE_METHOD:
                blocks = []
                while True:
                    t = self.u1()
                    if t == TC_ENDBLOCKDATA:
                        break
                    if t == TC_BLOCKDATA:
                        ln = self.u1()
                        blocks.append(self.d[self.i:self.i+ln]); self.i += ln
                    elif t == TC_BLOCKDATALONG:
                        ln = self.u4()
                        blocks.append(self.d[self.i:self.i+ln]); self.i += ln
                    else:
                        self.i -= 1
                        try:
                            blocks.append(self.read_object())
                        except EndBlock:
                            break
                if blocks:
                    obj["__fields__"]["__custom__"] = blocks

    def read_prim(self, tc):
        if tc == "B": v = self.d[self.i]; self.i += 1; return v
        if tc == "C":
            v = self.d[self.i:self.i+2].decode("utf-16-be"); self.i += 2; return v
        if tc == "D":
            import struct
            v = struct.unpack(">d", self.d[self.i:self.i+8])[0]; self.i += 8; return v
        if tc == "F":
            import struct
            v = struct.unpack(">f", self.d[self.i:self.i+4])[0]; self.i += 4; return v
        if tc == "I":
            v = int.from_bytes(self.d[self.i:self.i+4], "big", signed=True); self.i += 4; return v
        if tc == "J":
            v = int.from_bytes(self.d[self.i:self.i+8], "big", signed=True); self.i += 8; return v
        if tc == "S":
            v = int.from_bytes(self.d[self.i:self.i+2], "big", signed=True); self.i += 2; return v
        if tc == "Z":
            v = self.d[self.i]; self.i += 1; return bool(v)
        raise ValueError("prim %r" % tc)


def parse_chls(path):
    """A .chls stream holds MANY top-level objects (the Session summary, then
    one object per transaction record).  Read them all, in stream order."""
    data = open(path, "rb").read()
    assert data[:4] == b"\xac\xed\x00\x05", data[:4].hex()
    r = R(data)
    r.i = 4
    objs = []
    while r.i < len(data):
        # skip any stray zero padding between top-level objects
        while r.i < len(data) and data[r.i] == 0x00:
            r.i += 1
        if r.i >= len(data):
            break
        try:
            objs.append(r.read_object())
        except EndBlock:
            continue
    return objs, r


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Apps\Downloads\payrupi.chls"
    objs, r = parse_chls(path)
    print("parsed %d top-level objects, consumed %d of %d bytes"
          % (len(objs), r.i, len(open(path, "rb").read())))
    seen = {}

    def walk(v):
        if isinstance(v, dict):
            cn = v.get("__class__")
            if cn:
                seen.setdefault(cn, []).append(v)
            for k, x in v.items():
                if k != "__class__":
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    for o in objs:
        walk(o)
    for cn, objs2 in sorted(seen.items()):
        print("  %-64s x%d" % (cn, len(objs2)))

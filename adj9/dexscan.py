"""Minimal DEX parser: list classes + method signatures matching a filter."""
import struct
import sys


class Dex:
    def __init__(self, path):
        self.buf = open(path, "rb").read()
        b = self.buf
        assert b[:4] == b"dex\n", "not a dex"
        (self.str_size, self.str_off) = struct.unpack_from("<II", b, 56)
        (self.type_size, self.type_off) = struct.unpack_from("<II", b, 64)
        (self.proto_size, self.proto_off) = struct.unpack_from("<II", b, 72)
        (self.method_size, self.method_off) = struct.unpack_from("<II", b, 88)
        (self.class_size, self.class_off) = struct.unpack_from("<II", b, 96)
        self._str_cache = {}

    # --- uleb128 ---
    def uleb(self, off):
        b = self.buf
        result = 0
        shift = 0
        while True:
            cur = b[off]
            off += 1
            result |= (cur & 0x7F) << shift
            if cur & 0x80 == 0:
                break
            shift += 7
        return result, off

    def string(self, idx):
        if idx in self._str_cache:
            return self._str_cache[idx]
        off = struct.unpack_from("<I", self.buf, self.str_off + idx * 4)[0]
        _, off = self.uleb(off)  # utf16 length
        end = self.buf.index(b"\x00", off)
        s = self.buf[off:end].decode("utf-8", "replace")
        self._str_cache[idx] = s
        return s

    def type_name(self, idx):
        return self.string(struct.unpack_from("<I", self.buf, self.type_off + idx * 4)[0])

    def proto(self, idx):
        base = self.proto_off + idx * 12
        _shorty, ret, params_off = struct.unpack_from("<III", self.buf, base)
        ret_name = self.type_name(ret)
        params = []
        if params_off:
            size = struct.unpack_from("<I", self.buf, params_off)[0]
            for i in range(size):
                t = struct.unpack_from("<H", self.buf, params_off + 4 + i * 2)[0]
                params.append(self.type_name(t))
        return ret_name, params

    def method(self, idx):
        base = self.method_off + idx * 8
        cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.buf, base)
        return self.type_name(cls_idx), self.string(name_idx), self.proto(proto_idx)

    def classes(self):
        for i in range(self.class_size):
            base = self.class_off + i * 32
            cls_idx = struct.unpack_from("<I", self.buf, base)[0]
            data_off = struct.unpack_from("<I", self.buf, base + 24)[0]
            yield self.type_name(cls_idx), data_off

    def class_methods(self, data_off):
        out = []
        if not data_off:
            return out
        off = data_off
        n_static, off = self.uleb(off)
        n_inst, off = self.uleb(off)
        n_direct, off = self.uleb(off)
        n_virtual, off = self.uleb(off)
        prev = 0
        for _ in range(n_static + n_inst):
            _, off = self.uleb(off)
            _, off = self.uleb(off)
        for kind, count in (("direct", n_direct), ("virtual", n_virtual)):
            prev = 0
            for _ in range(count):
                diff, off = self.uleb(off)
                _flags, off = self.uleb(off)
                _code, off = self.uleb(off)
                prev += diff
                out.append((kind, prev))
        return out


def desc(ret, params):
    return "(" + "".join(params) + ")" + ret


def main():
    path = sys.argv[1]
    filt = sys.argv[2] if len(sys.argv) > 2 else "adjust/sdk/sig"
    d = Dex(path)
    print(f"# {path}: classes={d.class_size} methods={d.method_size}")
    for cls, data_off in d.classes():
        if filt not in cls:
            continue
        print(f"\nclass {cls}")
        if not data_off:
            print("   (no class_data)")
            continue
        for kind, midx in d.class_methods(data_off):
            owner, name, (ret, params) = d.method(midx)
            print(f"   {kind:8s} {name}{desc(ret, params)}")


if __name__ == "__main__":
    main()

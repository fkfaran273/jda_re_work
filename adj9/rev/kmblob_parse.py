# kmblob_parse.py - decode the "pKMblob" CBOR envelope to expose IV/ciphertext/tag
import struct

BLOB_HEX = ('704b4d626c6f6200851a4b4d4b441b00000004000000041b5f27857d9eec5f58'
            '5872a201ac1a2000000181021a1000000218801a300000031901001a20000005'
            '81041a300000081901001a1000012d001a700001f7f51a100002be001a300002c1'
            '1a0001d4c01a300002c21a000315dd1a300002ce1a01348a551a300002cf1a0134'
            '8a5500a11a600002bd1b000001a038c16ea0844050b5723ba163b49ca6ae07bc4f'
            '841ca8fa58204f8c854670fd3d54b346cb9b4da4400952815f4869bd5fcbf1c49e'
            '576834426450e43d722687b4a84f81145e8bd40cdfbb')

data = bytes.fromhex(BLOB_HEX)


class R:
    def __init__(self, b, o=0):
        self.b, self.o = b, o

    def u8(self):
        v = self.b[self.o]; self.o += 1; return v

    def take(self, n):
        v = self.b[self.o:self.o + n]; self.o += n; return v

    def item(self, depth=0):
        ib = self.u8()
        mt, ai = ib >> 5, ib & 0x1f
        if ai < 24:
            v = ai
        elif ai == 24:
            v = self.u8()
        elif ai == 25:
            v = struct.unpack('>H', self.take(2))[0]
        elif ai == 26:
            v = struct.unpack('>I', self.take(4))[0]
        elif ai == 27:
            v = struct.unpack('>Q', self.take(8))[0]
        else:
            v = None
        if mt == 0:
            return ('uint', v)
        if mt == 1:
            return ('nint', -1 - v)
        if mt == 2:
            return ('bstr', self.take(v))
        if mt == 3:
            return ('tstr', self.take(v))
        if mt == 4:
            return ('array', [self.item(depth + 1) for _ in range(v)])
        if mt == 5:
            return ('map', [(self.item(depth + 1), self.item(depth + 1))
                            for _ in range(v)])
        if mt == 7:
            return ('simple', v)
        return ('mt%d' % mt, v)


r = R(data)
assert data[:8] == b'pKMblob\0'
r.o = 8
outer = r.item()
print('magic:', data[:8])
print('consumed: %d / %d bytes' % (r.o, len(data)))
print()


def show(x, ind=0):
    t, v = x
    p = ' ' * ind
    if t == 'bstr':
        print('%s bstr(%d) %s' % (p, len(v), v.hex()))
    elif t == 'tstr':
        print('%s tstr(%d) %r' % (p, len(v), v))
    elif t == 'array':
        print('%s array(%d)' % (p, len(v)))
        for e in v:
            show(e, ind + 2)
    elif t == 'map':
        print('%s map(%d)' % (p, len(v)))
        for k, val in v:
            show(k, ind + 2)
            show(val, ind + 4)
    else:
        print('%s %s %s' % (p, t, hex(v) if isinstance(v, int) and v is not None else v))


show(outer)
print()
print('trailing bytes:', data[r.o:].hex())

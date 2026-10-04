#!/usr/bin/env python3
"""dex_strings.py - parse the string_ids pool of every classes*.dex in a dir.

Usage: python dex_strings.py <dex_dir> <out_txt>
Writes one string per line (NUL/CR/LF replaced, since the pool can hold them).
"""
import os
import struct
import sys


def read_uleb128(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def dex_strings(path):
    data = open(path, 'rb').read()
    if data[:4] not in (b'dex\n', b'dex\r'):
        raise ValueError('not a dex: %s' % path)
    # header: string_ids_size @0x38, string_ids_off @0x3C
    n_strings, sids_off = struct.unpack_from('<II', data, 0x38)
    out = []
    for i in range(n_strings):
        (data_off,) = struct.unpack_from('<I', data, sids_off + 4 * i)
        # string_data_item: uleb128 utf16_size, then MUTF-8 bytes, NUL-terminated
        _utf16_len, p = read_uleb128(data, data_off)
        end = data.index(b'\x00', p)
        raw = data[p:end]
        # MUTF-8 is close enough to UTF-8 for identifier hunting; use
        # surrogatepass to survive embedded NULs / lone surrogates.
        try:
            s = raw.decode('utf-8', 'surrogatepass')
        except Exception:
            s = raw.decode('latin1')
        out.append(s.replace('\x00', '\\0').replace('\r', '\\r')
                    .replace('\n', '\\n'))
    return out


def main():
    dex_dir, out_path = sys.argv[1], sys.argv[2]
    seen = []
    for name in sorted(os.listdir(dex_dir)):
        if not name.endswith('.dex'):
            continue
        strs = dex_strings(os.path.join(dex_dir, name))
        seen.extend(strs)
        print('%s/%s: %d strings' % (dex_dir, name, len(strs)))
    with open(out_path, 'w', encoding='utf-8', errors='surrogatepass') as f:
        for s in seen:
            f.write(s + '\n')
    print('total %d -> %s' % (len(seen), out_path))


if __name__ == '__main__':
    main()

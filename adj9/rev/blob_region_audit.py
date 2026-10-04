"""Decode every REAL device signature and test whether its region is a pure
function of d2.

If d0 (#0) and d4 (#4) are fully determined by d2 (#2) across all real device
blobs, then the envelope carries NO hidden hardware-bound component: a Python
reimplementation that reproduces d2 can reproduce d0/d4 too, and therefore the
whole 192-byte envelope. That would mean the signature is NOT the gate.

Region law (F.py):  seed = d2 (little-endian store, read big-endian)
                    d4 = _d4_words(seed);  d0 = _d0_words(d4)
"""
import base64
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

# import the law directly
F = None
for cand in (os.path.join(HERE, "F.py"),):
    if os.path.exists(cand):
        import importlib.util
        spec = importlib.util.spec_from_file_location("F", cand)
        F = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(F)
        break
if F is None:
    from rev.F import F  # type: ignore

# descriptor layout after the 16-byte header, in VA_ORDER
LAYOUT = [(0, 36), (9, 5), (8, 4), (4, 8), (2, 1), (7, 1),
          (10, None), (5, 1), (1, 0), (6, 1), (3, 0)]


def parse_body(blob):
    """Return dict desc# -> list of big-endian dwords (desc10 left as raw)."""
    body = blob[16:]
    off = 0
    out = {}
    for idx, n in LAYOUT:
        if idx == 10:
            # desc10 is variable; its padded length comes from desc#7.
            if 7 not in out or not out[7]:
                return None
            n10 = out[7][0]                       # unpadded byte length
            padded = (n10 + 3) // 4 * 4
            out[10] = body[off:off + padded]
            off += padded
            continue
        cnt = n * 4
        chunk = body[off:off + cnt]
        if len(chunk) < cnt:
            return None
        off += cnt
        out[idx] = [int.from_bytes(chunk[i:i + 4], "big")
                    for i in range(0, len(chunk), 4)]
    return out


def main():
    pat = re.compile(r'signature="([A-Za-z0-9+/=]{100,})"')
    b64s = set()
    for f in glob.glob(os.path.join(HERE, "..", "device", "*.log")):
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = pat.search(line)
                if m:
                    b64s.add(m.group(1))
    b64s = sorted(b64s)
    print("real device signatures found:", len(b64s))

    checked = 0
    d2_ok = d4_ok = d0_ok = 0
    bad = []
    for b in b64s:
        try:
            blob = base64.b64decode(b)
        except Exception:
            continue
        if len(blob) != 192:
            continue
        d = parse_body(blob)
        if d is None or 7 not in d or not d[7] or 2 not in d:
            continue
        d2 = d[2][0]
        d4 = d[4]
        d0 = d[0]
        seed = int.from_bytes(d2.to_bytes(4, "big"), "little")
        e4 = F._d4_words(seed)
        e0 = F._d0_words(e4)
        checked += 1
        ok4 = (e4 == d4)
        ok0 = (e0[:36] == d0)
        d4_ok += ok4
        d0_ok += ok0
        if not (ok4 and ok0):
            bad.append((b[:16], hex(d2), ok4, ok0))

    print("parsed & checked      :", checked)
    print("d4 == _d4_words(d2)   : %d/%d" % (d4_ok, checked))
    print("d0 == _d0_words(d4)   : %d/%d" % (d0_ok, checked))
    if bad:
        print("MISMATCHES (first 5):")
        for x in bad[:5]:
            print("  ", x)
    verdict = (checked and d4_ok == checked and d0_ok == checked)
    print("\nREGION IS PURE FUNCTION OF d2:", verdict)
    print("=> envelope fully reproducible in Python; NO hidden TEE component"
          if verdict else "=> region NOT reproducible from d2; hidden component present")


if __name__ == "__main__":
    main()

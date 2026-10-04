"""find23.py - locate the true blobs for pair rows 2 and 3.

Log format (adj9_wh*.log): ###ADJ9_BEGIN type=... ts=... records.
  type=authorization_header carries the full header incl. signature="<b64,256 chars>"
  type=nsign / nsign_in carry hex payloads (the 192-B blob as 384 hex).

Plan: harvest (ts, blob_hex) from authorization_header (b64 -> hex) and nsign records,
then for rows 2/3 invert each blob's header to its true second and FinEx-match by body.
"""
import base64
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def row_descs(row):
    z36 = list(struct.unpack(">36I", bytes.fromhex(row["d0"])))
    z8 = list(struct.unpack(">8I", bytes.fromhex(row["d4"])))
    d2v = int(row["d2"], 16)
    d7v = int(row["d7"], 16)
    raw10 = bytes.fromhex(row["d10"])
    n10 = len(raw10) // 4
    z10 = list(struct.unpack(">%dI" % n10, raw10))
    by = {0: (36, b(z36)), 9: (5, bytes.fromhex(row["d9"])), 8: (4, bytes.fromhex(row["d8"])),
          4: (8, b(z8)), 2: (1, b([d2v])), 7: (1, b([d7v])),
          10: (n10, b(z10)), 5: (1, b"\x00" * 4), 6: (1, b"\x00" * 4),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]


def finex_blob(descs, sec):
    ex = FinEx(sec, descs)
    ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(sec))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    if stream is None:
        return None
    return b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))


LOGS = [r"C:\Users\Apps\Downloads\com.penti.app\adj9\device\adj9_wh.log",
        r"C:\Users\Apps\Downloads\com.penti.app\adj9\device\adj9_wh2.log",
        r"C:\Users\Apps\Downloads\com.penti.app\adj9\device\adj9_wh4.log"]

blobs = {}  # hex384 -> [ts,...]
rec_re = re.compile(r"###ADJ9_BEGIN type=(\S+) [^\n]*ts=(\d+)\n(.*?)###ADJ9_END", re.S)
sig_re = re.compile(r'signature="([A-Za-z0-9+/]{256})"')
hex384_re = re.compile(r"hex=([0-9a-f]{384})")

for lf in LOGS:
    if not os.path.exists(lf) or os.path.getsize(lf) == 0:
        continue
    with open(lf, encoding="utf-8", errors="replace") as f:
        txt = f.read()
    n = 0
    for m in rec_re.finditer(txt):
        typ, ts, body = m.group(1), int(m.group(2)), m.group(3)
        if typ == "authorization_header":
            sm = sig_re.search(body)
            if sm:
                hx = base64.b64decode(sm.group(1)).hex()
                blobs.setdefault(hx, []).append(ts)
                n += 1
        elif typ in ("nsign", "nsign_out"):
            hm = hex384_re.search(body)
            if hm:
                blobs.setdefault(hm.group(1), []).append(ts)
                n += 1
    print(os.path.basename(lf), "->", n, "blob records (total distinct:", len(blobs), ")", flush=True)

json.dump({hx: ts for hx, ts in blobs.items()},
          open(os.path.join(HERE, "blob_pool.json"), "w"), indent=0)
print("saved blob_pool.json with", len(blobs), "blobs")

# rows 2/3 descriptors
rows = {r["d2"]: r for r in A}
r2 = [r for r in A if r["d2"] == "31409094"][0]
r3 = [r for r in A if r["d2"] == "6b157640"][0]

# cheap pre-filter: compute each blob's true second once; keep blobs whose body
# could be rows 2/3 (we can't tell without FinEx, so invert all, then FinEx the
# closest-by-second ones first).
print("inverting headers ...", flush=True)
inv = {}  # hex -> second
for i, (hx, tss) in enumerate(blobs.items()):
    want = bytes.fromhex(hx[:32])
    base = (tss[0] // 1000) if tss else 0
    found = None
    for delta in range(0, 4):
        for sec in ((base + delta, base - delta) if delta else (base,)):
            if make_header(sec) == want:
                found = sec
                break
        if found:
            break
    inv[hx] = found
    if i % 50 == 0:
        print("  inv", i, "/", len(blobs), flush=True)
print("inverted:", sum(1 for v in inv.values() if v), "/", len(blobs), flush=True)

# try rows 2/3 against every inverted blob, nearest-second first
for label, row in (("row2", r2), ("row3", r3)):
    descs = row_descs(row)
    cands = sorted(((hx, s) for hx, s in inv.items() if s),
                   key=lambda x: abs(x[1] - (1789240075 if label == "row2" else 1789240076)))
    print(label, "d2=%s candidates=%d" % (row["d2"], len(cands)), flush=True)
    hit = None
    for j, (hx, sec) in enumerate(cands[:12]):
        got = finex_blob(descs, sec)
        ok = got is not None and got.hex() == hx
        print("  [%d] sec=%d blob=%s... %s" % (j, sec, hx[:16], "BYTE-EXACT" if ok else "no"), flush=True)
        if ok:
            hit = (hx, sec)
            break
    print(label, "=> ", hit if hit else "NO MATCH in top candidates", flush=True)


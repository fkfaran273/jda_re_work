"""fit_table.py - build the labelled (V, pid, tid) -> (d0, d2, d4) table for
the F fit.  Sources: rev/fill_runs/*.json (era-1 and era-2) and the small
rev/fit_runs/*.json dumps produced by fit_gen.py.

Key structure discovered while mining (see F_FIT_FINDINGS.md):
  * #0 = 36 BE words.  Words 6..35 are a 4-word TILE repeated; words 0..5 are
    a head (W0, X, 4 head words).  Era-1 emits ONE EXTRA 16-bit unit inside the
    head (shifting everything after it by one unit); d2, d4 and the tile cycle
    are byte-identical across eras.
  * L1: C0^C2 == C1^C3 == R||R (16-bit replication), R = (C0^C2)&0xffff.
  * L2: d4[6]>>16 == R.
  * d2 = (hi16 << 16) | LO where LO is a per-process constant (0x9b5a here)
    and hi16 is a small fold of V (and pid/tid).
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FILL = os.path.join(HERE, "fill_runs")
FIT = os.path.join(HERE, "fit_runs")


def emu_V(cfg):
    us = cfg.get("usec", 500000) + 4000
    sec = cfg.get("sec", 1789240512) + us // 1000000
    return sec ^ (us % 1000000)


def _parse(descs):
    by = {e["build_idx"]: e for e in descs[0]}
    if 0 not in by or by[0].get("nbytes") != 144:
        return None
    d0 = bytes.fromhex(by[0]["hex"])
    d2 = bytes.fromhex(by[2]["hex"]) if by.get(2, {}).get("nbytes") == 4 else None
    d4 = bytes.fromhex(by[4]["hex"]) if by.get(4, {}).get("nbytes") == 32 else None
    if d2 is None or d4 is None:
        return None
    return d0, d2, d4


def words(b):
    return list(struct.unpack(">%dI" % (len(b) // 4), b))


def units(b):
    return [(b[i] << 8) | b[i + 1] for i in range(0, len(b), 2)]


def tile_R(d0):
    """Return (phase_word_index, cycle4, R) using the last 30 words."""
    w = words(d0)
    for s in range(6, 10):
        C = w[s:s + 4]
        if len(C) == 4 and all(w[i] == C[(i - s) % 4] for i in range(s, 36)):
            x = C[0] ^ C[2]
            if (x >> 16) == (x & 0xFFFF) and (C[1] ^ C[3]) == x:
                return s, C, x & 0xFFFF
    return None, None, None


def load_all():
    """returns list of dicts: tag, src, V, pid, tid, d0, d2, d4, era"""
    rows = []
    for src, directory in (("fill_runs", FILL), ("fit_runs", FIT)):
        if not os.path.isdir(directory):
            continue
        for fn in sorted(os.listdir(directory)):
            if not fn.endswith(".json"):
                continue
            tag = fn[:-5]
            if tag in ("body_map", "emit_trace", "env_val") or tag.startswith("lift"):
                continue          # no region / gated / lift instrumentation
            try:
                d = json.load(open(os.path.join(directory, fn)))
            except Exception:
                continue
            cfg = d.get("cfg", {})
            if "descs" in d and d.get("descs"):
                p = _parse(d["descs"])
            elif "d0" in d and d.get("d0"):
                p = (bytes.fromhex(d["d0"]), bytes.fromhex(d["d2"]),
                     bytes.fromhex(d["d4"]))
            else:
                continue
            if not p:
                continue
            d0, d2, d4 = p
            V = d.get("V") if "V" in d else emu_V(cfg)
            pid = d.get("pid", cfg.get("pid", 12345))
            tid = d.get("tid", cfg.get("tid", 12346))
            s, C, R = tile_R(d0)
            w0 = words(d0)
            era = 1 if w0[1] == 0x879D6E77 else 2
            rows.append(dict(tag=tag, src=src, V=V, pid=pid, tid=tid,
                             d0=d0, d2=d2, d4=d4, w0=w0, era=era,
                             phase=s, cycle=C, R=R, d2w=words(d2)[0],
                             d4w=words(d4)))
    return rows


def dedup(rows):
    """collapse byte-identical region rows (inert-input battery)"""
    seen, out = {}, []
    for r in rows:
        k = (r["V"], r["pid"], r["tid"], r["d0"], r["d2"], r["d4"])
        if k in seen:
            seen[k]["also"].append(r["tag"])
            continue
        r["also"] = [r["tag"]]
        seen[k] = r
        out.append(r)
    return out


def canonical_stream(r):
    """16-bit unit stream of the region; era-1 has one extra head unit which we
    drop by matching against the tile phase (the cycle is unique enough)."""
    u = units(r["d0"]) + units(r["d2"]) + units(r["d4"])
    if r["era"] == 2:
        return u
    # era-1: find the insertion offset k in 0..9 such that dropping u[k]
    # yields a stream whose first 8-unit tile aligns with the era-2 convention
    # (tile starts at unit 12 of d0 for era-2)
    for k in range(0, 10):
        v = u[:k] + u[k + 1:]
        if v[2:12] == u[3:13] or True:
            pass
    # structural: tile cycle in era-1 d0 starts at word 6 -> unit 12 too,
    # but one unit earlier content.  Find k by requiring the 8-unit cycle to
    # equal the cycle found at unit 12 offset.
    C = r["cycle"]
    if C is None:
        return u
    cu = units(struct.pack(">4I", *C))  # 8 units
    hits = [i for i in range(0, 24) if u[i:i + 8] == cu]
    if not hits:
        return u
    # the first hit is the tile start; the stream is canonical iff tile starts
    # at unit 12 (era-2 convention)
    if hits[0] == 12:
        return u          # already canonical
    k = 12 - hits[0]
    if 0 <= k < len(u):
        return u[:k] + u[k + 1:]
    return u


if __name__ == "__main__":
    rows = dedup(load_all())
    print("raw rows: %d, unique: %d" % (len(load_all()), len(rows)))
    print("%-16s %5s %-6s %-10s %-7s %-6s %-6s %-6s %s" %
          ("tag", "era", "src", "V", "pid/tid", "R", "d2", "W0", "also"))
    for r in sorted(rows, key=lambda r: (r["era"], r["V"], r["pid"], r["tid"])):
        print("%-16s %5d %-6s %08x  %5d/%-5d %04x  %08x %08x %s" %
              (r["tag"], r["era"], r["src"][:4], r["V"], r["pid"], r["tid"],
               r["R"] or 0, r["d2w"], r["w0"][0], ",".join(r["also"][1:])))
    vs = sorted(set((r["V"], r["pid"], r["tid"]) for r in rows))
    print("\ndistinct (V,pid,tid): %d" % len(vs))
    print("distinct V: %d ; era1 %d ; era2 %d" %
          (len(set(r["V"] for r in rows)),
           len(set(r["V"] for r in rows if r["era"] == 1)),
           len(set(r["V"] for r in rows if r["era"] == 2))))

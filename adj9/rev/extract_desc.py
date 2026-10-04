#!/usr/bin/env python3
"""extract_desc.py — reconstruct the 11 VM field descriptors of an adj9 signing.

Two independent reconstruction paths:

PATH A (records-based; WORKS for the aligned session pid 12438):
  device/vm_full.json holds live frida captures (vmhook.js):
    hook 0x100094 "vm"        -> one record per VM(0x100094) call
    hook 0x100114 "fieldloop" -> 12 hits per VM call = field-loop head
                                 0x100114 `cmp x23, x26`, i = 0..11.
  At loop-head hit i the captured registers show:
    x2 = last value written to w2 = previous desc's LAST emit index (or the
         original arg2 = 0xb = desc count for i = 0)
    x3 = last emit value (rev32/BE view) for i >= 1; desc-pass[0] node ptr
         for i = 0 (arg3 untouched by prologue)
    x1 = [ctx + 0x20 + (i-1)*8] = sink stream of the previous desc
  Therefore record k (k = 1..11) yields desc pass[k-1]'s (last j, last value)
  -> length (j+1 for tag-0 inner, or L with tail per #7's w0) and its last
  dword.  Descriptors that emit nothing (empty descs) leave the previous
  (x2, x3) unchanged (carry-over) — the two duplicated records identify them.

PATH B (memory-based; for any dump that contains the live master struct):
  master struct layout (slices 23/26/27, x19 = stamp 0x12cb74's x2 arg):
    +0x20  u32   -> desc build#2 (4 B)
    +0x30  32 B  -> desc build#4 = H (TEE-HMAC, arg3)
    +0x50  144 B -> desc build#0 = core record (36 dw)
    +0x100 20 B  -> desc build#9 = SHA-1(cert DER) = fad0f10d...74bd
    +0x128 u32   -> byte-length of the packed claim string (= desc build#7's
                    value AND desc build#10's w0 = (L<<2)|tag)
    +0x130 ptr   -> desc build#10 data (the packed fetch-claim strings)
  Anchor scan: the cert SHA-1 is session-INDEPENDENT -> find it raw, require
  it to sit at cand+0x100 and validate cand+0x128/+0x130; H (session-bound)
  then sits at cand+0x30.  All pointers are MTE-masked to 0x0000FFFFFFFFFFFF.

Run:  python extract_desc.py            # full report + descriptors JSON
Outputs rev/descriptors_aligned.json.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.normpath(os.path.join(HERE, "..", "device"))

CERT_SHA1 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
MTE_MASK = 0x0000FFFFFFFFFFFF

# pass order (va_list order) = build order of the stamp's 11 mkdesc sites,
# recovered from the records; see OPS_LIFT.md §2.
PASS_TO_BUILD = [0, 9, 8, 4, 2, 7, 10, 5, 6, 1, 3]
STATIC_LEN = {0: 36, 1: 0, 2: 1, 3: 0, 4: 8, 5: 1, 6: 1, 7: 1, 8: 4, 9: 5}


def rev32(x):
    return int.from_bytes(int(x & 0xFFFFFFFF).to_bytes(4, "little"), "little")


def be_view(raw):
    """dword list as the field loop emits them (BE view of the bytes)."""
    pad = raw + b"\x00" * ((-len(raw)) % 4)
    return [int.from_bytes(pad[i:i + 4], "big") for i in range(0, len(pad), 4)]


# ---------------------------------------------------------------- PATH A ----
def parse_vm_full(path=None):
    path = path or os.path.join(DEV, "vm_full.json")
    recs = json.load(open(path))
    out = {"vm": [], "fieldloop": [], "workhorse": []}
    for r in recs:
        if "tag" in r:
            out[r["tag"]].append(r)
    return out


def mask(v):
    v = int(v, 0) if isinstance(v, str) else v
    return v & MTE_MASK


def rounds_from_records(recs):
    """Group fieldloop records into VM rounds; pair each with its vm record."""
    rounds, cur = [], None
    for r in recs:
        n = r["n"]
        if cur is None or n != cur["last"] + 1:
            cur = {"entry": None, "hits": [], "last": n}
            rounds.append(cur)
        if r["x2"] == "0xb" and not cur["hits"]:
            cur["entry"] = r
        else:
            cur["hits"].append(r)
        cur["last"] = n
    return [r for r in rounds if r["entry"] and len(r["hits"]) >= 10]


def desc10_w0(last_j, last_v):
    """Given #10's last emit, decide (L, tag)."""
    # tag 0: last inner emit j = L-1, value = any dword
    # tag t>0: tail emit index j = L (w21), value = tail pack (bytes << (8*(3-t)))
    for tag in (0, 1, 2, 3):
        if tag == 0:
            L = last_j + 1
        else:
            if tag == 1 and last_v & 0x00FFFFFF:
                continue
            if tag == 2 and last_v & 0x00FFFF:
                continue
            L = last_j
        w0 = (L << 2) | tag
        if w0 == last_j and tag == 0:  # degenerate, not our case
            continue
        yield L, tag, w0


def reconstruct_round(entry, hits, verbose=True):
    """Rebuild the 11 descriptors of one VM round from its 12 records."""
    assert int(entry["x2"], 0) == 0xB
    d = {}
    d["ctx"] = mask(entry["x1"])          # x20 = CTX (sink slots at +0x20)
    d["writer"] = mask(entry["x0"])       # x19
    d["node_pass0"] = mask(entry["x3"])   # desc pass[0] node ptr
    d["node_pass1"] = mask(entry["x4"])   # desc pass[1] node ptr
    descs = []
    # record k (hits[k-1]) shows the last emit of the most recent EMITTING
    # desc among pass[0..k-1].  The pass order ends with the two EMPTY descs
    # (build #1, #3 — no emits), so hits 10 and 11 (i = 10, 11) are guaranteed
    # carry-over records: their (x2,x3) repeat the 9th emit and their x1 is
    # the empty descs' (dummy) ctx slot.  The first 9 hits are the 9 emitting
    # descriptors in pass order.
    assert len(hits) >= 10
    for k in range(1, 10):               # hits for loop-head i = 1..9
        r = hits[k - 1]
        j = int(r["x2"], 0) & 0xFFFFFFFF
        v = int(r["x3"], 0) & 0xFFFFFFFF
        sink = mask(r["x1"])
        descs.append({"kind": "emit", "last_j": j, "last_v": v, "sink": sink})
    for k in (10, 11):                   # empty desc hits (carry-over)
        r = hits[k - 1]
        descs.append({"kind": "empty", "sink": mask(r["x1"]),
                      "carry_j": int(r["x2"], 0) & 0xFFFFFFFF,
                      "carry_v": int(r["x3"], 0) & 0xFFFFFFFF})
    # carry-over sanity: the two trailing records must repeat the last emit
    assert all(x["carry_j"] == descs[8]["last_j"] and
               x["carry_v"] == descs[8]["last_v"] for x in descs[9:]), \
        "trailing records are not carry-over of the last emit"
    d["hits"] = descs
    out = []
    emit_descs = [x for x in descs if x["kind"] == "emit"]
    assert len(emit_descs) == 9, "expected 9 emitting descriptors"
    (e0, e9, e8, e4, e2, e7, e10, e5, e6) = emit_descs
    # #10: length word must equal #7's emitted value
    cand = list(desc10_w0(e10["last_j"], e10["last_v"]))
    ok = [c for c in cand if c[2] == e7["last_v"]]
    assert len(ok) == 1, ("desc10 w0 mismatch", cand, hex(e7["last_v"]))
    L10, tag10, w010 = ok[0]

    def be_bytes(v, n=4):
        """bytes the loop must hold so rev32(LE) == v (the loop emits the BE
        view of its data; scalar descs are stored pre-reversed by the stamp)."""
        return v.to_bytes(n, "big")

    def mk(bidx, L, tag, last_j, last_v, sink, note, data_hex=None,
           unknown=None):
        return {"build_idx": bidx, "len_dw": L, "tag": tag,
                "w0": (L << 2) | tag, "last_j": last_j, "last_v": last_v,
                "sink": sink, "note": note,
                "data_hex": data_hex,
                "unknown_dwords": unknown}

    out.append(mk(0, 36, 0, e0["last_j"], e0["last_v"], e0["sink"],
                  "core record, 144 B @struct+0x50; only dword35 live-known",
                  unknown=list(range(36))))
    out.append(mk(9, 5, 0, e9["last_j"], e9["last_v"], e9["sink"],
                  "SHA-1(cert DER) — constant, byte-verified",
                  data_hex=CERT_SHA1.hex()))
    out.append(mk(8, 4, 0, e8["last_j"], e8["last_v"], e8["sink"],
                  "16 B; dword3 = 0 (NOT the digest prefix — refutes the "
                  "slice-26 same-base reading); dwords 0-2 unknown",
                  data_hex=None, unknown=[0, 1, 2]))
    out.append(mk(4, 8, 0, e4["last_j"], e4["last_v"], e4["sink"],
                  "H = TEE-HMAC (arg3), 32 B; dword7 = BE of H bytes[28:32]; "
                  "H itself not present in any aligned-session dump",
                  data_hex=None, unknown=list(range(8))))
    out.append(mk(2, 1, 0, e2["last_j"], e2["last_v"], e2["sink"],
                  "u32 @struct+0x20 (per-signing value)",
                  data_hex=be_bytes(e2["last_v"]).hex()))
    out.append(mk(7, 1, 0, e7["last_j"], e7["last_v"], e7["sink"],
                  "u32 @struct+0x128 = byte-len of #10 = raw w0 word of #10",
                  data_hex=be_bytes(e7["last_v"]).hex()))
    out.append(mk(10, L10, tag10, e10["last_j"], e10["last_v"], e10["sink"],
                  "packed fetch-claim strings @struct+0x130 "
                  "(len u32 @struct+0x128 = %d B); content = BE view of the "
                  "pack; workhorse loop re-fetches the same claims "
                  "(90 fetches, hardcoded order)" % ((L10 << 2) + tag10),
                  data_hex=None, unknown=list(range(L10))))
    out.append(mk(5, 1, 0, e5["last_j"], e5["last_v"], e5["sink"],
                  "proven constant 0 (slice 27)",
                  data_hex=be_bytes(0).hex()))
    out.append(mk(6, 1, 0, e6["last_j"], e6["last_v"], e6["sink"],
                  "proven constant 0 (slice 27)",
                  data_hex=be_bytes(0).hex()))
    # the two empty descs are build #1 and #3 (pass order of the pair is not
    # observable — both are {0, NULL} and share the dummy sink)
    for k, x in enumerate(descs):
        if x["kind"] == "empty":
            out.append(mk(1 if k == len(descs) - 2 else 3, 0, 0,
                          None, None, x["sink"],
                          "empty {0, NULL} (proven slice 27); "
                          "order of the pair unobservable", data_hex=""))
    out.sort(key=lambda x: PASS_TO_BUILD.index(x["build_idx"])
             if x["build_idx"] is not None else 99)
    d["descs"] = out
    d["total_input_dwords"] = sum(x["len_dw"] + (1 if x["tag"] else 0)
                                  for x in out)
    return d


# ---------------------------------------------------- Part 2a: field loop ----
def tail_value(tag, raw_end):
    """tail emit value per tag&3 (field loop 0x1001a8..0x100208)."""
    if tag == 1:
        return raw_end[-1] << 24
    if tag == 2:
        return int.from_bytes(raw_end[-2:], "big") << 16 & 0xFFFFFFFF
    if tag == 3:
        return (raw_end[-3] << 24) | (raw_end[-2] << 16) | (raw_end[-1] << 8)
    return None


def crosscheck_round(d, entry, hits, known_sha1=True):
    """Simulate the field loop over the reconstructed descriptors and check
    every captured record (12 per round).  Returns per-record verdicts."""
    order = sorted(d["descs"], key=lambda x: PASS_TO_BUILD.index(x["build_idx"]))
    verdicts = []
    # expected state at each loop-head hit i = 0..11
    last_emit = None          # (j, v) of the most recent emitting desc
    for i in range(12):
        if i == 0:
            exp = {"x1": d["ctx"], "x2": 0xB, "x3": d["node_pass0"]}
        else:
            pd = order[i - 1]
            exp = {"x1": pd["sink"]}
            if pd["len_dw"] == 0 and not pd["tag"]:
                exp["x2"], exp["x3"] = (last_emit or (None, None))
            elif pd["tag"]:
                exp["x2"] = pd["len_dw"]              # tail index = L (w21)
                exp["x3"] = pd.get("tail_v")           # known only for #10 B
                last_emit = (exp["x2"], exp["x3"])
            else:
                exp["x2"] = pd["len_dw"] - 1
                exp["x3"] = pd["last_v"]
                last_emit = (exp["x2"], exp["x3"])
        r = entry if i == 0 else hits[i - 1]
        got = {"x1": mask(r["x1"]), "x2": int(r["x2"], 0) & 0xFFFFFFFF,
               "x3": int(r["x3"], 0) & MTE_MASK if i == 0
               else int(r["x3"], 0) & 0xFFFFFFFF}
        ok = {}
        for k in ("x1", "x2", "x3"):
            if exp[k] is None:
                ok[k] = "N/A(unknown value)"
            else:
                ok[k] = (got[k] == (exp[k] & MTE_MASK if k in ("x1",)
                                    or i == 0 and k == "x3" else exp[k]))
        verdicts.append({"hit_i": i, "record_n": r["n"], "expected": exp,
                         "got": got, "match": ok})
    d["record_crosscheck"] = verdicts
    d["all_records_match"] = all(all(v["match"][k] is True or
                                     str(v["match"][k]).startswith("N/A")
                                     for k in v["match"])
                                 for v in verdicts)
    # independent (non-circular) checks per descriptor
    checks = {}
    by_b = {x["build_idx"]: x for x in d["descs"]}
    checks["len#0 static 36 == live"] = by_b[0]["len_dw"] == 36 and \
        by_b[0]["last_j"] == 35
    checks["len#9 static 5 == live"] = by_b[9]["len_dw"] == 5 and \
        by_b[9]["last_j"] == 4
    checks["val#9 == SHA-1 dword4 (independent)"] = \
        by_b[9]["last_v"] == int.from_bytes(CERT_SHA1[16:20], "big")
    checks["len#8 static 4 == live"] = by_b[8]["len_dw"] == 4 and \
        by_b[8]["last_j"] == 3
    checks["len#4 static 8 == live"] = by_b[4]["len_dw"] == 8 and \
        by_b[4]["last_j"] == 7
    checks["val#5 == 0 (slice 27)"] = by_b[5]["last_v"] == 0
    checks["val#6 == 0 (slice 27)"] = by_b[6]["last_v"] == 0
    checks["val#7 == w0(#10)"] = by_b[7]["last_v"] == by_b[10]["w0"]
    checks["w0(#10) == 4*len+tag self-consistent"] = \
        by_b[10]["w0"] == ((by_b[10]["len_dw"] << 2) | by_b[10]["tag"])
    checks["#1/#3 empty, no emits"] = by_b[1]["len_dw"] == 0 and \
        by_b[3]["len_dw"] == 0
    d["independent_checks"] = checks
    d["all_checks_pass"] = all(checks.values())
    return d



class MemMap:
    def __init__(self):
        self.regs = []          # (base, bytes)

    def add_file(self, path, base):
        self.regs.append((base, open(path, "rb").read()))

    def read(self, va, n):
        va &= MTE_MASK
        for base, b in self.regs:
            if base <= va < base + len(b):
                o = va - base
                return b[o:o + n], base
        return None, None

    def find(self, pat):
        for base, b in self.regs:
            i = b.find(pat)
            while i >= 0:
                yield base + i, base
                i = b.find(pat, i + 1)

    def u32(self, va):
        d, reg = self.read(va, 4)
        return (struct.unpack("<I", d)[0], reg) if d else (None, None)

    def u64(self, va):
        d, reg = self.read(va, 8)
        return (struct.unpack("<Q", d)[0], reg) if d else (None, None)


def load_vm_mem():
    mm = MemMap()
    meta = json.load(open(os.path.join(DEV, "vm_mem", "meta.json")))
    for lo, _hi in meta["regions"]:
        fn = os.path.join(DEV, "vm_mem", "R_%x.bin" % (int(lo, 16) & MTE_MASK))
        if os.path.exists(fn):
            mm.add_file(fn, int(lo, 16))
    return mm


def extract_from_memory(mm, expect_H=None):
    """PATH B: anchor on cert SHA-1 (session-independent) at struct+0x100."""
    results = []
    for va, reg in mm.find(CERT_SHA1):
        cand = va - 0x100
        ln, _ = mm.u32(cand + 0x128)
        ptr, _ = mm.u64(cand + 0x130)
        H, _ = mm.read(cand + 0x30, 32)
        core, _ = mm.read(cand + 0x50, 144)
        ok = ln is not None and 0 < ln < 0x400 and (ptr & MTE_MASK) > 0x1000
        results.append({"struct_va": cand, "region": hex(reg), "sha1_va": va,
                        "len10": ln, "ptr10": hex(ptr & MTE_MASK) if ptr else None,
                        "H_hex": H.hex() if H else None,
                        "core_hex": core.hex() if core else None,
                        "plausible": bool(ok),
                        "H_matches_expected": bool(expect_H and H == bytes.fromhex(expect_H))})
    return results


def main():
    report = {"session": "pid 12438 / vm_full.json / vm_mem (aligned)"}

    # ---- PATH A: the aligned session
    recs = parse_vm_full()
    rounds = rounds_from_records(recs["fieldloop"])
    assert len(rounds) == 2, "expected 2 field-loop rounds"
    aligned = []
    for k, rd in enumerate(rounds):
        d = reconstruct_round(rd["entry"], rd["hits"])
        d["round"] = "AB"[k]
        d["entry_x2"] = int(rd["entry"]["x2"], 0)
        vm = [v for v in recs["vm"] if v["n"] == rd["entry"]["n"] - 1]
        d["vm_record_consistent"] = bool(vm) and all(
            vm[0][a] == rd["entry"][a] for a in ("x0", "x1", "x2", "x3", "x4"))
        d = crosscheck_round(d, rd["entry"], rd["hits"])
        aligned.append(d)
    report["rounds"] = aligned

    # ---- PATH B: memory anchors
    tb = json.load(open(os.path.join(HERE, "target_body.json")))
    mm = load_vm_mem()
    H = tb["H"]
    raw_H = bytes.fromhex(H)
    h_hits = [(hex(va), hex(reg)) for va, reg in mm.find(raw_H)]
    s_hits = [(hex(va), hex(reg)) for va, reg in mm.find(CERT_SHA1)]
    report["vm_mem_H_hits"] = h_hits
    report["vm_mem_sha1_hits"] = s_hits
    report["vm_mem_struct_extraction"] = extract_from_memory(mm, H)

    # st_out stacks (related session): SHA-1 copy + SHA-1 desc node
    st = os.path.join(DEV, "st_out", "st23.bin")
    if os.path.exists(st):
        data = open(st, "rb").read()
        stack_base = 0x6EF91C2000          # stack_end(0x6ef9282000) - 0xC0000
        i = data.find(CERT_SHA1)
        nodes = []
        for o in range(0, len(data) - 16, 8):
            w0, pad = struct.unpack_from("<II", data, o)
            if w0 == 0x14 and pad == 0:
                ptr = struct.unpack_from("<Q", data, o + 8)[0] & MTE_MASK
                if 0x100000000 < ptr < 0x7F0000000000 and (ptr & 7) == 0:
                    nodes.append({"node_va": hex(stack_base + o),
                                  "data_ptr": hex(ptr)})
        report["st_out"] = {
            "file": st, "va_range": [hex(stack_base), hex(stack_base + len(data))],
            "sha1_copy_va": hex(stack_base + i) if i >= 0 else None,
            "sha1_desc_nodes": nodes,
            "note": "stack dump of the adj9-oracle thread (snap2.sh: "
                    "[stack_end-0xC0000, stack_end)); contains the SHA-1 desc "
                    "node {w0=0x14, ptr}; live master struct NOT in this dump "
                    "(struct+0x128/+0x130 zero at the stale stack copy)."}

    json.dump(report, open(os.path.join(HERE, "descriptors_aligned.json"), "w"),
              indent=1)

    # ---- console summary
    print("== aligned session: %d field-loop rounds ==" % len(aligned))
    for d in aligned:
        print("round %s  ctx=%x writer=%x  total_input=%d dwords  "
              "vm_record_consistent=%s  all_records_match=%s  "
              "all_checks_pass=%s" % (
                  d["round"], d["ctx"], d["writer"], d["total_input_dwords"],
                  d["vm_record_consistent"], d["all_records_match"],
                  d["all_checks_pass"]))
        for v in d["record_crosscheck"]:
            st = "".join("." if x is True else ("-" if str(x).startswith("N/A")
                                                else "X")
                         for x in (v["match"]["x1"], v["match"]["x2"],
                                   v["match"]["x3"]))
            print("  hit i=%-2d n=%-3d x1/x2/x3 = %s  "
                  "(exp x2=%s x3=%s)" % (
                      v["hit_i"], v["record_n"], st,
                      v["expected"]["x2"], hex(v["expected"]["x3"])
                      if isinstance(v["expected"]["x3"], int) else
                      v["expected"]["x3"]))
        for k, ok in d["independent_checks"].items():
            print("  check: %-42s %s" % (k, "PASS" if ok else "FAIL"))
    print("vm_mem: H hits=%d  cert-SHA1 hits=%d" % (len(h_hits), len(s_hits)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

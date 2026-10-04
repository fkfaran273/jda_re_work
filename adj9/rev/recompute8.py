"""recompute8.py — replay the workhorse stage (hook pc=0x12A880) from the
ALIGNED captured session (device/vm_full.json, pid 12438, created_at
2026-09-12T12:02:24.477Z -> sign second 1789207344).

What the hook really is (established this round, see WALL_A_SLICE_78):
  vmhook.js attaches at INSTRUCTION 0x12A880 — the LENQ->EMIT copy loop
      12a870  cmp  w22, w23            ; w22 = OUTLEN(src stream)
      12a878  ldr  x0, [x28]           ; src ctx stream
      12a87c  mov  w1, w23             ; LENQ index = k
      12a880  ldr  x24, [x26]          ; <-- HOOK (x1=k, x2=w21+k-1 leftover)
      12a888  bl   0x147304            ; LENQ(src, k)   -> offs[TOP+k]
      12a89c  bl   0x146ed8            ; EMIT(writer, [x26], w21+k, value)
  So logged x1 = loop counter k, x2 = previous iteration's EMIT index
  (w21+k-1), x3 = the value EMITted at k-1 (= LENQ result), x4/x9 leftovers.

Replay contract per entry (registers not covered by the hook are DERIVED):
  x26 -> cell containing the destination stream (synthetic MAIN stand-in)
  x28 -> cell containing the source stream VA (untagged logged x0)
  w21 = x2(k=1)                        ; EMIT base (84 = 0x54 here)
  w22 = max(k)+1                       ; loop bound (90 in round 1)
  x19 = logged x19 (status cell; 0 = no error so the loop continues)
"""
import sys, os, struct, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vm_final import Ex
from hydrate import RegionMem, load_mem, parse_stream, hydrate, untag, PM

DEV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "device")
HOOK = 0x12A880
DEST = 0x5DD00D0000          # synthetic destination stream (MAIN stand-in)
X26CELL = 0x5C00000260
X28CELL = 0x5C00000268
SP = 0x5C00000300
X29 = 0x5C00000000

M32 = 0xFFFFFFFF


def load_session():
    d = json.load(open(os.path.join(DEV, "vm_full.json")))
    wh = [h for h in d if h.get("tag") == "workhorse"]
    # split into rounds by (x19, x20, x0) context change
    rounds, cur, key = [], [], None
    for h in wh:
        k = (h["x19"], h["x20"])
        if key is not None and k != key:
            rounds.append(cur)
            cur = []
        key = k
        cur.append(h)
    if cur:
        rounds.append(cur)
    return d, rounds


def claims_score(h, k, claims):
    """prefer entries whose x3 spells the known ASCII claims word k-1"""
    if k >= 1 and k - 1 < len(claims):
        return 1 if (int(h["x3"], 16) & M32) == claims[k - 1] else 0
    return 0


def main():
    d, rounds = load_session()
    print("workhorse rounds:", [(len(r), int(r[0]["x1"], 16),
                                 int(r[-1]["x1"], 16)) for r in rounds])
    r1 = max(rounds, key=len)          # round 1: k = 0..89 (complete)
    r2 = [r for r in rounds if r is not r1]

    k1 = sorted(int(h["x1"], 16) for h in r1)
    W22 = k1[-1] + 1
    # w21: x2(k) = w21 + k - 1  for k >= 1  =>  w21 = x2(k) - k + 1
    w21s = set()
    for h in r1:
        k = int(h["x1"], 16)
        if k >= 1:
            w21s.add(((int(h["x2"], 16) & M32) - k + 1) & M32)
    assert len(w21s) == 1, "inconsistent w21 derivation: %s" % w21s
    W21 = w21s.pop()
    print("derived contract: w21=%d (0x%x) w22=%d" % (W21, W21, W22))

    # logged claims values: value[k-1] = x3 at iteration k (k=1..W22-1)
    by_k = {int(h["x1"], 16): h for h in r1}
    claims = []
    for k in range(1, W22):
        if k in by_k:
            claims.append(int(by_k[k]["x3"], 16) & M32)
    NV = W22 - len(claims)             # values never observed (last iteration)
    print("claims words logged: %d / %d (last %d unknown -> 0 placeholder)"
          % (len(claims), W22, NV))
    txt = b"".join(struct.pack(">I", v) for v in claims)
    print("claims text head: %r" % txt[:48])
    print("claims text tail: %r" % txt[-48:])

    SRC = untag(int(r1[1]["x0"], 16))          # source ctx stream (k>=1 recs)
    SRCs = set(untag(int(h["x0"], 16)) for h in r1 if int(h["x1"], 16) >= 1)
    assert len(SRCs) == 1
    print("source stream VA: %012x  dest [x26]: not captured (synthetic %012x)"
          % (SRC, DEST))

    # ---------------- memory + streams ----------------
    ex = Ex(seed=1789207344, descs=[(0, 0, b"")], shared_q=True)
    rm = RegionMem()
    ex.mem.update(load_mem())                  # raw region words (RO intent)
    ex._heap = [0x5A00000000, {}]

    # --- task 4 diagnosis: what does the DUMP say about the source stream? ---
    st = parse_stream(rm, SRC)
    print("\n[dump-state] source stream struct: %s" % st)
    vas = set()
    for h in d:
        for key in ("x0", "x1", "x20"):
            try:
                vas.add(untag(int(h[key], 16)))
            except Exception:
                pass
    inr = [v for v in sorted(vas) if rm.inrange(v)]
    print("[dump-state] %d/%d arg-derived VAs inside dumped regions" %
          (len(inr), len(vas)))
    hyd = hydrate(ex, rm, inr, verbose=True)
    if not any(v == SRC for v, _ in hyd):
        print("[dump-state] source stream NOT hydratable (acc=0,count=0) -> "
              "vm_mem holds NO post-field-loop stream state")

    # --- reconstruct the source stream from the logged x3 words (only honest
    #     data source for this session; dump alone yields zeros = recompute7) --
    s = ex.stream_for(SRC)
    s.ro = True
    s.data = [0]                    # native: frame-base stack, TOP = data[-1]
    s.offs = claims + [0] * NV      # value array; value[W22-1] unknown -> 0
    s._acc = W22
    s.limit = 0x100
    print("[reconstructed] LENQ triples (stream=%012x TOP=%08x):" % (SRC, 0))
    ex._slog = []
    for k in range(6):
        v = lenq_model(s, k)
        print("   LENQ(src, %d) -> offs[TOP+%d] = %08x %r" %
              (k, k, v, struct.pack(">I", v)))
    assert [lenq_model(s, k) for k in range(len(claims))] == claims

    # destination stream (fresh; force MERGE path like the live MAIN whose
    # acc > 0 after the header/structure EMITs)
    ex.mem[DEST + 0x10] = 1
    ex.mem[DEST + 0x14] = 0
    ex.mem[X26CELL] = DEST
    ex.mem[X28CELL] = SRC

    # ---------------- per-entry replay ----------------
    REC_REGS = ("x0", "x1", "x2", "x3", "x4", "x9", "x19", "x20")

    def replay(rec, src_va, w22=W22):
        """Enter at the hook (0x12A880) with this iteration's contract.

        Register hygiene: vm_final keeps wN/xN as separate dict entries
        (set_reg updates both, direct R writes do not), so stale wN values
        from a previous run silently shadow the fresh xN (this is what made
        recompute7/recompute8-v1 outputs drift).  Every replay therefore
        starts from a cleared register file and goes through set_reg.
        The status cell [x19] starts 0 (native per-invocation cell).
        Only the copy-loop's own EMITs (first w22-k, callsite 0x12a89c) are
        returned; the program legitimately continues after the loop
        (PUSH 1 -> further handlers) and those tail effects are ignored.
        """
        k = int(rec["x1"], 16)
        ex.R = {"sp": SP, "x29": X29}          # clear stale w/x aliases
        ex.set_reg("x0", int(rec["x0"], 16))   # tagged; stream_for masks
        ex.set_reg("x1", k)
        ex.set_reg("x2", int(rec["x2"], 16))
        ex.set_reg("x3", int(rec["x3"], 16))
        ex.set_reg("x4", int(rec["x4"], 16))
        ex.set_reg("x9", int(rec["x9"], 16))
        ex.set_reg("x19", untag(int(rec["x19"], 16)))
        ex.set_reg("x20", int(rec["x20"], 16))  # unused inside the loop
        ex.set_reg("x21", W21)                  # EMIT base (derived)
        ex.set_reg("x22", w22)                  # loop bound (derived)
        ex.set_reg("x23", k)                    # loop counter = logged x1
        ex.set_reg("x26", X26CELL)              # [x26] -> dest stream
        ex.set_reg("x28", X28CELL)              # [x28] -> source stream
        ex.set_reg("x30", 0xDEAD0000)
        ex.mem[untag(int(rec["x19"], 16)) & ~7] = 0   # status cell = no error
        ex.emit_trace = []
        ex._slog = []
        ex.pc = HOOK
        status = ex.run(max_steps=100000)
        ems = list(ex.emit_trace)[: max(w22 - k, 0)]   # copy-loop EMITs only
        return status, ems, list(ex._slog)

    outbuf = {}                    # emit index -> value (deduped by x1)
    per_iter = {}                  # k -> (index, value, status)
    lenq_log = []
    for h in sorted(r1, key=lambda h: int(h["x1"], 16)):
        k = int(h["x1"], 16)
        status, ems, sl = replay(h, SRC)
        if not ems:
            print("!! no EMIT for k=%d (status=%s)" % (k, status))
            continue
        idx, val = ems[0][1], ems[0][2]
        # dedupe by x1: first EMIT of the run is this iteration's slot
        if k not in per_iter:
            per_iter[k] = (idx, val, status)
            outbuf[idx] = val
            if k < 3 or k >= W22 - 2:
                print("k=%2d status=%s first EMIT idx=%d val=%08x (%d copy emits in run)"
                      % (k, status, idx, val, len(ems)))
        lenq_log += sl
    print("replayed %d iterations, %d deduped, outbuf span %d..%d" %
          (len(r1), len(per_iter), min(outbuf), max(outbuf)))
    exp_idx = [W21 + k for k in sorted(per_iter)]
    assert exp_idx == sorted(outbuf), "emit index contract broken"

    # round-2 cross-check (duplicated iterations x1=0..3, same claims)
    for r in r2:
        src2 = untag(int(r[1]["x0"], 16)) if len(r) > 1 else None
        print("\nround-2 check: %d records, src=%s (in dumps: %s)" %
              (len(r), "%012x" % src2 if src2 else "?", bool(src2 and rm.inrange(src2))))
        s2 = ex.stream_for(src2)
        s2.ro = True
        s2.data = [0]
        s2.offs = claims + [0] * NV
        s2._acc = W22
        for h in r:
            k = int(h["x1"], 16)
            if k == 0 or k not in per_iter:
                continue
            ex.mem[X28CELL] = src2
            status, ems, _ = replay(h, src2)
            idx, val = ems[0][1], ems[0][2]
            same = (val == per_iter[k][1])
            print("  round2 k=%d first EMIT idx=%d val=%08x matches round1: %s"
                  % (k, idx, val, same))
        ex.mem[X28CELL] = SRC

    # ---------------- assemble + compare (task 3) ----------------
    tj = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "target_body.json")))
    tgt = [int(x, 16) & M32 for x in tj["body_dwords_hex"]]
    seq = [outbuf[W21 + i] for i in range(W22)]         # iter order

    def score44(win):
        m = sum(1 for a, b in zip(win, tgt) if a == b)
        run = best = 0
        first = None
        for i, (a, b) in enumerate(zip(win, tgt)):
            if a == b:
                run += 1
                best = max(best, run)
            else:
                if first is None:
                    first = i
                run = 0
        return m, best, first

    print("\n=== comparison vs target body (44 BE dwords) ===")
    primary = seq[:44]
    m, run, first = score44(primary)
    print("first-44 (iter order):      matched %d/44  longest-run %d  first-div %s"
          % (m, run, first))
    m, run, first = score44(seq[-44:])
    print("last-44  (iter order):      matched %d/44  longest-run %d  first-div %s"
          % (m, run, first))
    best = max(((score44(seq[i:i + 44]), i) for i in range(len(seq) - 43)))
    print("best sliding 44-window:     matched %d/44  longest-run %d  at iter %d"
          % (best[0][0], best[0][1], best[1]))
    sw = [struct.unpack("<I", struct.pack(">I", v))[0] for v in seq]
    bs = max(score44(sw[i:i + 44])[0] for i in range(len(sw) - 43))
    print("byte-swapped best window:   matched %d/44" % bs)
    print("mine[:8] :", " ".join("%08x" % v for v in seq[:8]))
    print("target[:8]:", " ".join("%08x" % v for v in tgt[:8]))
    print("mine[-6] :", " ".join("%08x" % v for v in seq[-6:]))
    print("target[-6]:", " ".join("%08x" % v for v in tgt[-6:]))
    asciiish = sum(1 for v in seq if 0x20 <= (v >> 24) < 0x7f and
                   0x20 <= (v & 0xFF) < 0x7f)
    print("ASCII-textured emitted dwords: %d/%d (target body is binary)" %
          (asciiish, len(seq)))

    json.dump({"w21": W21, "w22": W22, "seq": ["%08x" % v for v in seq],
               "per_iter": {"%d" % k: ["%d" % v[0], "%08x" % v[1], v[2]]
                            for k, v in sorted(per_iter.items())}},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "recompute8_out.json"), "w"), indent=1)
    print("\nwrote rev/recompute8_out.json")
    return ex, seq, tgt


def lenq_model(s, n):
    """mirror of the native LENQ for reporting (offs[TOP+n] if < limit)"""
    top = s.data[-1] if s.data else 0
    idx = (top + n) & M32
    if idx < getattr(s, "limit", 0x7FFFFFFF) and idx < len(s.offs):
        return s.offs[idx]
    return 0


if __name__ == "__main__":
    main()

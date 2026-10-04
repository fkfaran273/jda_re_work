"""Differential test: original vs working adj9_signature.

Two independent levels of evidence:

  A. per-step full-state comparison over a prefix of the run (catches any
     divergence early, including compensating errors that would still yield
     the right 192 bytes at the end);
  B. whole-run comparison of emit_trace + final registers/memory/streams +
     the 192-byte blob itself.

Usage:  python -u _diff.py [kind] [prefix_steps] [checkpoint_every]
"""
import importlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _gate
import _orig_adj9_signature as O
import adj9_signature as N


def build(mod, kind):
    params = _gate.make(kind)
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": mod.CLIENT_SDK,
                "adj_signing_id": mod.ADJ_SIGNING_ID, "headers_id": "10",
                "native_version": mod.NATIVE_VERSION,
                "adj_verification": mod.ADJ_VERIFICATION})
    d0w, d2w, d4w = mod.region(_gate.SEED, 0, 0, head=mod.WIN_PHASE)
    padded, unpadded = mod.claims_padded(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, mod.DESC9), 8: (4, 0, mod.DESC8),
          4: (8, 0, d4), 2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in mod.VA_ORDER]


M32 = 0xFFFFFFFF


def regs(ex):
    """Canonical register view, identical in both worlds.

    The dict world (original) stores xN and wN as two keys that alias one
    64-bit slot; the list world stores the two views explicitly.  Normalise
    both to (x_view[0..32], w_view[0..32], exotic) so the comparison is about
    VALUES, not representation.  A key present on only one side contributes
    through the alias rule, exactly as Ex.val() did.
    """
    if hasattr(ex, "RL"):
        return ("v", tuple(ex.RL), tuple(ex.WL), tuple(sorted(ex.Rx.items())))
    R = ex.R
    xv = []
    wv = []
    for n in range(32):
        x = R.get("x%d" % n)
        w = R.get("w%d" % n)
        if x is None and w is None:
            xv.append(0); wv.append(0)
        elif x is None:
            xv.append(w); wv.append(w)
        elif w is None:
            xv.append(x); wv.append(x & M32)
        else:
            xv.append(x); wv.append(w)
    xv.append(R.get("sp", 0))
    wv.append(R.get("sp", 0))
    extra = tuple(sorted((k, v) for k, v in R.items()
                         if not (len(k) > 1 and k[0] in "wx" and k[1:].isdigit())
                             and k != "sp"))
    return ("v", tuple(xv), tuple(wv), extra)


def state(ex):
    st = [("pc", ex.pc), ("steps", ex.steps), ("nrand", ex.nrand),
          ("R", regs(ex)), ("F", tuple(sorted(ex.F.items()))),
          ("mem", tuple(sorted(ex.mem.items()))),
          ("it", tuple(sorted(ex.iters.items(), key=lambda kv: str(kv[0])))),
          ("emit", tuple(ex.emit_trace))]
    st.append(("queues", tuple(sorted(
        (k, tuple(v)) for k, v in ex.queues.items()))))
    ss = []
    for va in sorted(ex.streams):
        s = ex.streams[va]
        ss.append((va, tuple(s.top), tuple(sorted(s.offs.items())),
                   s.acc, s.limit))
    st.append(("streams", tuple(ss)))
    return tuple(st)


def first_diff(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return "field#%d %r != %r" % (i, str(x)[:400], str(y)[:400])
    return "length %d vs %d" % (len(a), len(b))


def run_stepwise(mod, kind, nsteps):
    """Run with a per-step hook that captures full state for `nsteps`."""
    ex = mod.FinEx(_gate.SECOND, build(mod, kind))
    cap = []
    st = {"n": 0}

    def hook(e):
        st["n"] += 1
        if st["n"] <= nsteps:
            cap.append(state(e))
        else:
            raise StopIteration
    ex._step_hook = hook
    try:
        status = ex.run(max_steps=40_000_000)
    except StopIteration:
        status = "<prefix>"
    return cap, status


def run_full(mod, kind, every):
    ex = mod.FinEx(_gate.SECOND, build(mod, kind))
    snaps = []
    st = {"n": 0}

    def hook(e):
        st["n"] += 1
        if st["n"] % every == 0:
            snaps.append(state(e))
    ex._step_hook = hook
    status = ex.run(max_steps=40_000_000)
    return snaps, state(ex), status


def mint(mod, kind):
    blob, info = None, None
    params = _gate.make(kind)
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": mod.CLIENT_SDK,
                "adj_signing_id": mod.ADJ_SIGNING_ID, "headers_id": "10",
                "native_version": mod.NATIVE_VERSION,
                "adj_verification": mod.ADJ_VERIFICATION})
    d0w, d2w, d4w = mod.region(_gate.SEED, 0, 0, head=mod.WIN_PHASE)
    padded, unpadded = mod.claims_padded(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, mod.DESC9), 8: (4, 0, mod.DESC8),
          4: (8, 0, d4), 2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in mod.VA_ORDER]
    ex = mod.FinEx(_gate.SECOND, descs)
    status = ex.run(max_steps=40_000_000)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for (sva, n), v in last.items():
        bys.setdefault(sva, {})[n] = v
    hdr = struct.unpack(">4I", mod.make_header(_gate.SECOND))
    stream = None
    for sva in sorted(bys):
        if tuple(bys[sva].get(k, 0) for k in range(4)) == hdr:
            stream = sva
            break
    blob = b"".join(struct.pack(">I", bys[stream].get(k, 0))
                    for k in range(mod.BLOB_WORDS))
    return blob, status, ex.steps


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "session"
    prefix = int(sys.argv[2]) if len(sys.argv) > 2 else 400_000
    every = int(sys.argv[3]) if len(sys.argv) > 3 else 250_000
    ok = True

    print("[A] per-step full-state comparison, first %d steps ..." % prefix)
    a, sa = run_stepwise(O, kind, prefix)
    b, sb = run_stepwise(N, kind, prefix)
    print("    captured %d vs %d states (status %s / %s)"
          % (len(a), len(b), sa, sb))
    if len(a) != len(b):
        print("    *** LENGTH MISMATCH ***")
        ok = False
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            print("    *** DIVERGED at step %d: %s" % (i + 1, first_diff(x, y)))
            ok = False
            break
    else:
        print("    identical for all %d steps" % len(a))

    print("[B] whole run: checkpoints every %d + final state + blob" % every)
    sa_, fa, ta = run_full(O, kind, every)
    sb_, fb, tb = run_full(N, kind, every)
    print("    status %s / %s   steps %d / %d   checkpoints %d / %d"
          % (ta, tb, fa[1][1], fb[1][1], len(sa_), len(sb_)))
    if (ta, fa[1][1]) != (tb, fb[1][1]):
        print("    *** STATUS/STEP MISMATCH ***")
        ok = False
    for i, (x, y) in enumerate(zip(sa_, sb_)):
        if x != y:
            print("    *** checkpoint %d diverged: %s"
                  % (i, first_diff(x, y)))
            ok = False
            break
    if fa != fb:
        print("    *** FINAL STATE: %s" % first_diff(fa, fb))
        ok = False
    ba, _, _ = mint(O, kind)
    bb, _, _ = mint(N, kind)
    print("    blob %d bytes, match=%s" % (len(bb), ba == bb))
    if ba != bb:
        nd = sum(1 for x, y in zip(ba, bb) if x != y)
        print("    *** BLOB MISMATCH (%d bytes differ)" % nd)
        ok = False

    print("DIFFERENTIAL", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

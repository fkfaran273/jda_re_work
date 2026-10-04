"""block_trace.py — provenance trace for the 32-byte record block at
record[46:78) of the adj9 signature (pre-whitening record).

  record = 144 B, first-write low bytes of stream 0x5450001000 @ [1134..1278)
  block  = record[46:78)  ==  stream 0x5450001000 @ [1180..1212)

Two deterministic passes over FinEx for row 7 of all_signings.json
(== pair_h3.json i=7, the `second` of that pair):

  pass 1  plain fast run with FinStream.emit instrumented to also capture the
          VM STEP number of every EMIT.  Produces the exact write list for
          stream [1180..1212): how many writes, from which loop iteration,
          in what order, and which are the "first write" (the record uses
          first-write-wins).

  pass 2  identical re-run (same seed -> same execution) with a WINDOWED
          per-step hook.  The interpreter keeps its FAST dispatch path; only
          steps inside the window pay for provenance.  In the window we log
          (a) every register change (diffed per step, so the bl-handler
          `R[...] = ...` direct assignments are captured too) and (b) every
          memory store through Ex.st / Ex.stbyte.  That is a complete
          def-use log for the window.

  slice   backward slicing from w3 at each of the 32 first-write EMITs through
          the pass-2 def-use log down to constants, descriptor words, memory
          cells and VM primitive ops (PUSH/POP/LENQ/RAND/EMIT/...).

Outputs: block_trace.json, block_trace_window.txt, block_trace_slices.txt
"""
import json
import struct
import sys
import re
import time
import inspect
import textwrap

sys.path.insert(0, '.')

import vm_final as V
import mint_pipeline as M
import fin_vm2
from fin_vm2 import FinEx, FinStream
from vm_final import IDX, INS

ROW = 7
MAIN = 0x5450001000
REC_OFF = 1134
REC_LEN = 144
BLK_LO, BLK_HI = 46, 78
S_LO, S_HI = REC_OFF + BLK_LO, REC_OFF + BLK_HI      # 1180 .. 1212
WIN_BACK = 60_000
WIN_FWD = 400
PROFILE = "--pass1" not in sys.argv      # pass 2 is the expensive part

D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

# descriptor-index -> (len_dw, data) for row 7, for leaf labelling
DESCMETA = [
    (0,  "d0",  "per-call region core, 144 B"),
    (9,  "d9",  "cert SHA-1, 20 B"),
    (8,  "d8",  "16-B constants"),
    (4,  "d4",  "region structured record, 32 B"),
    (2,  "d2",  "region per-call word"),
    (7,  "d7",  "unpadded #10 length"),
    (10, "d10", "claims (NUL-padded)"),
    (5,  "d5",  "const"),
    (6,  "d6",  "const"),
    (1,  "d1",  "empty"),
    (3,  "d3",  "empty"),
]


def load_row7():
    rows = json.load(open('all_signings.json', encoding='utf-8'))
    pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
    r, p = rows[ROW], pairs[ROW]
    d0 = bytes.fromhex(r['d0'])
    d2 = bytes.fromhex(r['d2'])
    d4 = bytes.fromhex(r['d4'])
    claims = bytes.fromhex(r['d10'])
    unp = len(claims)
    padded = claims + b'\x00' * ((-unp) % 4)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in M.VA_ORDER]
    return descs, int(p['second']), r, p


# =========================================================== pass 1: emits
_OWNER = {}
EMITS = []


def instrument(ex):
    for sva in ex.streams:
        _OWNER[sva] = ex


_orig_emit = FinStream.emit


def emit_spy(self, n, v):
    n &= 0xFFFFFFFF
    v &= 0xFFFFFFFF
    top = self.top[-1]
    _orig_emit(self, n, v)
    ex = _OWNER.get(self.va)
    EMITS.append(((ex.steps if ex else -1), self.va, top, n, v, top + n))


FinStream.emit = emit_spy

# ================================================== pass 2: windowed prov
STEP_LOG = []      # (step, pc, mnem, ops, ev)  ev = list[(kind,name,val)]
MEM_LOG = []       # (step, pc, kind, va, size, value)
BLOG = []          # (step, pc, target, x1, w2, qlen, qhead6)
LQ = []            # [step, stream_va, n, result, pc] for LENQ
WIN = [0, -1]

BL_PUSH, BL_POP = 0x147630, 0x147734
BL_EMIT, BL_LENQ = 0x146ed8, 0x147304
BL_SWAP, BL_CAPP = 0x147a20, 0x14784c
BL_CAPP0, BL_RAND = 0x147a18, 0x148d10
BL_OUTLEN, BL_PUSHS, BL_POPS = 0x1472e8, 0x147120, 0x147220
BL_MKITER, BL_ITNEXT, BL_ISEMPTY = 0x146558, 0x146650, 0x146474
BL_NAME = {BL_PUSH: "PUSH", BL_POP: "POP", BL_EMIT: "EMIT", BL_LENQ: "LENQ",
           BL_SWAP: "CAP_SWAP", BL_CAPP: "CAP_PUSH", BL_CAPP0: "CAP_PUSH0",
           BL_RAND: "RAND", BL_OUTLEN: "OUTLEN", BL_PUSHS: "PUSHS",
           BL_POPS: "POPS", BL_MKITER: "MKITER", BL_ITNEXT: "ITERNEXT",
           BL_ISEMPTY: "ISEMPTY"}


def make_windowed_run():
    """FinEx.run with the FAST dispatch forced on and a windowed hook.
    Two textual edits; no interpreter logic changed."""
    src = textwrap.dedent(inspect.getsource(fin_vm2.FinEx.run))
    a = ("    _fast = not (_hook is not None or _pclog is not None\n"
         "                 or _dbg is not None)")
    assert a in src, "anchor A missing"
    src = src.replace(a, "    _fast = True\n"
                          "    _win = self.__dict__.get('_win')")
    b = ("        if not _fast:\n"
         "            if _hook is not None:\n"
         "                _hook(self)\n")
    assert b in src, "anchor B missing"
    src = src.replace(
        b,
        "        if _win is not None and _win[0] <= self.steps <= _win[1]:\n"
        "            _hook(self)\n"
        "        if not _fast:\n")
    ns = dict(vars(fin_vm2))
    exec(compile(src, "<block_trace_run>", "exec"), ns)
    return ns['run']


def patch_stores():
    """Log every st/stbyte through the window."""
    orig_st, orig_stb = V.Ex.st, V.Ex.stbyte

    def st(self, va, v, size=8):
        if WIN[0] <= self.steps <= WIN[1]:
            MEM_LOG.append((self.steps, self.pc, "st",
                            va & 0xFFFFFFFFFFFF, size, v & 0xFFFFFFFFFFFFFFFF))
        return orig_st(self, va, v, size)

    def stbyte(self, va, b):
        if WIN[0] <= self.steps <= WIN[1]:
            MEM_LOG.append((self.steps, self.pc, "stb",
                            va & 0xFFFFFFFFFFFF, 1, b & 0xFF))
        return orig_stb(self, va, b)
    V.Ex.st, V.Ex.stbyte = st, stbyte
    return orig_st, orig_stb


INTERN = {}


def _i(s):
    return INTERN.setdefault(s, s)


def make_hook():
    prev = {}

    first_seen = []
    pend = []

    def hook(e):
        R = e.R
        ev = []
        for k, v in R.items():
            if prev.get(k, -1) != v:
                ev.append(("R", _i(k), v & 0xFFFFFFFF))
        for k in prev:
            if k not in R:
                ev.append(("Rdel", _i(k), 0))
        prev.clear()
        prev.update(R)
        if not first_seen:
            # the window opens mid-execution: the state at this step is not
            # the product of any instruction inside the window
            first_seen.append(1)
            ev = []
        if pend:
            for (kind, k, v) in ev:
                if kind == "R" and k == "w0":
                    pend[0][3] = v
            pend.clear()
        pc = e.pc
        k = IDX.get(pc)
        mnem, ops = (V.FAST[k][0], V.FAST[k][1]) if k is not None else ("?", "?")
        STEP_LOG.append((e.steps, pc, _i(mnem), _i(ops), ev))
        if mnem == "bl":
            t = V.pt(ops)
            if t in BL_NAME:
                x1 = R.get("x1", 0) & 0xFFFFFFFFFFFF
                q = e.queues.get(R.get("x1", 0))
                BLOG.append((e.steps, pc, BL_NAME[t], x1,
                             R.get("w2", 0) & 0xFFFFFFFF,
                             len(q) if q is not None else -1,
                             list(q[:8]) if q else None))
                if t == BL_LENQ:
                    LQ.append([e.steps, (R.get("x0", 0) & 0xFFFFFFFFFFFF),
                               R.get("w1", 0) & 0xFFFFFFFF, None, pc])
                    pend.append(LQ[-1])
    return hook


# ============================================================== pass 1 body
def pass1(descs, sec):
    t0 = time.time()
    ex = FinEx(sec, descs)
    instrument(ex)
    status = ex.run(max_steps=60_000_000)
    info = {"status": status, "steps": ex.steps, "nrand": ex.nrand,
            "secs": round(time.time() - t0, 1), "total_emits": len(EMITS)}
    return ex, info


def main():
    descs, sec, row, pair = load_row7()
    out = {"row": ROW, "second": sec,
           "record_stream_off": [REC_OFF, REC_OFF + REC_LEN],
           "block_record_off": [BLK_LO, BLK_HI],
           "block_stream_off": [S_LO, S_HI]}

    ex, info = pass1(descs, sec)
    out['pass1'] = info
    main_emits = [e for e in EMITS if (e[1] & 0xFFFFFFFFFFFF) == MAIN]
    rec = {}
    for e in main_emits:
        rec.setdefault(e[5], e[4] & 0xFF)
    record = bytes(rec[REC_OFF + i] for i in range(REC_LEN))
    blk = bytes(rec[S_LO + i] for i in range(32))
    out['main_emit_count'] = len(main_emits)
    # full MAIN stream content (last write wins per index) and the ordered
    # list of first-writes -- lets us test "record == slice of the stream"
    sidx = {}
    for e in main_emits:
        sidx[e[5]] = e[4] & 0xFFFFFFFF
    out['main_stream_max_idx'] = max(sidx) if sidx else None
    out['main_stream_words'] = {str(i): "%08x" % v
                                for i, v in sorted(sidx.items())}
    fidx = {}
    for e in main_emits:
        fidx.setdefault(e[5], e)
    out['main_stream_first'] = {
        str(i): {"step": fidx[i][0], "v": "%08x" % fidx[i][4],
                 "pc": "%#x" % fidx[i][1]} for i in sorted(fidx)}
    out['record_hex'] = record.hex()
    out['block_hex'] = blk.hex()
    out['block_dwords_be'] = ["%08x" % x for x in struct.unpack('>8I', blk)]
    out['block_dwords_le'] = ["%08x" % x for x in struct.unpack('<8I', blk)]

    tgt = [e for e in main_emits if S_LO <= e[5] < S_HI]
    first = {}
    for e in tgt:
        first.setdefault(e[5], e)
    out['target_writes'] = len(tgt)
    out['target_first_writes'] = len(first)
    fsteps = sorted((first[k][0], k) for k in first)
    out['first_write_order'] = [{"idx": k, "step": s} for s, k in fsteps]
    # full 144-byte record: first write of every record offset + the whole
    # first-write history of the record area (loop structure)
    rfirst = {}
    for e in main_emits:
        if REC_OFF <= e[5] < REC_OFF + REC_LEN:
            rfirst.setdefault(e[5], e)
    out['record_first_writes'] = [
        {"rec_off": e[5] - REC_OFF, "idx": e[5], "step": e[0], "n": e[3],
         "v": "%08x" % e[4]} for e in sorted(rfirst.values(), key=lambda x: x[0])]
    out['record_first_write_step_range'] = [
        min(e[0] for e in rfirst.values()), max(e[0] for e in rfirst.values())]
    out['first_write_step_range'] = [fsteps[0][0], fsteps[-1][0]]
    ts = [e[0] for e in tgt]
    out['target_step_range'] = [min(ts), max(ts)]
    print("pass1 %.0fs %s  main_emits=%d  writes->[1180,1212)=%d  "
          "first-writes=%d  first steps %d..%d  all writes steps %d..%d"
          % (info['secs'], info['status'], len(main_emits), len(tgt),
             len(first), fsteps[0][0], fsteps[-1][0], min(ts), max(ts)),
          flush=True)

    with open('block_trace_emits.txt', 'w', encoding='utf-8') as f:
        for e in main_emits:
            if not (S_LO <= e[5] < S_HI):
                continue
            f.write("step=%9d idx=%d top=%d n=%d v=%08x byte=%02x%s\n"
                    % (e[0], e[5], e[2], e[3], e[4], e[4] & 0xFF,
                       "   <FIRST" if first.get(e[5]) is e else ""))
    json.dump(out, open('block_trace.json', 'w'), indent=1)
    if not PROFILE:
        print("pass1 only (drop --pass1 for the provenance pass)")
        return

    # ---------------------------------------------------- pass 2
    del EMITS[:]
    del STEP_LOG[:]
    del MEM_LOG[:]
    lo = fsteps[0][0]
    hi = fsteps[-1][0]
    WIN[0], WIN[1] = max(0, lo - WIN_BACK), hi + WIN_FWD
    out['window'] = [WIN[0], WIN[1]]
    print("window %s (%d steps)" % (WIN, WIN[1] - WIN[0]), flush=True)
    patch_stores()
    ex2 = FinEx(sec, descs)
    instrument(ex2)
    ex2.__dict__['_win'] = (WIN[0], WIN[1])
    ex2.__dict__['_step_hook'] = make_hook()
    t0 = time.time()
    st2 = make_windowed_run()(ex2, max_steps=60_000_000)
    out['pass2'] = {"status": st2, "steps": ex2.steps,
                    "reg_steps_logged": len(STEP_LOG),
                    "mem_stores_logged": len(MEM_LOG),
                    "bl_ops_logged": len(BLOG),
                    "secs": round(time.time() - t0, 1)}
    print("pass2 %.0fs %s reg-steps=%d mem-stores=%d bl-ops=%d"
          % (out['pass2']['secs'], st2, len(STEP_LOG), len(MEM_LOG),
             len(BLOG)), flush=True)

    report(out, descs, sec, first, fsteps, tgt, main_emits)
    json.dump(out, open('block_trace.json', 'w'), indent=1)
    print("wrote block_trace.json block_trace_window.txt "
          "block_trace_slices.txt")




# ================================================== register-level backward slice
REG = re.compile(r'^[wx]\d+$')
PSEUDO = ("wzr", "xzr", "sp")


def build_index():
    """reg name -> sorted list of (step, pc, mnem, ops, val) for its writes."""
    hist = {}
    for (st, pc, mnem, ops, ev) in STEP_LOG:
        for (kind, k, v) in ev:
            if kind == "R":
                # the change is DETECTED at the top of step `st`; the
                # instruction that produced it ran at step st-1, address pc-4
                dpc = pc - 4
                dk = IDX.get(dpc)
                dm, do = (V.FAST[dk][0], V.FAST[dk][1]) if dk is not None                     else ("?", "?")
                hist.setdefault(k, []).append((st - 1, dpc, dm, do, v))
    return hist


def last_def(hist, name, before):
    h = hist.get(name)
    if not h:
        return None
    lo, hi, best = 0, len(h) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if h[mid][0] < before:
            best = h[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best


class Slicer(object):
    def __init__(self, hist, budget=400):
        self.hist = hist
        self.budget = budget
        self.leaves = []

    def reg(self, name, before, depth=0):
        if name in PSEUDO:
            return {"leaf": "const0", "reg": name}
        n = REG.match(name)
        if not n:
            return {"leaf": "imm", "reg": name, "text": name}
        if self.budget[0] <= 0:
            return {"leaf": "depth-cut", "reg": name}
        self.budget[0] -= 1
        d = last_def(self.hist, name, before)
        if d is None:
            self.leaves.append(("reg-outside-window", name, before))
            return {"leaf": "no-def-in-window", "reg": name, "at": before}
        st, pc, mnem, ops, v = d
        node = {"reg": name, "step": st, "pc": "%#x" % pc,
                "asm": "%s %s" % (mnem, ops), "val": "%08x" % v}
        p = [x.strip() for x in ops.split(",")]
        if mnem in ("mov", "movz"):
            node["from"] = p[1]
            node["src"] = self.reg(p[1], st, depth + 1)
        elif mnem in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr",
                      "rev", "rev16", "neg", "mvn", "udiv", "msub", "bfi",
                      "ubfx", "sbfx", "extr", "csel", "cset", "cinc", "csinc"):
            node["op"] = mnem
            srcs = [s for s in p[1:] if REG.match(s.split()[0])]
            node["chain"] = [self.reg(s, st, depth + 1) for s in srcs]
        elif mnem in ("ldr", "ldur", "ldrsw", "ldrb", "ldrh", "ldp"):
            node["load"] = ops
            srcs = [s for s in p[1:] if REG.match(s.split()[0])]
            node["chain"] = [self.reg(s, st, depth + 1) for s in srcs]
        elif mnem == "bl":
            node["bl"] = BL_NAME.get(V.pt(ops), ops)
        elif mnem in ("cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz",
                      "b", "ret", "nop", "mrs") or mnem.startswith("b."):
            node["flow"] = True
        elif mnem in ("str", "stur", "stp", "strb"):
            node["store"] = ops
        else:
            node["unhandled"] = True
            self.leaves.append(("unhandled-instr", mnem + " " + ops, st))
        return node


# ==================================================== queue token provenance
def replay_queue(BLOG):
    """Re-simulate every logged queue op, giving each POP a *token* that
    identifies the PUSH (step, w2) it came from.  Returns
      (tokens, results) where results[step] = token returned by that op."""
    qs = {}
    tok_of = {}          # (qva, slot_id) -> token
    tokens = {}          # token_id -> {"step":s,"val":v,"via":...}
    nxt = [0]
    pushes = []          # ordered list of (step, qva, val, token_id)

    def newtok(step, qva, val, via, parent=None):
        nxt[0] += 1
        t = nxt[0]
        tokens[t] = {"tok": t, "push_step": step, "qva": qva, "val": val,
                     "via": via, "parent": parent}
        pushes.append((step, qva, val, t))
        return t

    for (s, pc, name, x1, w2, qlen, head) in BLOG:
        q = qs.setdefault(x1, [])
        if name == "PUSH":
            t = newtok(s, x1, w2, "PUSH")
            q.insert(0, t)
        elif name == "POP":
            tok_of[s] = q.pop(0) if q else None
        elif name in ("CAP_PUSH", "CAP_PUSH0"):
            k = 0 if name == "CAP_PUSH0" else w2
            if len(q) > k:
                t = q[k]
                c = newtok(s, x1, tokens[t]["val"], "CAP_PUSH k=%d" % k,
                           parent=t)
                q.insert(0, c)
        elif name == "CAP_SWAP":
            k = w2
            if len(q) > k:
                q[0], q[k] = q[k], q[0]
    def root(tok):
        """walk CAP_PUSH ancestry back to the PUSH that first created the
        value"""
        seen = set()
        while tok in tokens and tokens[tok].get("parent") is not None                 and tok not in seen:
            seen.add(tok)
            tok = tokens[tok]["parent"]
        return tok
    return tokens, tok_of, root


def emit_result(BLOG, step):
    """the value an EMIT at `step` pushed: it is the token head of the
    stream; approximate with the POP result that fed w3 just before."""
    return None


def _ancestry(tokens, tok):
    out, seen = [], set()
    while tok in tokens and tok not in seen:
        seen.add(tok)
        out.append((tokens[tok]["push_step"], tokens[tok]["via"]))
        tok = tokens[tok].get("parent")
    return out


# ==================================================================== report
def report(out, descs, sec, first, fsteps, tgt, main_emits):
    hist = build_index()
    tokens, tok_of, root_of = replay_queue(BLOG)
    lines = []

    def W(s=""):
        lines.append(s)

    pops = [(s, name, x1, w2) for (s, pc, name, x1, w2, ql, h) in BLOG
            if name == "POP"]
    pop_steps = [p[0] for p in pops]

    def last_pop_before(s):
        lo, hi, best = 0, len(pop_steps) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if pop_steps[mid] < s:
                best = pop_steps[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    per_byte = []
    for s, idx in fsteps:
        e = first[idx]
        byte = e[4] & 0xFF
        ps = last_pop_before(e[0])
        tok = tok_of.get(ps)
        info = {"idx": idx, "emit_step": s, "byte": "%02x" % byte,
                "emit_dword": "%08x" % e[4], "pop_step": ps}
        if tok is not None:
            t = tokens[tok]
            info.update({"token": tok, "token_val": "%08x" % t["val"],
                         "token_push_step": t["push_step"],
                         "token_via": t["via"]})
            sl = Slicer(hist, [400])
            info["w2_slice"] = sl.reg("w2", t["push_step"])
            info["leaves"] = sl.leaves
        # the two operand POPs of the extraction `lsr w2, w21, w0`:
        #   w21 <- POP (the 32-bit source word W)
        #   w0  <- POP (the byte shift S, one of 0/8/16/24)
        w2n = info.get("w2_slice") or {}
        chain = w2n.get("chain", []) or []
        w21n = next((c for c in chain if c.get("reg") == "w21"), None)
        shn = [c for c in chain
               if c.get("reg") == "w0" and c is not w21n]
        if shn and "val" in shn[-1]:
            info["shift"] = int(shn[-1]["val"], 16)
            sp = last_def(hist, "w0", shn[-1]["step"] + 1)
            if sp:
                info["S_pop_step"] = sp[0]
                st_ = tok_of.get(sp[0])
                if st_:
                    info["S_push_step"] = tokens[st_]["push_step"]
        if w21n:
            sub = (w21n.get("chain") or []) or (
                [w21n["src"]] if "src" in w21n else [])
            pop21 = sub[0] if sub else None
            if pop21 and pop21.get("asm", "").startswith("bl"):
                info["W"] = pop21.get("val")
                info["W_pop_step"] = pop21.get("step")
                wt = tok_of.get(pop21.get("step"))
                if wt:
                    info["W_push_step"] = tokens[wt]["push_step"]
                    info["W_via"] = tokens[wt]["via"]
                    sl2 = Slicer(hist, [400])
                    info["W_slice"] = sl2.reg("w2", tokens[wt]["push_step"])
                    # the masked source word: w21 of the `and w2, w0, w21`
                    wch = [c for c in (info["W_slice"] or {}).get("chain", [])
                           if c.get("reg") == "w21"]
                    if wch:
                        wn = wch[0]
                        sub = (wn.get("chain") or []) or (
                            [wn["src"]] if "src" in wn else [])
                        pop21 = sub[0] if sub else None
                        if pop21 and pop21.get("asm", "").startswith("bl"):
                            info["src_word"] = pop21.get("val")
                            info["src_word_pop_step"] = pop21.get("step")
                            stw = tok_of.get(pop21.get("step"))
                            if stw:
                                info["src_word_push_step"] = \
                                    tokens[stw]["push_step"]
                                rt = root_of(stw)
                                info["src_word_root_step"] = \
                                    tokens[rt]["push_step"]
                                info["src_word_root_via"] = tokens[rt]["via"]
                                info["src_word_ancestry"] = _ancestry(
                                    tokens, rt)
                        info["mask"] = next(
                            (c.get("val") for c in
                             (info["W_slice"] or {}).get("chain", [])
                             if c.get("reg") == "w0"), None)
        per_byte.append(info)

    out['per_byte'] = per_byte
    out['n_bl_ops'] = len(BLOG)
    out['lenq'] = [{"step": e[0], "sva": "%012x" % e[1], "n": e[2],
                    "val": None if e[3] is None else "%08x" % e[3],
                    "pc": "%#x" % e[4]} for e in LQ]
    with open('block_trace_lenq.txt', 'w', encoding='utf-8') as f:
        for e in LQ:
            f.write("%9d %012x n=%-6d val=%s pc=%#x" % (
                e[0], e[1], e[2],
                "--------" if e[3] is None else "%08x" % e[3], e[4]) + chr(10))
    # ---- verify the derived copy formula --------------------------
    # the record-assembly loop reads the source dwords with
    #   LENQ(MAIN, n)  for n = 19,18,...,11   (pc 0x11930c)
    src = {}
    for e in LQ:
        if e[4] == 0x11930c and e[3] is not None:
            src[e[2]] = e[3]
    if src:
        ns = sorted(src, reverse=True)
        out['copy_src_dwords'] = [{"n": n, "val": "%08x" % src[n]}
                                    for n in ns]
        be = lambda n: struct.pack(">I", src[n] & 0xFFFFFFFF)
        recon = be(11)[2:] + b"".join(be(n) for n in range(12, 19)) + be(19)[:2]
        out['block_reconstructed'] = recon.hex()
        out['block_formula_ok'] = (recon.hex() == out['block_hex'])
        # the full relation record[44 + 4j + i] = byte i of stream[11 + j]
        recbytes = bytes.fromhex(out["record_hex"])
        ok, bad = 0, []
        for j in range(0, 25):
            if (11 + j) not in src:
                continue
            for i in range(4):
                k = 44 + 4 * j + i
                if k >= 144:
                    continue
                if recbytes[k] == be(11 + j)[i]:
                    ok += 1
                else:
                    bad.append(k)
        out['record_tail_bytes_verified'] = ok
        out['record_tail_bytes_mismatch'] = bad
    out['op_hist'] = {}
    for (s, pc, name, x1, w2, ql, h) in BLOG:
        out['op_hist'][name] = out['op_hist'].get(name, 0) + 1

    # ---------------- text report ----------------
    W("# Queue/VM provenance of record[46:78)  (row 7, second=%d)" % sec)
    W("")
    W("block hex = %s" % out['block_hex'])
    W("full record = %s" % out['record_hex'])
    W("")
    W("## window %s, %d steps, %d bl-ops, histogram %s"
      % (out['window'], out['pass2']['reg_steps_logged'],
         len(BLOG), out['op_hist']))
    W("")
    W("## per-byte chain (EMIT <- POP <- PUSH <- register slice)")
    for pb in per_byte:
        W("")
        W("### idx=%d  emit@%d  byte=%s  emit_dword=%s"
          % (pb['idx'], pb['emit_step'], pb['byte'], pb['emit_dword']))
        W("  POP @%s -> token %s val=%s (pushed @%s via %s)"
          % (pb.get('pop_step'), pb.get('token'), pb.get('token_val'),
             pb.get('token_push_step'), pb.get('token_via')))
        if "W" in pb:
            W("  word W=%s  shift S=%s  -> byte %s   (W popped @%s, "
              "pushed @%s via %s)"
              % (pb["W"], pb.get("shift"), pb["byte"], pb.get("W_pop_step"),
                 pb.get("W_push_step"), pb.get("W_via")))
        if "src_word" in pb:
            W("    src dword = %s mask=%s (popped @%s, pushed @%s)"
              % (pb["src_word"], pb.get("mask"), pb.get("src_word_pop_step"),
                 pb.get("src_word_push_step")))
            W("      ancestry root PUSH @%s via %s  chain=%s"
              % (pb.get("src_word_root_step"), pb.get("src_word_root_via"),
                 pb.get("src_word_ancestry")))
        sl = pb.get('w2_slice')
        if sl:
            def show(nn, ind=3):
                if not isinstance(nn, dict):
                    W("  " * ind + str(nn))
                    return
                if "asm" not in nn:
                    W("  " * ind + "%-5s LEAF %s %s %s"
                      % (nn.get("reg", "?"), nn.get("leaf"),
                         nn.get("text", ""), ("at=%s" % nn["at"])
                         if "at" in nn else ""))
                    return
                W("  " * ind + "%-5s = %-8s @%d  %s"
                  % (nn["reg"], nn["val"], nn["step"], nn["asm"]))
                for c in nn.get("chain", []) or []:
                    show(c, ind + 1)
                if "src" in nn:
                    show(nn["src"], ind + 1)
            show(sl)
        for lv in pb.get('leaves', [])[:8]:
            W("  ! %s" % (lv,))

    with open('block_trace_slices.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")
    with open('block_trace_window.txt', 'w', encoding='utf-8') as f:
        for (st, pc, mnem, ops, ev) in STEP_LOG:
            f.write("%9d %08x %-8s %-32s %s\n" % (
                st, pc, mnem, ops,
                " ".join("%s:%s=%08x" % (k, n, v) for k, n, v in ev) or "."))
    with open('block_trace_blops.txt', 'w', encoding='utf-8') as f:
        for (st, pc, name, x1, w2, ql, h) in BLOG:
            f.write("%9d %08x %-10s q=%012x w2=%08x len=%d head=%s\n"
                    % (st, pc, name, x1, w2, ql, h))
    W("")
    W("wrote block_trace_slices.txt block_trace_window.txt "
      "block_trace_blops.txt")
    print("\n".join(lines[-6:]), flush=True)


if __name__ == "__main__":
    main()

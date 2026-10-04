"""state_walk.py — mechanical control-flow-unflattening walker for sub_8d6f4
(the region builder in libsigner.so, 0x8d6f4..0x95fc4).

The function is O-LLVM control-flow flattened with 64-bit tags assembled by
mov/movk. Two dispatch hubs:
  HUB_A 0x8d798:  mov x0, x6  ; chain of { token mat ; cmp x0, xT ; b.eq T }
                  -> state reg x0, source reg x6 (blocks set x6 then `b 0x8d798`)
  HUB_B 0x9579c:  mov x20, x0 ; chain of { token mat ; cmp x9/x8, xT ; b.eq T }
                  -> state reg x9 (blocks set x9 then `b 0x9579c`)

Chain entries whose b.eq goes back to the hub are ALIASES: the state source
reg is re-materialized in-chain and the state continues under the new tag.
Work-block ends materialize the next tag (sometimes via csel of two candidates
guarded by a flag test) and branch back to a hub.

Usage:
  python state_walk.py chain          # dump hub chains (token -> target edges)
  python state_walk.py walk           # ordered execution trace from entry tag
  python state_walk.py block 0xADDR   # dump one work block with annotation
  python state_walk.py all            # everything
"""
import sys, os, re, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB

START, END = 0x8D6F4, 0x95FC4
HUB_A, HUB_B = 0x8D798, 0x9579C
HUBS = (HUB_A, HUB_B)
SRC_A, SRC_B = "x6", "x9"          # state-source regs for hub A / hub B

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = False
insns = list(md.disasm(elf[START:END], START))
IDX = {i.address: k for k, i in enumerate(insns)}
assert len(insns) == (END - START) // 4

def T(s):
    return int(s.replace("#", "").strip(), 16)

# ---------------------------------------------------------------- constants
def mat_value(mnemonic, op_str, regs):
    """Return (dst, newval, partial_info) for mov/movz/movk or None."""
    if mnemonic == "mov":
        m = re.match(r"^(w|x)(\d+|zr|29|30)$", op_str.split(",")[0])
        parts = op_str.split(", ")
        if len(parts) == 2 and parts[1].startswith("#"):
            try:
                return parts[0], int(parts[1].lstrip("#"), 16), None
            except ValueError:
                return None
        if len(parts) == 2 and re.match(r"^[wx]\d+$|wzr|xzr", parts[1]):
            return parts[0], ("copy", parts[1]), None
    if mnemonic == "movz":
        parts = [p.strip() for p in op_str.split(",")]
        if parts[1].startswith("#"):
            sh = 0
            if len(parts) > 2 and "lsl" in parts[2]:
                sh = int(parts[2].split("#")[1])
            return parts[0], int(parts[1].lstrip("#"), 16) << sh, None
    if mnemonic == "movk":
        parts = [p.strip() for p in op_str.split(",")]
        if parts[1].startswith("#"):
            sh = 0
            if len(parts) > 2 and "lsl" in parts[2]:
                sh = int(parts[2].split("#")[1])
            return parts[0], int(parts[1].lstrip("#"), 16) << sh, ("movk", sh)
    return None

def apply(regs, dst, val, partial):
    if partial:                                   # movk merge
        cur = regs.get(dst, 0)
        if isinstance(cur, int):
            sh = partial[1]
            regs[dst] = (cur & ~(0xFFFF << sh)) | val
        else:
            regs[dst] = val
    else:
        if isinstance(val, tuple) and val[0] == "copy":
            src = val[1]
            if src in regs:
                regs[dst] = regs[src]
            else:
                regs.pop(dst, None)
        else:
            regs[dst] = val

# ---------------------------------------------------------------- hub chain
CHAIN_OK = {"mov", "movz", "movk", "cmp", "csel", "adrp", "add", "b", "b.eq",
            "b.ne", "b.lt", "b.le", "b.gt", "b.ge", "b.lo", "b.ls", "b.hi",
            "b.hs", "ubfx", "orr", "sbfiz", "ldr", "ldur", "nop"}

def parse_chain(hub, state_reg, src_reg, verbose=False):
    """Linearly walk a hub's compare chain. Returns edges:
    token -> list of (kind, target[, alias_token]) with kind in
    'work' (target is a work block), 'alias' (re-enters a hub), 'hubloop'."""
    edges = collections.defaultdict(list)
    regs = {}
    i = IDX[hub]
    pending_cmp = None
    seen_first = False
    while True:
        ins = insns[i]
        a = ins.address
        if ins.mnemonic in ("mov", "movz", "movk"):
            r = mat_value(ins.mnemonic, ins.op_str, regs)
            if r:
                apply(regs, r[0], r[1], r[2])
            # do not clear pending_cmp: cmp operand values are read at the
            # b.eq site; the state-src reg is re-materialized in between.
        elif ins.mnemonic == "cmp":
            pc = ins.op_str.replace(" ", "").split(",")
            pending_cmp = [pc, regs.get(pc[1]) if len(pc) > 1 else None]
        elif ins.mnemonic in ("ccmp", "ccmn"):
            # model: after `cmp x0,xC`, `ccmp x0,xB,#nzcv,cond`
            #  - cond true  -> flags = cmp(x0, xB)
            #  - cond false -> flags = nzcv
            # operand values are SNAPSHOTTED here (decoy moves may clobber the
            # registers before the b.eq)
            parts = ins.op_str.replace(" ", "").split(",")
            pending_cmp = [pending_cmp, parts, regs.get(parts[1]), ins.address]
        elif ins.mnemonic == "csel":
            # inside chains csel normally rewrites the state src (alias choices)
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) >= 3:
                regs[parts[0]] = ("csel", a, parts[1], parts[2])
            pending_cmp = None
        elif ins.mnemonic in ("b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
                              "b.lo", "b.ls", "b.hi", "b.hs"):
            tg = T(ins.op_str)
            if ins.mnemonic == "b.eq" and pending_cmp:
                pc = pending_cmp
                if isinstance(pc[0], list) and len(pc) == 4:
                    # stacked: [ [cmpA,cmpB], [ccmpA,ccmpB,nzcv,cond], tokBsnap, site ]
                    (cmpA, cmpC), (cA, cB, nzcv, cond), tokB, csite = pc
                    tokC = pc[0][1]
                    try:
                        nz = int(nzcv.lstrip("#"), 16)
                    except (ValueError, AttributeError):
                        nz = 0
                    zset = bool(nz & 4)
                    ne = (cond == "ne")
                    for tok in (tokC, tokB):
                        if isinstance(tok, int):
                            if tok is tokB or (tok is tokC and zset):
                                kind = "alias" if tg in HUBS else "work"
                                alias = None
                                if kind == "alias":
                                    ns = regs.get(src_reg if tg == HUB_A else SRC_B)
                                    alias = ns if isinstance(ns, int) else ("?", tg)
                                edges[tok].append((kind, tg, alias, csite))
                    pending_cmp = None
                elif isinstance(pc[0], list) and len(pc[0]) == 2:
                    cmpA, cmpB = pc[0]
                    tok = pc[1]
                    if isinstance(tok, int):
                        kind = "alias" if tg in HUBS else "work"
                        alias = None
                        if kind == "alias":
                            newstate = regs.get(src_reg if tg == HUB_A else SRC_B)
                            if tg == hub:
                                newstate = regs.get(src_reg if hub == HUB_A else SRC_B)
                            alias = newstate if isinstance(newstate, int) else ("?", a)
                        edges[tok].append((kind, tg, alias, a))
            pending_cmp = None
        elif ins.mnemonic == "b":
            tg = T(ins.op_str)
            if tg not in HUBS:
                edges[("__chainend__", a)] = [("chainend", tg, None, a)]
                break
            # unconditional back to a hub = end of chain fallthrough path
            edges[("__chainend__", a)] = [("hubfall", tg, None, a)]
            break
        elif ins.mnemonic in ("ret", "blr", "br"):
            edges[("__chainend__", a)] = [("chainend", ins.mnemonic, None, a)]
            break
        elif ins.mnemonic in ("ldr", "ldur", "adrp", "add", "nop", "ubfx",
                              "orr", "sbfiz", "mrs", "ldp", "stp", "stur",
                              "str", "movi", "fmov", "ldur", "sub", "umull",
                              "ubfiz", "extr", "rev", "rev32", "sxtw", "uxtw",
                              "cset", "csetm", "csinc", "csneg", "csinv",
                              "ldrsw", "ldrb", "strb", "mvn", "neg", "and",
                              "eon", "lsl", "lsr", "asr", "ror", "bic",
                              "madd", "msub", "sdiv", "udiv", "mul", "smull",
                              "tst", "adds", "subs", "ands", "bics", "orn"):
            if ins.mnemonic in ("ldr", "ldur", "ldrb", "ldrsw", "ldurh", "ldrsb"):
                parts = [p.strip() for p in ins.op_str.split(",")]
                regs.pop(parts[0], None)
            elif ins.mnemonic == "ldp":
                parts = [p.strip() for p in ins.op_str.split("[")[0].split(",")]
                for p in parts:
                    p = p.strip()
                    if re.match(r"^[wx]\d+$", p):
                        regs.pop(p, None)
            elif ins.mnemonic == "adrp":
                parts = [p.strip() for p in ins.op_str.split(",")]
                # capstone gives page addr in op_str second part
                try:
                    regs[parts[0]] = int(parts[1], 16)
                except ValueError:
                    regs.pop(parts[0], None)
            elif ins.mnemonic == "add":
                parts = [p.strip() for p in ins.op_str.split(",")]
                if len(parts) == 3 and parts[2].startswith("#"):
                    base = regs.get(parts[1])
                    try:
                        imm = int(parts[2].lstrip("#"), 16)
                    except ValueError:
                        imm = None
                    if isinstance(base, int) and imm is not None:
                        regs[parts[0]] = base + imm
                    else:
                        regs.pop(parts[0], None)
            elif ins.mnemonic == "mrs":
                parts = [p.strip() for p in ins.op_str.split(",")]
                regs.pop(parts[0], None)
        else:
            edges[("__chainend__", a)] = [("chainend", ins.mnemonic, None, a)]
            break
        i += 1
        if i >= len(insns):
            break
    return edges

def parse_block(start, limit=400):
    """Walk a work block from `start` to its terminating branch/ret.
    Returns dict with notes: calls, mem ops, xor ops, next-tag candidates."""
    notes = {"start": start, "calls": [], "mem": [], "xors": [], "csel": [],
             "end": None, "end_kind": None, "tags": [], "branches": []}
    regs = {}
    i = IDX[start]
    n = 0
    while i < len(insns) and n < limit:
        ins = insns[i]
        a = ins.address
        n += 1
        if ins.mnemonic in ("mov", "movz", "movk"):
            r = mat_value(ins.mnemonic, ins.op_str, regs)
            if r:
                apply(regs, r[0], r[1], r[2])
        elif ins.mnemonic == "cmp":
            pass
        elif ins.mnemonic == "csel":
            notes["csel"].append((a, ins.op_str))
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) >= 3:
                regs[parts[0]] = ("csel", a, parts[1], parts[2])
        elif ins.mnemonic == "bl":
            notes["calls"].append((a, T(ins.op_str)))
        elif ins.mnemonic == "blr":
            notes["calls"].append((a, "blr"))
        elif ins.mnemonic in ("b",):
            notes["end"] = T(ins.op_str)
            notes["end_kind"] = "b"
            notes["tags"] = extract_tag(regs, notes["end"])
            break
        elif ins.mnemonic == "ret":
            notes["end"] = a
            notes["end_kind"] = "ret"
            break
        elif ins.mnemonic.startswith("b.") or ins.mnemonic in ("cbz", "cbnz",
                                                               "tbz", "tbnz"):
            tg = T(ins.op_str.split(",")[-1])
            notes["branches"].append((a, ins.mnemonic, tg))
        elif ins.mnemonic in ("str", "stur", "strb", "strh", "stlr", "stnp",
                              "stp", "ldr", "ldur", "ldrb", "ldrh", "ldurh",
                              "ldrsb", "ldrsb", "ldrsw", "ldp", "ldnp"):
            notes["mem"].append((a, ins.mnemonic, ins.op_str))
        elif ins.mnemonic in ("eor", "add", "sub", "mul", "and", "orr", "mvn",
                              "lsl", "lsr", "asr", "ror", "neg", "bic", "eon",
                              "madd", "msub", "ubfx", "sbfx", "sbfiz", "ubfiz",
                              "extr", "rev", "rev32", "rev16", "clz", "rbit",
                              "smull", "umull", "sdiv", "udiv", "madd", "sxtw",
                              "uxtw", "slt", "cset", "csetm", "csinc", "csneg",
                              "csinv", "adrp", "tst", "adds", "subs", "ands",
                              "orns", "eon", "bics", "nop", "fmov", "scvtf",
                              "mrs", "msr", "dmb", "isb", "dsb", "ldrsw"):
            if ins.mnemonic in ("eor", "eon"):
                notes["xors"].append((a, ins.op_str))
        if ins.mnemonic in ("eor",):
            pass
        i += 1
    else:
        notes["end"] = insns[i - 1].address
        notes["end_kind"] = "fallthrough?"
    return notes

def extract_tag(regs, end):
    """Tags materialized for hub dispatch: values of x6 (A) and x9 (B)."""
    out = []
    for r, v in regs.items():
        if r in (SRC_A, SRC_B) and isinstance(v, int):
            out.append((r, v))
        elif r in (SRC_A, SRC_B) and isinstance(v, tuple) and v[0] == "csel":
            out.append((r, ("csel",) + v[1:]))
    return out

# ---------------------------------------------------------------- CLI
def fmt_tok(t):
    return "0x%016x" % t if isinstance(t, int) else str(t)

def show_chain(hub, state_reg, src_reg):
    edges = parse_chain(hub, state_reg, src_reg)
    print("=== HUB 0x%x (state %s, src %s): %d tokens ===" %
          (hub, state_reg, src_reg, len([k for k in edges if isinstance(k, int)])))
    for tok in sorted((k for k in edges if isinstance(k, int))):
        for kind, tg, alias, site in edges[tok]:
            if kind == "work":
                print("  token %s -> work 0x%x  (cmp site 0x%x)" % (fmt_tok(tok), tg, site))
            elif kind == "alias":
                print("  token %s -> ALIAS new=%s -> hub 0x%x (site 0x%x)" %
                      (fmt_tok(tok), fmt_tok(alias) if not isinstance(alias, tuple) else alias, tg, site))
    for k, v in edges.items():
        if not isinstance(k, int):
            print("  chain end at 0x%x: %s" % (k[1], v))
    return edges

# ================================================================ WALK ENGINE
# Symbolic values: ("imm", v) | ("arg", n) | ("ctx",) | ("ctxo", off) |
#                  ("fr", off) = address x29-off | ("glob", addr) |
#                  ("memc", off) = ctx+off value | ("sel", site, v1, v2, guard)
# Mach carries regs + frame-slot memory (the obfuscator spills tag candidates
# into [x29-0xNN] slots and reloads them at shared tails).
SLOTS = {0x118: ("arg", 0), 0x120: ("ctx",), 0x5A0: ("arg", 1),
         0x5A8: ("ctxo", 0x64), 0x5B0: ("ctxo", 0x60)}

def sym_str(s):
    try:
        return _sym_str(s)
    except Exception:
        return "sym?%r" % (s,)

def _sym_str(s):
    if s is None:
        return "?"
    k = s[0]
    if k == "imm":
        return "#0x%x" % s[1]
    if k == "arg":
        return "arg%d" % s[1]
    if k == "ctx":
        return "ctx"
    if k == "ctxo":
        return "&ctx+0x%x" % s[1]
    if k == "fr":
        return "[x29-0x%x]" % s[1] if s[1] >= 0 else "[x29+0x%x]" % -s[1]
    if k == "glob":
        return "g_0x%x" % s[1]
    if k == "memc":
        return "MEM[ctx+0x%x]" % s[1]
    if k == "sel":
        return "sel@0x%x(%s | %s)" % (s[1], sym_str(s[2]), sym_str(s[3]))
    return "unk:%r" % (s,)

def is_x(r):
    return bool(re.match(r"^[xw]\d+$", r) or r in ("xzr", "wzr"))

class Mach:
    def __init__(self):
        self.r = {}
        self.mem = dict(SLOTS)      # frame-slot offset (x29-off) -> value
    def get(self, reg):
        return self.r.get(reg)
    def set(self, reg, v):
        if reg in ("xzr", "wzr", "sp"):
            return
        if reg.startswith("w"):
            self.r["x" + reg[1:]] = v
        self.r[reg] = v
    def clobber_caller(self):
        for i in range(19):
            self.r.pop("x%d" % i, None)
        for p in ("v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
                  "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17",
                  "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25",
                  "v26", "v27", "v28", "v29", "v30", "v31"):
            self.r.pop(p, None)

def membase(mach, memstr):
    m = re.match(r"\[(x\d+|sp)(?:,\s*#(-?0x[0-9a-f]+))?\]!?$", memstr.strip())
    if not m:
        return None
    base = mach.get(m.group(1))
    off = int(m.group(2), 16) if m.group(2) else 0
    return (base, off)

def slotoff(base, off):
    """Return frame-slot key (x29 - eff) if base is x29-derived, else None."""
    if isinstance(base, tuple) and base[0] == "fr":
        return base[1] - off          # address = x29 - (base[1]-off)
    return None

def ctxoff(base, off):
    if not isinstance(base, tuple):
        return None
    if base[0] == "ctx":
        return off
    if base[0] == "ctxo":
        return base[1] + off
    if base[0] == "memc":
        return base[1] + off
    return None

CTX_STORES = []                       # global: (site, eff, mnemonic, valsym)

def block_exec(start, mach, notes, depth=0, guard=None):
    """Symbolically execute a work block (following tail b links) until hub/ret."""
    i = IDX[start]
    n = 0
    while i < len(insns) and n < 900:
        ins = insns[i]; a = ins.address; n += 1
        mn, ops = ins.mnemonic, ins.op_str
        if mn in ("mov", "movz", "movk"):
            r = mat_value(mn, ops, {})
            if r:
                dst, val, partial = r
                if partial:
                    cur = mach.get(dst)
                    if isinstance(cur, tuple) and cur[0] == "imm":
                        sh = partial[1]
                        mach.set(dst, ("imm", (cur[1] & ~(0xFFFF << sh)) | val))
                    else:
                        mach.set(dst, None)
                elif isinstance(val, tuple) and val[0] == "copy":
                    mach.set(dst, mach.get(val[1]))
                elif is_x(dst):
                    mach.set(dst, ("imm", val))
                else:
                    mach.set(dst, None)
            else:
                parts = [p.strip() for p in ops.split(",")]
                if parts and not is_x(parts[0]):
                    notes.append((a, "%s %s" % (mn, ops)))
                    mach.set(parts[0], None)
        elif mn == "movi":
            notes.append((a, "vec-key %s" % ops))
        elif mn in ("cmp", "tst"):
            guard = (a, "%s %s" % (mn, ops))
        elif mn in ("adds", "subs", "ands", "bics"):
            guard = (a, "%s %s" % (mn, ops))
            parts = [p.strip() for p in ops.split(",")]
            if parts[0].startswith(("x", "w")):
                mach.set(parts[0], None)
        elif mn in ("cbz", "cbnz", "tbz", "tbnz"):
            guard = (a, "%s %s" % (mn, ops))
            notes.append((a, "COND %s %s -> %s" % (mn, ops, ops.split(",")[-1].strip())))
        elif mn == "cset" or mn == "csetm":
            dst = ops.split(",")[0].strip()
            mach.set(dst, ("imm", 1 if mn == "cset" else (-1 & 0xFFFFFFFFFFFFFFFF)))
        elif mn in ("csel", "csinc", "csinv", "csneg"):
            parts = [p.strip() for p in ops.split(",")]
            cc = parts[3] if len(parts) > 3 else ""
            mach.set(parts[0], ("sel", a, mach.get(parts[1]), mach.get(parts[2]), guard, cc))
        elif mn in ("add", "sub"):
            parts = [p.strip() for p in ops.split(",")]
            dst, src = parts[0], parts[1]
            base = mach.get(src)
            imm = None
            if len(parts) >= 3 and parts[2].startswith("#"):
                try:
                    imm = int(parts[2].lstrip("#"), 16)
                except ValueError:
                    imm = None
            out = None
            if isinstance(base, tuple) and imm is not None:
                if base[0] == "imm":
                    out = ("imm", base[1] + imm if mn == "add" else base[1] - imm)
                elif base[0] == "ctx" and mn == "add":
                    out = ("ctxo", imm)
                elif base[0] == "ctxo" and mn == "add":
                    out = ("ctxo", base[1] + imm)
                elif base[0] == "fr":
                    out = ("fr", base[1] + imm if mn == "sub" else base[1] - imm)
                elif base[0] == "glob":
                    out = ("glob", base[1] + imm)
            elif isinstance(base, tuple) and base[0] == "imm" and imm is None:
                out = base
            mach.set(dst, out)
        elif mn in ("adrp", "adr"):
            parts = [p.strip() for p in ops.split(",")]
            try:
                mach.set(parts[0], ("glob", int(parts[1].lstrip("#"), 16)))
            except ValueError:
                mach.set(parts[0], None)
        elif mn in ("ldr", "ldur", "ldrb", "ldrh", "ldrsw", "ldursb", "ldurh",
                    "ldrsb", "ld1"):
            parts = [p.strip() for p in ops.split(",", 1)]
            dst = parts[0]
            mb = membase(mach, parts[1]) if len(parts) > 1 else None
            handled = False
            if mb:
                base, off = mb
                sk = slotoff(base, off)
                if sk is not None:
                    v = mach.mem.get(sk)
                    if v is None:
                        notes.append((a, "load %s <- [x29%+#x] (UNKNOWN slot)" % (dst, -sk)))
                    mach.set(dst, v)
                    handled = True
                elif ctxoff(base, off) is not None:
                    eff = ctxoff(base, off)
                    notes.append((a, "load %s = ctx+0x%x" % (dst, eff)))
                    mach.set(dst, ("memc", eff))
                    handled = True
                elif isinstance(base, tuple) and base[0] == "glob":
                    notes.append((a, "load %s = [g_0x%x%+#x]" % (dst, base[1], off)))
                    mach.set(dst, ("mem", (("glob", base[1]), off)))
                    handled = True
            if not handled:
                mach.set(dst, None)
        elif mn in ("str", "stur", "strb", "strh", "stlr", "sturh"):
            parts = [p.strip() for p in ops.split(",", 1)]
            srcv = mach.get(parts[0])
            mb = membase(mach, parts[1]) if len(parts) > 1 else None
            if mb:
                base, off = mb
                sk = slotoff(base, off)
                if sk is not None:
                    mach.mem[sk] = srcv
                    notes.append((a, "SPILL %s=%s -> [x29%+#x]" % (parts[0], sym_str(srcv), -sk)))
                elif ctxoff(base, off) is not None:
                    eff = ctxoff(base, off)
                    notes.append((a, "*** CTX[0x%x] = %s   (%s %s)" % (eff, sym_str(srcv), mn, parts[0])))
                    CTX_STORES.append((a, eff, mn, sym_str(srcv)))
                elif isinstance(base, tuple) and base[0] == "glob":
                    notes.append((a, "store %s -> [g_0x%x%+#x] (val=%s)" % (parts[0], base[1], off, sym_str(srcv))))
                elif isinstance(base, tuple) and base[0] == "mem":
                    notes.append((a, "store(cplx) %s %s (val=%s)" % (mn, ops, sym_str(srcv))))
            else:
                notes.append((a, "store(cplx) %s %s (val=%s)" % (mn, ops, sym_str(srcv))))
        elif mn in ("stp", "stnp"):
            head = ops.split("[")[0]
            regs2 = [p.strip() for p in head.split(",")]
            mb = membase(mach, "[" + ops.split("[", 1)[1])
            if mb:
                base, off = mb
                sk = slotoff(base, off)
                v1 = mach.get(regs2[0]) if len(regs2) > 0 else None
                v2 = mach.get(regs2[1]) if len(regs2) > 1 else None
                if sk is not None:
                    stride = 4 if regs2 and regs2[0].startswith("w") else 8
                    mach.mem[sk] = v1
                    mach.mem[sk - stride] = v2
                    notes.append((a, "SPILL %s=%s, %s=%s -> [x29%+#x,%+#x]" %
                                  (regs2[0], sym_str(v1), regs2[1], sym_str(v2), -sk, -(sk - 8))))
                else:
                    eff = ctxoff(base, off)
                    if eff is not None:
                        notes.append((a, "*** CTX[0x%x..0x%x] = %s, %s (stp)" % (eff, eff + 16, regs2[0], regs2[1])))
                        CTX_STORES.append((a, eff, "stp", "%s,%s" % (sym_str(v1), sym_str(v2))))
                    elif isinstance(base, tuple) and base[0] == "glob":
                        notes.append((a, "stp %s,%s -> [g_0x%x%+#x]" % (regs2[0], regs2[1], base[1], off)))
                    elif isinstance(base, tuple) and base[0] == "mem":
                        notes.append((a, "stp(cplx) %s" % ops))
            else:
                notes.append((a, "stp(cplx) %s" % ops))
        elif mn in ("ldp", "ldnp"):
            head = ops.split("[")[0]
            regs2 = [p.strip() for p in head.split(",") if re.match(r"^[wx]\d+$", p.strip())]
            mb = membase(mach, "[" + ops.split("[", 1)[1])
            if mb and len(regs2) == 2:
                base, off = mb
                sk = slotoff(base, off)
                if sk is not None:
                    mach.set(regs2[0], mach.mem.get(sk))
                    mach.set(regs2[1], mach.mem.get(sk - 8))
                else:
                    mach.set(regs2[0], None)
                    mach.set(regs2[1], None)
        elif mn in ("eor", "eon"):
            parts = [p.strip() for p in ops.split(",")]
            notes.append((a, "EOR %s  (%s ^ %s)" % (ops, sym_str(mach.get(parts[1])),
                          sym_str(mach.get(parts[2]) if len(parts) > 2 else None))))
            mach.set(parts[0], None)
        elif mn in ("and", "orr", "orn", "bic", "mul", "madd", "msub", "lsl",
                    "lsr", "asr", "ror", "ubfx", "sbfiz", "ubfiz", "extr",
                    "rev", "rev32", "rev16", "rbit", "clz", "sdiv", "udiv",
                    "smull", "umull", "sxtw", "uxtw", "sbfx"):
            if "," in ops:
                parts = [p.strip() for p in ops.split(",")]
                mach.set(parts[0], None)
        elif mn == "b":
            tg = T(ops)
            if tg in HUBS:
                return ("hub", tg, collect_tags(mach))
            if depth < 8:
                return block_exec(tg, mach, notes, depth + 1, guard)
            return ("tail?", tg, collect_tags(mach))
        elif mn == "ret":
            return ("ret", a, collect_tags(mach))
        elif mn == "bl":
            tg = T(ops)
            notes.append((a, "CALL 0x%x" % tg))
            mach.clobber_caller()
        elif mn in ("blr", "br"):
            tgt = mach.get(ops.strip())
            notes.append((a, "CALL* %s" % (sym_str(tgt) if tgt else ops)))
            mach.clobber_caller()
        elif mn.startswith("b."):
            tg = T(ops)
            notes.append((a, "COND %s %s -> 0x%x" % (mn, ops, tg)))
        elif mn in ("nop", "mrs", "msr", "dmb", "isb", "dsb", "fmov", "scvtf",
                    "stlrb", "ldarb", "staddb", "casb", "casa", "stadd",
                    "ldaxrb", "stlxrb", "stxr", "ldaxr", "stlxr", "ldxr", "dmb"):
            pass
        else:
            notes.append((a, "? %s %s" % (mn, ops)))
        i += 1
    return ("maxlen", insns[i - 1].address if i > 0 else start, collect_tags(mach))

def collect_tags(mach):
    out = []
    for r in (SRC_A, SRC_B):
        v = mach.get(r)
        if isinstance(v, bool):
            v = ("imm", int(v))
        elif isinstance(v, int):
            v = ("imm", v & 0xFFFFFFFFFFFFFFFF)
        out.append((r, v))
    return out

def resolve_aliases(edges, maxd=16):
    table = {}
    def resolve(tok, d=0):
        if d > maxd:
            return ("loop", tok)
        es = edges.get(tok)
        if not es:
            return ("nomatch", tok)
        kind, tg, alias, site = es[0]
        if kind == "work":
            return ("work", tg)
        if kind == "alias":
            if isinstance(alias, int):
                return resolve(alias, d + 1)
            return ("alias?", site)
        return ("other", kind)
    for tok in edges:
        if isinstance(tok, int):
            table[tok] = resolve(tok)
    return table

# ================================================================ DRIVER 2
ENTRY_TAG = 0xCDB13B067E1DEE4A      # x6 materialized in the prologue

def build():
    ea = parse_chain(HUB_A, "x0", SRC_A)
    eb = parse_chain(HUB_B, "x9", SRC_B)
    ta = resolve_aliases(ea)
    tb = resolve_aliases(eb)
    return ea, eb, ta, tb

def tag_block(tag, ta, tb):
    if tag in ta:
        return ("A",) + ta[tag]
    if tag in tb:
        return ("B",) + tb[tag]
    return (None, "nomatch", None)

def run_walk2(log=print, max_states=500):
    ea, eb, ta, tb = build()
    mach = Mach()
    mach.set("x29", ("fr", 0))
    mach.set("x0", ("arg", 0)); mach.set("x1", ("arg", 1))
    mach.set("x2", ("ctx",));   mach.set("x3", ("arg", 3))
    state = {"n": 0, "emitted": set(), "halt": False}
    path = []

    def walk(tag, depth):
        if state["halt"]:
            return
        if depth > 400:
            log("  [depth limit at 0x%016x]" % tag)
            return
        if len(state["emitted"]) > max_states:
            log("  [state cap hit]")
            state["halt"] = True
            return
        state["n"] += 1
        step = state["n"]
        hubkind, kind, target = tag_block(tag, ta, tb)
        fresh = tag not in state["emitted"]
        log("")
        if fresh:
            state["emitted"].add(tag)
            log("### STEP %d  state=0x%016x  (hub %s) -> %s" % (step, tag, hubkind, (kind, hex(target) if isinstance(target, int) else target)))
        elif state["emitted"].count(tag) if False else True:
            # allow one re-execution (different incoming path), then treat as loop
            if state.get("revisits", {}).get(tag, 0) >= 1:
                log("### (revisit %d) state=0x%016x  [loop - stop]" % (step, tag))
                return
            state.setdefault("revisits", {})[tag] = state.get("revisits", {}).get(tag, 0) + 1
            log("### STEP %d  state=0x%016x  (hub %s) -> %s  [REVISITED via other path]" % (step, tag, hubkind, (kind, hex(target) if isinstance(target, int) else target)))
        if kind != "work" or not isinstance(target, int):
            log("  [default/nomatch -> %s]" % (("0x%x" % target) if isinstance(target, int) else target))
            if hubkind == "A" and kind == "nomatch":
                walk(0x95124, depth + 1)   # hub A default block
            return
        notes = []
        end_kind, end_t, tags = block_exec(target, mach, notes)
        for a, t in notes:
            log("  0x%x  %s" % (a, t))
        log("  [block 0x%x end=%s]" % (target, end_kind))
        if end_kind == "ret":
            log("  *** RETURN ***")
            return
        if not tags:
            log("  [no tags]")
            return
        want = SRC_A if (end_kind == "hub" and end_t == HUB_A) else SRC_B
        tags = [(r, v) for r, v in tags if r == want]
        for r, v in tags:
            if isinstance(v, tuple) and len(v) > 1 and v[0] == "sel":
                _, site, v1, v2, g, cc = (list(v) + [""] * 6)[:6]
                gtxt = "%s @0x%x" % (g[1], g[0]) if g else "(carried flags)"
                log("  BRANCH @0x%x cc=%s guard=%s" % (site, cc, gtxt))
                log("    cond-true  -> %s" % sym_str(v1))
                log("    cond-false -> %s" % sym_str(v2))
                for vi in (v1, v2):
                    if isinstance(vi, tuple) and len(vi) > 1 and vi[0] == "imm":
                        walk(vi[1], depth + 1)
                    else:
                        log("    [arm unresolved: %s]" % sym_str(vi))
            elif isinstance(v, tuple) and len(v) > 1 and v[0] == "imm":
                nxt = v[1]
                log("  NEXT -> state 0x%016x%s" % (nxt, "  [LOOP]" if nxt in state["emitted"] else ""))
                walk(nxt, depth + 1)
            elif v is None:
                log("  [next tag lost - spill/reload gap]")
            else:
                log("  [next tag odd: %s]" % sym_str(v))
    walk(ENTRY_TAG, 0)
    return state["emitted"]

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "walk"
    if cmd == "chain":
        show_chain(HUB_A, "x0", SRC_A)
        show_chain(HUB_B, "x9", SRC_B)
    elif cmd in ("walk", "all"):
        run_walk2()
    elif cmd == "block":
        notes = []
        m = Mach(); m.set("x29", ("fr", 0))
        m.set("x0", ("arg", 0)); m.set("x1", ("arg", 1)); m.set("x2", ("ctx",)); m.set("x3", ("arg", 3))
        print(block_exec(T(sys.argv[2]), m, notes))
        for a, t in notes:
            print("  0x%x  %s" % (a, t))

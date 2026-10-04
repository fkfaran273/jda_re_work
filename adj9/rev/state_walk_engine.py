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
            mach.set(parts[0], ("sel", a, mach.get(parts[1]), mach.get(parts[2]), guard))
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
                    mach.mem[sk] = v1
                    mach.mem[sk - 8] = v2
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

                elif isinstance(base, tuple) and base[0] == "mem":
                    eff = base[1][1] + off
                    notes.append((a, "*** ctx[0x%x..] = %s, %s (stp)" % (eff, regs2[0], regs2[1])))
            if mn == "ldp":
                head = ops.split("[")[0]
                for rp in head.split(","):
                    rp = rp.strip()
                    if re.match(r"^[wx]\d+$", rp):
                        mach.set(rp, None)
        elif mn == "eor" or mn == "eon":
            parts = [p.strip() for p in ops.split(",")]
            notes.append((a, "eor %s   (%s=%s^%s)" % (ops, parts[0],
                          sym_str(mach.get(parts[1])), sym_str(mach.get(parts[2]) if len(parts) > 2 else None))))
            mach.set(parts[0], None)
        elif mn in ("b",):
            tg = T(ops)
            if tg in HUBS:
                return ("hub", tg, collect_tags(mach))
            if depth < 6:
                return block_exec(tg, mach, notes, depth + 1)
            return ("tail?", tg, collect_tags(mach))
        elif mn == "ret":
            return ("ret", a, collect_tags(mach))
        elif mn in ("blr", "br"):
            tgt = mach.get(ops.strip())
            notes.append((a, "CALL* %s" % (sym_str(tgt) if tgt else ops)))
            mach.clobber_caller()
        elif mn == "bl":
            tg = T(ops)
            notes.append((a, "CALL 0x%x" % tg))
            mach.clobber_caller()
        elif mn in ("cbz", "cbnz", "tbz", "tbnz"):
            tg = T(ops.split(",")[-1])
            guard = (a, "%s %s" % (mn, ops))
            notes.append((a, "COND %s %s -> 0x%x" % (mn, ops, tg)))
            i += 1
            continue
        elif mn.startswith("b."):
            tg = T(ops)
            notes.append((a, "COND %s %s -> 0x%x" % (mn, ops, tg)))
            i += 1
            continue
        elif mn in ("nop", "mrs", "msr", "dmb", "isb", "dsb", "fmov", "scvtf",
                    "madd", "msub", "mul", "and", "orr", "orn", "bic", "mvn",
                    "neg", "lsl", "lsr", "asr", "ror", "ubfx", "sbfiz", "ubfiz",
                    "extr", "rev", "rev32", "rev16", "rbit", "clz", "sdiv",
                    "udiv", "smull", "umull", "adds", "subs", "ands", "bics",
                    "ccmp", "ccmn", "fmov", "fneg"):
            if mn in ("lsl", "lsr", "asr", "ror", "rev", "rev32", "rev16",
                      "rbit", "mvn", "neg", "clz", "ubfx", "sbfiz", "ubfiz",
                      "extr", "sxtw", "uxtw") and "," in ops:
                parts = [p.strip() for p in ops.split(",")]
                mach.set(parts[0], None)
            if mn in ("adds", "subs", "ands", "bics", "tst", "cmp"):
                last_flag_ins = a
            i += 1
            continue
        else:
            notes.append((a, "? %s %s" % (mn, ops)))
            i += 1
            continue
        i += 1
    return ("maxlen", insns[i-1].address if i else start, collect_tags(mach))

def collect_tags(mach):
    out = []
    for r in (SRC_A, SRC_B):
        v = mach.get(r)
        if isinstance(v, tuple) and v[0] == "imm":
            out.append((r, v[1]))
        elif isinstance(v, tuple) and v[0] == "sel":
            _, a, t1, t2, guard = v
            v1 = mach.get(t1); v2 = mach.get(t2)
            out.append((r, ("sel", a, v1, v2, guard)))
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

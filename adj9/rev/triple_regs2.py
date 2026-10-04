# triple_regs2.py - reconstruct the per-value (kind) triple bound at function entry
# into x26/x27/x28 for the SECOND field group (0xdae88-0xdaeac). The lower half of
# each u64 is the VA-table index the nSign frame jumps through.
import re

s = open("nsign_fn.log", encoding="utf-8", errors="replace").read()
lines = s.splitlines()
regs = {}


def feed(a0, a1):
    pat = re.compile(r"0x([0-9a-f]+)\s+(mov|movk|movz)\s+(x\d+),\s*#\s*(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?")
    for ln in lines:
        m = pat.match(ln)
        if not m:
            continue
        a = int(m.group(1), 16)
        if not (a0 <= a <= a1):
            continue
        r, v, sh = m.group(3), int(m.group(4), 16), int(m.group(5) or 0)
        cur = regs.get(r, 0)
        # mov resets, movk merges
        text = ln
        if "movk" in text:
            mask = ~(0xFFFF << sh) & 0xFFFFFFFFFFFFFFFF
            regs[r] = ((cur & mask) | ((v & 0xFFFF) << sh)) & 0xFFFFFFFFFFFFFFFF
        else:
            regs[r] = v


feed(0xDAE88, 0xDAEAC)
# the group only builds the HIGH 48 bits; low 16 came from the mov at 0xdae88-equivalent
for r in ("x26", "x27", "x28"):
    print("%s = %s" % (r, hex(regs.get(r, 0))))
print("done")
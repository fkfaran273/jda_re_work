"""One-shot mechanical rewrite of the cold Ex.run register accesses.

Only touches adj9_signature.py.  Converts  X.R.get("xN", 0)  ->  X.RL[N]  (and
the w/sp forms) plus the handful of direct  R["w0"]= / R["x0"]=  writes into
paired RL/WL stores, so the legacy non-fast path keeps working after the
register file became two lists.
"""
import io
import os
import re
import sys

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "adj9_signature.py")

with io.open(PATH, encoding="utf-8") as fh:
    src = fh.read()

n_before = len(src)

# X.R.get("xN", 0) / X.R.get("wN") / X.R.get("sp", 0)  -> list index
pat = re.compile(r'\b(self|w)\.R\.get\("(x|w)(\d+)"(?:,\s*0)?\)')


def sub(m):
    obj, kind, num = m.group(1), m.group(2), m.group(3)
    lst = "RL" if kind == "x" else "WL"
    return "%s.%s[%s]" % (obj, lst, num)


src, a = pat.subn(sub, src)

src, b = re.subn(r'\b(self|w)\.R\.get\("sp", 0\)', r"\1.RL[SP]", src)

# X.R.get("x%d" % n, 0)  ->  X.RL[n]
src, c = re.subn(r'\b(self|w)\.R\.get\("x%d" % ([a-z])% n, 0\)',
                 r"\1.RL[\2]", src)

# mrs: R[dest] = 0x1000  ->  set_reg(dest, 0x1000) semantics via the setter
src, d = re.subn(r'\b(self|R)\[(ops\.split\(","\)\[0\]\.strip\(\))\]\s*=\s*0x1000',
                 r'\1.set_reg(\2, 0x1000)', src)

with io.open(PATH, "w", encoding="utf-8", newline="") as fh:
    fh.write(src)

print("rewrites: x/w/sp get=%d, sp=%d, loop=%d, mrs=%d" % (a, b, c, d))

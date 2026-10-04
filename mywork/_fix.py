"""_fix.py — one-shot repair of diff_paired.py stray/duplicated lines."""
import ast
import os

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diff_paired.py")
lines = open(P, encoding="utf-8").read().splitlines(keepends=True)

# 1) drop the duplicated 'cap: %r' print (two identical adjacent lines)
dup = 'print("     cap: %r" % cap10u[max(0, i - 24):i + 60])'
hits = [i for i, l in enumerate(lines) if l.strip() == dup]
for i in reversed(hits[1:]):
    del lines[i]
print("duplicate 'cap:' prints: %d found, %d removed" % (len(hits), len(hits) - 1))

# 2) drop the stray 'return status, ...' left after the __main__ block
guard = next(i for i, l in enumerate(lines) if l.startswith("if __name__ =="))
for i in range(len(lines) - 1, guard, -1):
    if lines[i].strip().startswith("return status"):
        del lines[i]
        print("removed stray return after __main__ (was line %d)" % (i + 1))

src = "".join(lines)
ast.parse(src)
open(P, "w", encoding="utf-8").writelines(lines)
print("OK — syntax valid, %d lines" % len(src.splitlines()))

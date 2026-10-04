"""ks_table2.py - FIXED keystream extractor for sub_9afa4.

Fix vs ks_table.py: eor sites use `w` registers (low 32 bits of the
tracked `x` constants). ks_table.py only matched `t == "x"` operands
and found 0 keys.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

DIS = os.path.join(HERE, "fn_9afa4_full.log")
lines = open(DIS, encoding="utf-8", errors="replace").read().splitlines()
print("disasm lines: %d" % len(lines))

RXV = re.compile(r"^(0x[0-9a-f]+)\s+(\S+)\s*(.*)$")
WREG = re.compile(r"^([wx])(\d+)$")


def regno(r):
    m = WREG.match(r.strip())
    if not m:
        return None, None
    return (m.group(1), int(m.group(2)))


consts = {}
insns = []
for ln in lines:
    m = RXV.match(ln.strip())
    if not m:
        continue
    va = int(m.group(1), 16)
    mn = m.group(2)
    ops = [o.strip() for o in m.group(3).split(",")] if m.group(3) else []
    insns.append((va, mn, ops))
print("insns parsed: %d" % len(insns))

scalar_eor = []
vector_eor = []
stores_q = []
stores_w = []
stores_x = []

for va, mn, ops in insns:
    if mn == "mov" and len(ops) == 2 and ops[1].startswith("#"):
        t, tn = regno(ops[0])
        if t == "x":
            try:
                consts[tn] = int(ops[1][1:], 0) & 0xFFFFFFFFFFFFFFFF
            except ValueError:
                pass
    elif mn == "movk" and len(ops) >= 2 and ops[1].startswith("#"):
        t, tn = regno(ops[0])
        if t == "x":
            try:
                imm = int(ops[1][1:], 0)
            except ValueError:
                continue
            sh = 0
            if len(ops) == 3 and "lsl" in ops[2]:
                sh = int(ops[2].split("#")[1])
            base = consts.get(tn, 0)
            base &= ~(0xFFFF << sh)
            base |= (imm & 0xFFFF) << sh
            consts[tn] = base & 0xFFFFFFFFFFFFFFFF
    elif mn in ("eor", "eor3") and len(ops) == 3:
        dt, dn = regno(ops[0])
        kt, kn = regno(ops[2])
        if dt in ("w", "x") and dn is not None and kt in ("w", "x") and kn is not None:
            keyval = None
            if kn in consts:
                full = consts[kn]
                keyval = full & 0xFFFFFFFF if kt == "w" else full
            scalar_eor.append((va, ops, kt, kn, keyval))
        else:
            vector_eor.append((va, ops))
    elif mn in ("eor", "eor3"):
        vector_eor.append((va, ops))
    elif mn in ("str", "stur", "stp"):
        joined = " ".join(ops)
        first = joined.split(",")[0]
        if re.search(r"\bq\d+\b", first):
            stores_q.append((va, ops))
        elif re.search(r"\bw\d+\b", first):
            stores_w.append((va, ops))
        else:
            stores_x.append((va, ops))

print("scalar eor: %d  vector eor: %d" % (len(scalar_eor), len(vector_eor)))
print("str q: %d  word stores: %d  x-stores: %d" % (len(stores_q), len(stores_w), len(stores_x)))
keyed = [e for e in scalar_eor if e[4] is not None]
print("keyed scalar eor: %d / %d" % (len(keyed), len(scalar_eor)))
for va, ops, kt, kn, kv in keyed[:60]:
    print("  0x%x  %-28s key %s%d = %08x" % (va, ", ".join(ops), kt, kn, kv & 0xFFFFFFFF))
nokey = [e for e in scalar_eor if e[2] in ("w", "x") and e[4] is None]
print("unkeyed (register key, value unknown): %d" % len(nokey))
for va, ops, kt, kn, kv in nokey[:40]:
    print("  0x%x  %-28s keyreg %s%d (untracked)" % (va, ", ".join(ops), kt, kn))
print("--- vector eor ---")
for va, ops in vector_eor:
    print("  0x%x  %s" % (va, ", ".join(ops)))
print("--- str q ---")
for va, ops in stores_q:
    print("  0x%x  %s" % (va, ", ".join(ops)))

keys = {}
for va, ops, kt, kn, kv in keyed:
    keys.setdefault("%08x" % (kv & 0xFFFFFFFF), []).append(va)
print("distinct 32-bit key words: %d" % len(keys))
for k, vas in sorted(keys.items()):
    print("  key=%s at %s" % (k, ["0x%x" % a for a in vas[:6]]))
json.dump({"keys": keys,
           "keyed": [[va, ops, "%08x" % (kv & 0xFFFFFFFF)] for va, ops, kt, kn, kv in keyed],
           "unkeyed": [[va, ops] for va, ops, kt, kn, kv in nokey]},
          open(os.path.join(HERE, "ks_consts2.json"), "w"), indent=1)
print("saved ks_consts2.json")

S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
try:
    D = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))
except FileNotFoundError:
    D = []
region_words = set()
for x in list(S) + list(D):
    for f in ("d0", "d4"):
        raw = bytes.fromhex(x[f])
        for j in range(0, len(raw), 4):
            region_words.add(int.from_bytes(raw[j:j + 4], "big"))
    d2 = x["d2"]
    region_words.add(int(d2, 16) if isinstance(d2, str) else d2)
print("region words: %d" % len(region_words))
hits = [(k, vas[:3]) for k, vas in keys.items() if int(k, 16) in region_words]
print("key words verbatim in region corpus: %d" % len(hits))
for k, vas in hits[:30]:
    print("  key=%s at %s" % (k, ["0x%x" % a for a in vas]))

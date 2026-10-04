"""ks_table.py — extract the per-site keystream structure from sub_9afa4.

The builder (fn_9afa4_full.log, exact-VA disasm, 3072 insns) writes each
16-byte descriptor block as: 4 words XORed with ONE key register, then a
vector XOR and a `str q` store.  The key registers are the low words of
64-bit constants loaded by `mov`+`movk`.

This script:
  1. parses the disassembly;
  2. tracks 64-bit constants per register (mov/movk chains);
  3. finds every eor site and which register holds the "key" side;
  4. finds every str q / str x / stur site (the block writes);
  5. reports the reconstructed key constants and their offsets.

Output: ks_table.log (sites + constants), ks_consts.json (the table).
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


# canonical 64-bit register namespace: wN is the low half of xN
consts = {}          # xN -> value
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

# pass 1: constant tracking
sites = []
for idx, (va, mn, ops) in enumerate(insns):
    if mn == "mov" and len(ops) == 2 and ops[1].startswith("#"):
        t, tn = regno(ops[0])
        if t == "x":
            val = int(ops[1][1:], 0) & 0xFFFFFFFFFFFFFFFF
            consts[tn] = val
    elif mn == "movk" and len(ops) >= 2 and ops[1].startswith("#"):
        t, tn = regno(ops[0])
        if t == "x":
            imm = int(ops[1][1:], 0)
            sh = 0
            if len(ops) == 3 and "lsl" in ops[2]:
                sh = int(ops[2].split("#")[1])
            base = consts.get(tn, 0)
            base &= ~(0xFFFF << sh)
            base |= (imm & 0xFFFF) << sh
            consts[tn] = base & 0xFFFFFFFFFFFFFFFF
    elif mn in ("eor", "eor3"):
        sites.append(("eor", va, ops, dict(consts)))
    elif mn in ("str", "stur", "strb", "strh"):
        sites.append(("store", va, ops, dict(consts)))

print("eor sites: %d" % sum(1 for s in sites if s[0] == "eor"))
print("store sites: %d" % sum(1 for s in sites if s[0] == "store"))

# report eor sites where an operand register holds a full 64-bit constant
out = []
for kind, va, ops, snap in sites:
    if kind != "eor":
        continue
    # find operands that are registers with constants
    for o in ops[1:]:
        t, tn = regno(o)
        if t == "x" and tn in snap:
            out.append((va, ops, "%016x" % snap[tn]))
            break

print()
print("--- eor sites with a constant register operand (first 60) ---")
for va, ops, v in out[:60]:
    print("  0x%x  %-30s const=%s" % (va, ", ".join(ops), v))

# collect the distinct key constants
keys = {}
for va, ops, v in out:
    keys.setdefault(v, []).append(va)
print()
print("distinct constants used at eor sites: %d" % len(keys))
json.dump({"keys": keys, "sites": [[va, ops, v] for va, ops, v in out]},
          open(os.path.join(HERE, "ks_consts.json"), "w"), indent=1)
print("saved ks_consts.json")

# also: any constant that equals a *reversed* or byte-permuted form of a
# captured region word?  cheap xref against the region corpus
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
region_words = set()
for x in S:
    for f in ("d0", "d4"):
        raw = bytes.fromhex(x[f])
        for j in range(0, len(raw), 4):
            region_words.add(int.from_bytes(raw[j:j + 4], "big"))
    region_words.add(int(x["d2"], 16))
print("region words: %d" % len(region_words))
hits = []
for v, vas in keys.items():
    six = int(v, 16)
    for shift in (0, 16, 32, 48):
        w = (six >> shift) & 0xFFFFFFFF
        if w in region_words:
            hits.append((v, shift, vas[:3]))
            break
print("key words matching a region word: %d" % len(hits))
for v, shift, vas in hits[:30]:
    print("  const=%s shift=%d at %s" % (v, shift, ["0x%x" % a for a in vas]))

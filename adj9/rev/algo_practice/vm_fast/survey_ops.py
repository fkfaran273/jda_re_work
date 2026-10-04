import collections, os, re, sys, pickle
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REV); sys.path.insert(0, os.path.join(REV,"creditsea")); sys.path.insert(0, HERE)
import vm_final as V
pairs = sorted(set((m, ops) for (m, ops, npc) in V.FAST))
bym = collections.defaultdict(set)
for m, ops in pairs:
    bym[m].add(ops)
print("mnemonics: %d" % len(bym))
SKIP = {"mov","movk","ldr","ldur","str","stur","ldp","stp","bl","b","cmp","cmn","tst","cbnz","cbz","tbz","tbnz","add","sub","eor","and","orr","mul","lsl","lsr","rev","rev16","neg","mvn","cset","csel","ccmp","udiv","msub","blr","ret","b.eq","b.ne","b.hs","b.lo","b.hi","b.ls","b.lt","b.ge","b.gt","b.le","mrs"}
for m in sorted(bym):
    if m in SKIP: continue
    s = sorted(bym[m])
    print("%-10s n=%-5d  e.g. %s" % (m, len(s), s[:8]))
print("\n--- branch conds present ---")
print(sorted({m for m in bym if m.startswith("b.")}))
print("\n--- sample forms per hot mnemonic ---")
for m in ("mov","ldr","ldp","ldur","str","stur","stp","add","sub","eor","and","orr","cmp","tst","cbnz","cset","lsl","lsr","mul","rev","csel","ccmp","movk","stur","stp","ldrsb","ldrsw","ldursw","strb","stlrb","ldrsh","ldrb"):
    if m in bym:
        print("### %s (%d uniq)" % (m, len(bym[m])))
        for s in sorted(bym[m])[:14]:
            print("    ", s)

"""Execution statistics for one signature: which opcodes actually run, how
often, and what their operand strings look like.  Drives the rewrite design
(dispatch by int, pre-parsed operand indices, register-file shape)."""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_signature as S
import _gate

KIND = sys.argv[1] if len(sys.argv) > 1 else "session"


class CountingList(list):
    def __init__(self, src, ctr):
        super().__init__(src)
        self._ctr = ctr

    def __getitem__(self, i):
        self._ctr[i] = self._ctr.get(i, 0) + 1
        return list.__getitem__(self, i)


def build(kind):
    params = _gate.make(kind)
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": S.CLIENT_SDK,
                "adj_signing_id": S.ADJ_SIGNING_ID, "headers_id": "10",
                "native_version": S.NATIVE_VERSION,
                "adj_verification": S.ADJ_VERIFICATION})
    d0w, d2w, d4w = S.region(_gate.SEED, 0, 0, head=S.WIN_PHASE)
    padded, unpadded = S.claims_padded(val, kind)
    import struct
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, S.DESC9), 8: (4, 0, S.DESC8),
          4: (8, 0, d4), 2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in S.VA_ORDER]


ctr = {}
orig_fast = S.FAST
S.FAST = CountingList(orig_fast, ctr)
ex = S.FinEx(_gate.SECOND, build(KIND))
status = ex.run(max_steps=40_000_000)
S.FAST = orig_fast
print("status", status, "steps", ex.steps)

mn = collections.Counter()
ops_by_mn = collections.defaultdict(collections.Counter)
tot = sum(ctr.values())
for k, c in ctr.items():
    m, ops, npc = orig_fast[k]
    mn[m] += c
    ops_by_mn[m][ops] += c
print("\n== executed mnemonics (total %d) ==" % tot)
for m, c in mn.most_common(30):
    print("  %-9s %9d  %5.1f%%  distinct_ops=%d"
          % (m, c, 100.0 * c / tot, len(ops_by_mn[m])))

print("\n== top operand strings for the hottest mnemonics ==")
for m, _ in mn.most_common(12):
    print("--", m)
    for o, c in ops_by_mn[m].most_common(8):
        print("     %9d  %r" % (c, o))

# what does val()/set_reg() actually see?
print("\n== operand field shapes ==")
kinds = collections.Counter()
for m, ops, npc in orig_fast:
    if not ops:
        continue
    for p in ops.replace("[", " ").replace("]", " ").replace(",", " ").split():
        if p and p[0] in "wx" and p[1:].isdigit():
            kinds["reg " + p[0]] += 1
        elif p.startswith("#"):
            kinds["imm"] += 1
        elif p.startswith("0x"):
            kinds["branch"] += 1
        else:
            kinds["other " + p] += 1
for kk, c in kinds.most_common(18):
    print("  %-16s %d" % (kk, c))

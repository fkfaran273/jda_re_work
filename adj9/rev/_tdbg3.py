"""_tdbg3.py — dual-run taint diff: find where S-dependence enters values but
not nodes.  Two TaintEx runs (row 7, d2 real vs d2^1).  At every stream EMIT
record (step, sva, n, v, id(node)).  The first emit where v differs but the
node id is the SAME in both runs = the exact op site that lost provenance.
NEW file.
"""
import os, sys, json, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T
import vm_final as V
import mint_pipeline as M

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)

# flip d2 (S): position 4 in VA order
d2w = struct.unpack(">I", bytes.fromhex(T.json.load(
    open(os.path.join(HERE, "all_signings.json"))) [7]["d2"]))[0]
descs2 = list(descs)
p = 4  # VA_ORDER index of logical d2
lendl, tag, data = descs2[p]
data2 = struct.pack(">I", d2w ^ 1) + data[4:]
descs2[p] = (lendl, tag, data2)


def run(descs):
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    hist = []
    orig = T.TaintStream.emit_t

    def emit_t(self, n, v, node):
        r = orig(self, n, v, node)
        hist.append((ex.steps, self.va & 0xFFFFF, n & 0xFFFFFFFF,
                     v & 0xFFFFFFFF, id(node)))
        return r
    T.TaintStream.emit_t = emit_t
    st = ex.run(max_steps=20_000_000)
    T.TaintStream.emit_t = orig
    return ex, st, hist


t0 = time.time()
ex1, st1, h1 = run(descs)
ex2, st2, h2 = run(descs2)
print("runs done %.0fs status %s/%s steps %d/%d emits %d/%d"
      % (time.time() - t0, st1, st2, ex1.steps, ex2.steps, len(h1), len(h2)),
      flush=True)
n = min(len(h1), len(h2))
first_bad = None
for k in range(n):
    s1, sv1, nn1, v1, id1 = h1[k]
    s2, sv2, nn2, v2, id2 = h2[k]
    if sv1 != sv2 or nn1 != nn2:
        print("emit stream/n mismatch at %d — traces diverged structurally" % k)
        break
    if v1 != v2 and id1 == id2:
        first_bad = k
        break
    if v1 != v2:
        print("first value-diff emit at trace %d: step %d/%d s=%x n=%d "
              "v=%08x/%08x idnode=%d/%d"
              % (k, s1, s2, sv1, nn1, v1, v2, id1, id2), flush=True)
        break
if first_bad is not None:
    s1, sv1, nn1, v1, id1 = h1[first_bad]
    s2, sv2, nn2, v2, id2 = h2[first_bad]
    print("DROPSITE: emit step=%d/%d stream=%05x n=%d v=%08x/%08x "
          "SAME node id=%d" % (s1, s2, sv1, nn1, v1, v2, id1), flush=True)
    # node identity means the SAME interned tuple: show it
    for nd in T._INTERN.values():
        if id(nd) == id1:
            print("  node = %s" % (str(nd)[:200]), flush=True)
            break
# also: count value-diff emits with same node id
same = sum(1 for k in range(n)
           if h1[k][3] != h2[k][3] and h1[k][4] == h2[k][4]
           and h1[k][1] == h2[k][1] and h1[k][2] == h2[k][2])
diffnode = sum(1 for k in range(n)
               if h1[k][3] != h2[k][3] and h1[k][4] != h2[k][4]
               and h1[k][1] == h2[k][1] and h1[k][2] == h2[k][2])
print("emits: value-diff w/ same node %d, w/ diff node %d" % (same, diffnode),
      flush=True)
blob1, stream1 = T.blob_from_ex(ex1, second)
blob2, stream2 = T.blob_from_ex(ex2, second)
w1 = struct.unpack(">48I", blob1)
w2 = struct.unpack(">48I", blob2)
print("blob diff words:", [i for i in range(48) if w1[i] != w2[i]], flush=True)
print("blob1==cap:", blob1 == cap, flush=True)

"""Reconstruct the seq-affected claims layout: mint full event map once,
enumerate candidate claims strings offline."""
import json
import os
import re
import sys

WORK = r"C:\Users\Apps\Downloads\com.penti.app\adj7_work"
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")

import adj7_pure as ap
from adj7_oracle import cbc_decrypt
import adj7s3_emu

EV = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))["4"]["nmap"]
SPLIT = ap.CLAIM_POOL.index("session_count")

emu = adj7s3_emu.Emu(verbose=False)
emu.fixed_time = 1791271810
out = emu.run(payload=b"\x00" * 32, mapobj=EV, arg4=8)
assert out and len(out) == 304
body = cbc_decrypt(out[16:272], out[:16])
rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
cert40 = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
print("mint H:", H)
print("nonce :", nonce12.hex(), "cert40 NUL:", cert40 == b"\x00" * 40)


def parts_of(m, keep_seq=True, use_id=True, block2=True):
    seqv = str(m.get("seq", ""))
    out = [str(m[k]) for k in ap.CLAIM_POOL[:SPLIT] if m.get(k) not in (None, "")]
    if use_id:
        out.append(ap.ADJ_SIGNING_ID)
    tail = []
    for k in ap.CLAIM_POOL[SPLIT:-2]:
        if m.get(k) in (None, ""):
            continue
        if k == "seq" and not keep_seq:
            continue
        tail.append(str(m[k]))
    out += tail
    if block2:
        out += [str(m.get("activity_kind", "")), str(m.get("client_sdk", ""))]
    return out, seqv


def test(parts, tag, found):
    cl = "".join(parts)
    if ap.commitment_digest(cl.encode("latin1"), nonce12, cert40).hex().upper() == H:
        print("!!! MATCH %-38s claims=%r" % (tag, cl))
        found.append((tag, cl))


found = []
# family 1: seq kept in tail, extra seq value inserted at some gap
base, seqv = parts_of(EV, keep_seq=True)
for i in range(len(base) + 1):
    test(base[:i] + [seqv] + base[i:], "dup-seq gap%d" % i, found)
# family 2: seq removed from tail, inserted at some gap
base2, _ = parts_of(EV, keep_seq=False)
for i in range(len(base2) + 1):
    test(base2[:i] + [seqv] + base2[i:], "move-seq gap%d" % i, found)
# family 3: seq removed entirely (sanity -> should match pool law? no, law says transformed)
test(base2, "no-seq (sanity)", found)
# family 4: seq value doubled in place
b3 = list(base)
i_seq = None
for i, p in enumerate(base):
    if p == seqv and i > len([x for x in base[:i]]):
        pass
# locate tail seq position explicitly
tail_start = len([str(EV[k]) for k in ap.CLAIM_POOL[:SPLIT] if EV.get(k) not in (None, "")]) + 1
b4 = list(base)
b4[tail_start] = seqv + seqv
test(b4, "seq doubled in place", found)
# family 5: append id again at end / seq+id variants
for extra in ([seqv + ap.ADJ_SIGNING_ID], [ap.ADJ_SIGNING_ID + seqv],
              [seqv, ap.ADJ_SIGNING_ID], [ap.ADJ_SIGNING_ID, seqv]):
    test(base + list(extra), "tail+extra %r" % (extra,), found)
    test(list(extra) + base, "head+extra %r" % (extra,), found)

print("matches:", len(found))

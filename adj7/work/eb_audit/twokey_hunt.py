"""Mint 2-key seq maps and enumerate all part permutations to see the
native's actual claims."""
import itertools
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
ID = ap.ADJ_SIGNING_ID
ACT, SDK = "event", "android5.6.0"


def mint(mapobj, sec=1791271810):
    emu = adj7s3_emu.Emu(verbose=False)
    emu.fixed_time = sec
    out = emu.run(payload=b"\x00" * 32, mapobj=mapobj, arg4=8)
    assert out and len(out) == 304, "mint failed"
    body = cbc_decrypt(out[16:272], out[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    c40 = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    return H, a.to_bytes(8, "little") + bytes.fromhex(d8), c40


def hunt(tag, m, pool_values, extra=None):
    """pool_values: dict pool-key -> value actually in the map.
    Enumerate permutations of [values..., ID, ACT, SDK] (+ optional extras)."""
    H, n12, c40 = mint(m)
    parts = list(pool_values.values()) + [ID, ACT, SDK]
    cands = set("".join(p) for p in itertools.permutations(parts))
    if extra:
        for e in extra:
            for base in list(itertools.permutations(parts)):
                for i in range(len(base) + 1):
                    cands.add("".join(base[:i] + (e,) + base[i:]))
    for cl in cands:
        if ap.commitment_digest(cl.encode("latin1"), n12, c40).hex().upper() == H:
            print("[%s] MATCH %r" % (tag, cl))
            return cl
    print("[%s] no match among %d cands (mint H=%s...)" % (tag, len(cands), H[:16]))
    return None


hunt("seq+country", {"activity_kind": ACT, "client_sdk": SDK,
                     "seq": "1", "country": "IN"},
     {"country": "IN", "seq": "1"})

hunt("seq+session_count", {"activity_kind": ACT, "client_sdk": SDK,
                           "seq": "1", "session_count": "1"},
     {"seq": "1", "session_count": "1"})

hunt("seq+session_length", {"activity_kind": ACT, "client_sdk": SDK,
                            "seq": "1", "session_length": "5"},
     {"seq": "1", "session_length": "5"})

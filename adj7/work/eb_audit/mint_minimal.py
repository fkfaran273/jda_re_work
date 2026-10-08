"""Minimal-map mint: learn the seq-branch claims structure from scratch."""
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


def mint(mapobj, sec=1791271810):
    emu = adj7s3_emu.Emu(verbose=False)
    emu.fixed_time = sec
    out = emu.run(payload=b"\x00" * 32, mapobj=mapobj, arg4=8)
    assert out and len(out) == 304, "mint failed"
    body = cbc_decrypt(out[16:272], out[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    c = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    return H, a.to_bytes(8, "little") + bytes.fromhex(d8), c, rec


def hunt(tag, m, pieces, extra_pieces=()):
    """pieces: list of candidate part-strings; try all orders (and optional
    extra pieces inserted)."""
    H, n12, c40, rec = mint(m)
    print("[%s] mint H=%s nonce=%s" % (tag, H[:16], n12.hex()))
    found = []
    n = len(pieces)
    perms = set(itertools.permutations(pieces))
    for extra in extra_pieces:
        for base in perms:
            for i in range(len(base) + 1):
                cand = base[:i] + (extra,) + base[i:]
                cl = "".join(cand)
                if ap.commitment_digest(cl.encode("latin1"), n12, c40).hex().upper() == H:
                    print("  !!! MATCH %r" % cl)
                    found.append(cl)
    for base in perms:  # plain perms again (in case extra_pieces empty loop)
        cl = "".join(base)
        if cl.encode("latin1") and ap.commitment_digest(
                cl.encode("latin1"), n12, c40).hex().upper() == H:
            if cl not in found:
                print("  !!! MATCH %r" % cl)
                found.append(cl)
    if not found:
        print("  no match among %d perms x extras" % (len(perms) * (len(extra_pieces) + 1)))
    return found, (H, n12, c40)


# minimal seq map
m = {"activity_kind": "event", "client_sdk": "android5.6.0", "seq": "1"}
pieces = ["1", ap.ADJ_SIGNING_ID, "event", "android5.6.0"]
found, ctx = hunt("min-seq", m, pieces,
                  extra_pieces=["1", ap.ADJ_SIGNING_ID])
json.dump({"found": found, "H": ctx[0], "nonce": ctx[1].hex(),
           "cert40": ctx[2].decode("latin1")},
          open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\eb_audit\min_seq.json", "w"))

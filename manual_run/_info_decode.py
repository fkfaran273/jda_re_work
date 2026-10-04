"""_info_decode.py -- decode every blob in event_vectors.json; extract
(head16, seed, cert, block) per row, verify record structure + digest + MAC,
and find the head phase per row via head16_for.
"""
import json, struct, sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\manual_run")
import adj9_pure as P
import adj9_decode as D

vecs = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\manual_run\event_vectors.json"))

rows = []
for i, v in enumerate(vecs):
    blob = bytes.fromhex(v["blob"])
    assert len(blob) == 192, len(blob)
    header = blob[:16]
    body = blob[16:160]
    mac = blob[160:192]
    rec = D.whiten_body_inverse(body, header)
    kind = v["map"]["activity_kind"]
    ok_mac = (P.record_digest(body) == mac)
    magic = tuple(rec[0:3])
    head = rec[3:19]
    seed = struct.unpack(">I", rec[20:24])[0]
    cert = rec[25:45]
    block = rec[46:78]
    tags = (rec[19], rec[24], rec[45], rec[78])
    sha0_ok = (rec[79:111] == P.SHA0)
    # find head phase
    phases = []
    for ph in [(0x2B,), (0x2B, 0x48), (0x40,), (0x2B, 0x40), (0x40, 0x48),
               (0x2B, 0x48, 0x40), (0x48,), (0x41,), (0x42,), (0x43,),
               (0x44,), (0x45,), (0x46,), (0x47,)]:
        if P.head16_for(seed, ph) == head:
            phases.append(ph)
    print("row %d %-11s ts=%d mac_ok=%s magic=%s tags=%s sha0_ok=%s phase=%s"
          % (i, kind, v["ts"], ok_mac, magic, tags, sha0_ok, phases))
    print("   head=%s seed=%08x cert=%s" % (head.hex(), seed, cert.hex()))
    print("   block=%s" % block.hex())
    rows.append(dict(idx=i, kind=kind, ts=v["ts"], head=head, seed=seed,
                     cert=cert, block=block, map=v["map"], blob=blob,
                     rec=rec))

# maps of the three info rows identical?
import itertools
info = [r for r in rows if r["kind"] == "info"]
for a, b in itertools.combinations(info, 2):
    print("info maps %d vs %d identical: %s" % (a["idx"], b["idx"],
                                                a["map"] == b["map"]))

# sanity: solved laws reproduce the blocks of session/click/attribution/event
for r in rows:
    kind = r["kind"]
    if kind == "info":
        continue
    val = r["map"]
    keys = P.claim_key_order(val, kind)
    raw = "".join(val[k] for k in keys).encode("latin1")
    got = P.record_block(r["head"], r["seed"], raw, r["cert"])
    print("row %d %-11s claims_len=%4d block_ok=%s"
          % (r["idx"], kind, len(raw), got == r["block"]))

json.dump([{k: (v.hex() if isinstance(v, bytes) else v)
            for k, v in r.items() if k not in ("map", "blob", "rec")}
           for r in rows],
          open(r"C:\Users\Apps\Downloads\com.penti.app\manual_run\_info_rows.json", "w"))
print("wrote _info_rows.json")

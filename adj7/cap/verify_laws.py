"""verify_laws.py — check the known adj7 closed-form laws on the niri 3.61.0 capture.

Laws under test (from adj7_work/ADJ7_MINT_FINDINGS.md):
  header  blob[0:16] = bionic rand() pair-XOR BE, seed = signing second
  tag     blob[272:304] = HMAC-SHA256(DK37, blob[16:272])

  python verify_laws.py
"""
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "adj7_work"))
from adj7_law import BionicRand  # read-only import of the proven PRNG

DK37 = bytes.fromhex(
    "2a4cc07960d647623cc386dcefafbf25"
    "b669914d32cc8585a1ed7f920ef591eb")


def iso_to_unix(s):
    """2026-02-16T13:43:27.591Z+0300 -> unix float"""
    m = re.match(r"(.*?)Z([+-]\d{4})?$", s)
    if not m:
        raise ValueError(s)
    base = m.group(1)
    tz = m.group(2) or "+0000"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(base, fmt)
            break
        except ValueError:
            continue
    else:
        raise ValueError(s)
    sign = 1 if tz[0] == "+" else -1
    off = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
    return (dt - off).replace(tzinfo=timezone.utc).timestamp()


def header_from_seed(seed):
    r = BionicRand(seed)
    d = [r.next() for _ in range(8)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(x.to_bytes(4, "big") for x in w)


def main():
    recs = json.load(open(os.path.join(
        HERE, "nirio_16Feb", "nirio_16Feb_oneplus7_newapp_adjust.json"),
        encoding="utf-8"))
    out = []
    ok_tag = ok_head = 0
    for r in recs:
        auth = next(v for k, v in r["request_headers"] if k.lower() == "authorization")
        sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1)
        blob = bytes.fromhex(sig)
        path = re.sub(r"^https://[^/]+", "", r["url"]).split("?")[0]
        rec = {"sid": r["sid"], "kind": path.strip("/").split("?")[0],
               "sig_hex": sig, "blob_len": len(blob)}
        # seed candidates
        cands = {}
        if r["method"] == "POST" and isinstance(r["body"], dict):
            for fld in ("created_at", "sent_at"):
                if fld in r["body"]:
                    t = iso_to_unix(r["body"][fld])
                    for d in (-1, 0, 1):
                        cands[f"{fld}{d:+d}" if d else fld] = int(t) + d
        else:
            begin = r.get("begin", "")  # HH:MM:SS.mmm local (IST) — day from session
            if begin:
                # take the day from the first POST's sent_at (same capture window)
                pass
        # tag law
        tag = blob[272:304]
        calc = hmac.new(DK37, blob[16:272], hashlib.sha256).digest()
        rec["tag_ok"] = (tag == calc)
        ok_tag += rec["tag_ok"]
        # header law
        hit = None
        for name, sec in sorted(cands.items()):
            if header_from_seed(sec) == blob[:16]:
                hit = (name, sec)
                break
        rec["header_hit"] = hit
        ok_head += hit is not None
        rec["seed_cands"] = cands
        out.append(rec)
        print(f'{rec["sid"]:>3} {rec["kind"]:20s} len={len(blob):3d} '
              f'tag={rec["tag_ok"]} head={hit or "MISS"} '
              f'cands={list(cands.values())}')
    print(f"\ntag law: {ok_tag}/{len(recs)}   header law: {ok_head}/{len(recs)}")
    with open(os.path.join(HERE, "nirio_16Feb", "law_check.json"), "w") as f:
        json.dump(out, f, indent=1, default=str)

if __name__ == "__main__":
    main()

"""step1_headtag.py -- header law + tag law on the 18 niceone blobs.

header: adj8 bionic rand() law (make_header, seed = signing second)
        vs the iOS MINSTD variant (make_ios_header) -- which generator do the
        genuine iOS blobs follow?
tag:    HMAC-SHA256(DK38, blob[16:144]).
"""
import sys, json, base64, hmac, hashlib, datetime

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios")
import adj9ios_pure as P

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))
DK38 = A.DK38


def minstd_header(sec):
    return P.make_ios_header(sec)


def find_second(hdr, t_center, span=8):
    """Scan +-span seconds around the charles timestamp for a header hit."""
    for law, fn in (("bionic", A.make_header), ("minstd", minstd_header)):
        for off in range(-span, span + 1):
            if fn(t_center + off) == hdr:
                return law, t_center + off
    return None, None


print(f"{'rec':>4} {'kind':<12} {'header_law':<9} {'second':<11} {'tag_ok'}")
ok_h = ok_t = 0
results = []
for r in RECS:
    blob = bytes.fromhex(r["blob_hex"])
    hdr, body, tag = blob[:16], blob[16:144], blob[144:]
    tag_ok = hmac.new(DK38, body, hashlib.sha256).digest() == tag
    ok_t += tag_ok
    kind = ("attrib" if r["path"] == "/attribution" else
            r["path"].strip("/") if r["path"] else "?")
    law = sec = None
    if r["charles_ms"]:
        t_center = int(r["charles_ms"] // 1000)
        law, sec = find_second(hdr, t_center)
    ok_h += law is not None
    results.append({"i": r["i"], "law": law, "second": sec, "tag_ok": tag_ok})
    print(f"{r['i']:>4} {kind:<12} {str(law):<9} {str(sec):<11} {tag_ok}")

print(f"\nheader law matched: {ok_h}/18   DK38 tag verified: {ok_t}/18")
json.dump(results, open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_step1.json", "w"), indent=1)

"""step1b_headscan.py -- wide scan (+-600 s) for each blob's signing second,
both header laws, anchored on charles_ms / sent_at / created_at."""
import sys, json, re, datetime

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios")
import adj9ios_pure as P

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))


def iso2s(s):
    if not s:
        return None
    m = re.match(r"(.*?)\+(\d\d):?(\d\d)$", s)
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f%z") if "." in m.group(1) \
        else datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S%z")
    return int(dt.timestamp())


def minstd_header(sec):
    return P.make_ios_header(sec)


print(f"{'rec':>4} {'law':<8} {'second':<11} {'d_charles':>9} {'d_sent':>7}")
out = []
for r in RECS:
    blob = bytes.fromhex(r["blob_hex"])
    hdr = blob[:16]
    p = r["params"]
    t_c = int(r["charles_ms"] // 1000) if r["charles_ms"] else None
    t_s = iso2s(p.get("sent_at"))
    t_cr = iso2s(p.get("created_at"))
    anchors = [t for t in (t_c, t_s, t_cr) if t]
    hit = None
    for law, fn in (("bionic", A.make_header), ("minstd", minstd_header)):
        for a in anchors:
            for off in range(-600, 601):
                if fn(a + off) == hdr:
                    hit = (law, a + off, (a + off) - t_c if t_c else None,
                           (a + off) - t_s if t_s else None)
                    break
            if hit:
                break
        if hit:
            break
    out.append({"i": r["i"], "law": hit[0] if hit else None,
                "second": hit[1] if hit else None,
                "d_charles": hit[2] if hit else None,
                "d_sent": hit[3] if hit else None})
    print(f"{r['i']:>4} {out[-1]['law'] or '-':<8} {str(out[-1]['second']):<11} "
          f"{str(out[-1]['d_charles']):>9} {str(out[-1]['d_sent']):>7}")

json.dump(out, open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_step1b.json", "w"), indent=1)

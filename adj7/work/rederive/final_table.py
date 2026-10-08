import json, datetime, calendar, sys, os
sys.path.insert(0, os.getcwd())
import mylaws as ml

rows = json.load(open("master_rows.json"))
vr = json.load(open("verify_results.json"))
recs = json.load(open("record_summary.json"))

def parse(ts):
    dt = datetime.datetime.strptime(ts[:23], "%Y-%m-%dT%H:%M:%S.%f")
    t = calendar.timegm(dt.timetuple())
    off = 0
    sfx = ts[19:]
    if "+" in sfx:
        o = sfx.split("+")[1]
        off = int(o[:2]) * 3600 + int(o[2:4]) * 60
    elif sfx.startswith("-"):
        o = sfx[1:5]
        off = -(int(o[:2]) * 3600 + int(o[2:4]) * 60)
    return t, t - off, off

final = []
for i, (r, v, q) in enumerate(zip(rows, vr, recs)):
    c_utc, c_off, off = parse(r["created_at"])
    s_utc, s_off, _ = parse(r["sent_at"]) if r.get("sent_at") else (None, None, 0)
    sec = v.get("signing_second")
    row = {
        "row": i, "src": "+".join(r["srcs"]), "kind": r["kind"],
        "app_token": r["app_token"], "pkg": r.get("package_name",""),
        "created_at": r["created_at"], "sent_at": r["sent_at"],
        "utc_off_s": off,
        "blob_len": v["blob_len"], "tag_ok": v["tag_ok"],
        "signing_second": sec,
        "hit": v.get("hit"),
        "d_created_asUTC": (sec - c_utc) if sec is not None else None,
        "d_created_off": (sec - c_off) if sec is not None else None,
        "d_sent_asUTC": (sec - s_utc) if (sec is not None and s_utc) else None,
        "d_sent_off": (sec - s_off) if (sec is not None and s_off) else None,
        "law": "STD" if v["std_readable"] else ("MEAS" if v["meas_readable"] else "?"),
        "record_ok": q["regex"] and q["rebuild"] and q["a20"] and q["e_ok"] and q["pad0x10"] and q["nonce_ok"],
        "cert40": q["c"], "cert_match_expected": q["cert_ok"],
        "reencrypt_ok": v.get("reencrypt_ok"),
    }
    final.append(row)

json.dump(final, open("final_table.json","w"), indent=1)
hdr = f'{"row":>3} {"kind":<20} {"app":<10} {"tag":^5} {"len":^4} {"d_cUTC":>7} {"d_cOFF":>7} {"d_sOFF":>7} {"rec":^4} {"reenc":^5} law'
print(hdr)
for r in final:
    app = {"smxi7gqwu39c":"hanaf","tczjrkpa8lc0":"burger","vf3lochhmgw0":"hunch","cv4d2hlazp4w":"nirio"}.get(r["app_token"], r["app_token"][:9])
    print(f'{r["row"]:>3} {r["kind"]:<20} {app:<10} {str(r["tag_ok"]):^5} {r["blob_len"]:>4} '
          f'{str(r["d_created_asUTC"]):>7} {str(r["d_created_off"]):>7} {str(r["d_sent_off"]):>7} '
          f'{str(r["record_ok"])[:4]:^4} {str(r["reencrypt_ok"])[:5]:^5} {r["law"]}')

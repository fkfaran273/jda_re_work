import sys, os, json, hmac, hashlib, calendar, datetime, struct
sys.path.insert(0, os.getcwd())
import mylaws as ml

RK = ml.key_expand_256(ml.SEED)
rows = json.load(open("master_rows.json"))

def ts_to_secs(ts):
    """'2026-10-07T01:10:48.959Z+0530' -> (utc_epoch_Z, utc_epoch_offset_applied)"""
    m = ts.strip()
    dt = datetime.datetime.strptime(m[:23], "%Y-%m-%dT%H:%M:%S.%f")
    t_as_utc = calendar.timegm(dt.timetuple())
    off = None
    if "+" in m:
        offs = m.split("+")[1]
        if offs and offs.lower() != "z":
            hh, mm = int(offs[:2]), int(offs[2:4])
            off = hh * 3600 + mm * 60
    elif "-" in m[10:]:
        offs = m[10:].split("-")[1]
        hh, mm = int(offs[:2]), int(offs[2:4])
        off = -(hh * 3600 + mm * 60)
    t_offset_applied = t_as_utc - off if off is not None else t_as_utc
    return t_as_utc, t_offset_applied

out = []
for idx, r in enumerate(rows):
    blob = bytes.fromhex(r["sig"])
    rec = {"row": idx, "src": "+".join(r["srcs"]), "kind": r["kind"],
           "pkg": r.get("package_name",""), "app_token": r["app_token"],
           "path": r["path"], "created_at": r["created_at"], "sent_at": r["sent_at"]}
    # TASK 5: length
    rec["blob_len"] = len(blob)
    # TASK 1: tag
    rec["tag_ok"] = ml.tag_ok(blob)
    # TASK 2: header brute force
    header = blob[:16]
    c_utc, c_off = ts_to_secs(r["created_at"])
    s_utc, _ = ts_to_secs(r["sent_at"]) if r.get("sent_at") else (None, None)
    hit = None
    search = {}
    for label, base in (("created_utc", c_utc), ("created_off", c_off), ("sent_utc", s_utc)):
        if base is None: continue
        for d in range(0, 121):
            for sec in ((base - d), (base + d)):
                if ml.header_from_second(sec) == header:
                    hit = (label, sec, d if d else 0)
                    search[label] = hit
                    break
            if hit: break
        if hit: break
    if hit:
        rec["hit"] = hit
        rec["signing_second"] = hit[1]
        rec["delta_vs_created_utc"] = hit[1] - c_utc
        rec["delta_vs_sent_utc"] = (hit[1] - s_utc) if s_utc is not None else None
    else:
        # wider sweep +-3600 around created utc
        wide = None
        for d in range(0, 3601):
            for sec in (c_utc - d, c_utc + d):
                if ml.header_from_second(sec) == header:
                    wide = sec; break
            if wide: break
        rec["hit"] = ("WIDE", wide, wide - c_utc) if wide else None
        rec["signing_second"] = wide
        rec["delta_vs_created_utc"] = (wide - c_utc) if wide else None
    # TASK 3: decrypt
    body = blob[16:272]
    rec_std = ml.cbc_dec(body, header, ml.dec_block_std, RK)
    rec_meas = ml.cbc_dec(body, header, ml.dec_block_meas, RK)
    rec["std_readable"] = rec_std.startswith(b'{ "a"')
    rec["meas_readable"] = rec_meas.startswith(b'{ "a"')
    # TASK 4: record layout
    if rec["meas_readable"]:
        pr = ml.parse_record(rec_meas)
        rec["record"] = {k: v for k, v in pr.items() if k not in ("pad",)}
        rec["record_bytes"] = rec_meas.hex()
        # re-encrypt byte equality
        re_enc = ml.cbc_enc(rec_meas, header, ml.enc_block_meas, RK)
        rec["reencrypt_ok"] = (re_enc == body)
    elif rec["std_readable"]:
        pr = ml.parse_record(rec_std)
        rec["record"] = {k: v for k, v in pr.items() if k not in ("pad",)}
        rec["record_bytes"] = rec_std.hex()
        re_enc = ml.cbc_enc(rec_std, header, ml.enc_block_std, RK)
        rec["reencrypt_ok"] = (re_enc == body)
    out.append(rec)

json.dump(out, open("verify_results.json", "w"), indent=1, default=str)

# --- table ---
print(f'{"row":>3} {"tag":^5} {"law":^4} {"rec":^5} {"reenc":^5} {"delta(created)":>14} {"delta(sent)":>11} {"len":^4} kind/pkg')
for rec in out:
    law = "MEAS" if rec["meas_readable"] else ("STD" if rec["std_readable"] else "?")
    d1 = rec.get("delta_vs_created_utc")
    d2 = rec.get("delta_vs_sent_utc")
    print(f'{rec["row"]:>3} {str(rec["tag_ok"]):^5} {law:^4} {str(rec.get("record",{}).get("regex_match"))[:5]:^5} '
          f'{str(rec.get("reencrypt_ok"))[:5]:^5} {str(d1):>14} {str(d2):>11} {rec["blob_len"]:>4} {rec["kind"]}/{rec["pkg"]}')

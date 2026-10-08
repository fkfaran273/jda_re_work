"""booking_diff.py -- THE booking diff, byte-exact.

Golden  : payrupik_new_.saz (Fiddler, this PC) -- the phone's REAL app
          traffic that BOOKED NON-ORGANIC (tracker 248wk8ym
          VL-Alliance::HM2::HM2_1722_).  sid 42 POST /session,
          sid 43 POST /sdk_click, sid 44 GET /attribution,
          sid 45 POST /event.  The CLICK itself is NOT in the saz
          (it happened on the phone before the capture began).
Ours    : run_install.py (adj7 funnel) as run in run_hanaf6.log /
          run_hanaf7.log -- same app, same PC/IP, signatures proven
          byte-exact (cap/REPLAY_RULE_RESULT.md probe G) -- answers ORGANIC.

Everything is compared AT THE RAW BYTES level (before percent-decoding):
request line, every header in wire order, raw body/query tokens in wire
order, per-token encoding laws, timestamp formats.

    python booking_diff.py        # writes booking_diff_out.json + prints

Read-only everywhere except work/booking_diff/ (golden_raw/, our_wire/,
booking_diff_out.json).
"""
import gzip
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
SAZ = r"C:\Users\Apps\Downloads\payrupik_new_.saz"
GOLDEN_DIR = os.path.join(HERE, "golden_raw")
OUR_DIR = os.path.join(HERE, "our_wire")
OUT = os.path.join(HERE, "booking_diff_out.json")

report = {}

TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}$")
TS_FIELDS = {"created_at", "sent_at", "click_time", "click_time_server",
             "install_begin_time", "install_begin_time_server",
             "installed_at", "updated_at"}


# ------------------------------------------------------------------ parse
def parse_request(raw):
    """Exact split of a raw client request: request line, headers IN ORDER
    (values verbatim), raw body bytes."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    start = lines[0].decode("utf-8", "replace")
    headers = []
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        headers.append([k.decode("latin1"), v.decode("latin1")])
    return {"start_line": start, "headers": headers,
            "body": body if sep else b"", "head_bytes": head}


def decode_response(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    hmap = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hmap[k.strip().lower()] = v.strip()
    if hmap.get("transfer-encoding", "").lower() == "chunked":
        out, rest = b"", body
        while rest:
            m = re.match(rb"([0-9a-fA-F]+)[^\r\n]*\r\n", rest)
            if not m:
                break
            n = int(m.group(1), 16)
            out += rest[m.end():m.end() + n]
            rest = rest[m.end() + n:]
            if rest.startswith(b"\r\n"):
                rest = rest[2:]
            if n == 0:
                break
        body = out
    if hmap.get("content-encoding", "").lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    return lines[0], body.decode("utf-8", "replace")


def split_tokens(raw):
    """Wire tokens of a form body / query: split on &, then first =.
    Returns [(raw_key, raw_value)] -- still percent-encoded."""
    toks = []
    for t in raw.split(b"&"):
        if not t:
            continue
        k, _, v = t.partition(b"=")
        toks.append((k, v))
    return toks


def enc_law(dec_val, enc_val, quote_plus_side):
    """Which encoding did this side apply, per character?  Returns
    {char: encoded_form} for chars that are not plain a-z A-Z 0-9 . - _ ~"""
    law = {}
    for ch in set(dec_val):
        if re.match(r"^[A-Za-z0-9.\-_~]$", ch):
            continue
        if quote_plus_side:
            law[ch] = urllib.parse.quote_plus(ch, safe="")
        else:
            law[ch] = urllib.parse.quote(ch, safe="")
    return law


def golden_side_is_quote_plus(raw_val):
    """A raw value that contains '+' as space -> quote_plus; '%20' -> quote."""
    return b"+" in raw_val and b"%20" not in raw_val


# ------------------------------------------------------------------ golden
def golden():
    import zipfile
    z = zipfile.ZipFile(SAZ)
    os.makedirs(GOLDEN_DIR, exist_ok=True)
    out = {}
    names = {"session": "42", "sdk_click": "43", "attribution": "44",
             "event": "45"}
    for label, sid in names.items():
        craw = z.open(f"raw/{sid}_c.txt").read()
        sraw = z.open(f"raw/{sid}_s.txt").read()
        open(os.path.join(GOLDEN_DIR, f"{sid}_c.txt"), "wb").write(craw)
        open(os.path.join(GOLDEN_DIR, f"{sid}_s.txt"), "wb").write(sraw)
        req = parse_request(craw)
        sline, sbody = decode_response(sraw)
        method, _, rest = req["start_line"].partition(" ")
        target, _, httpver = rest.rpartition(" HTTP/")
        is_get = method == "GET"
        raw_tokens = split_tokens(req["body"] if not is_get
                                  else target.partition("?")[2].encode())
        clen = dict((k.lower(), v.strip())
                    for k, v in req["headers"]).get("content-length")
        out[label] = {
            "sid": sid, "method": method, "target": target,
            "http_ver": "HTTP/" + httpver,
            "absolute_form": "://" in target,
            "headers": req["headers"],
            "raw_body": req["body"],
            "content_length_hdr": clen,
            "body_len": len(req["body"]),
            "tokens": raw_tokens,
            "status": sline,
            "response_body": sbody,
        }
    return out


# -------------------------------------------------------------------- ours
def ours():
    """Rebuild EXACTLY what run_install.py's call() put on the wire for the
    run_hanaf7 run (last_run.json holds its gaid/uuids/click_second/reftag).
    Body/query encoding and header order are re-derived from call(), not
    assumed."""
    sys.path.insert(0, ADJ7)
    with open(os.path.join(ADJ7, "last_run.json")) as f:
        lr = json.load(f)
    import run_install as ri

    gaid = lr["gaid"]
    auuid = lr["android_uuid"]
    click_sec = lr["click_second"]
    referrer = lr["reftag"]
    # run_hanaf7 actual timing (log): click t=+1s, session/sdk_click t=+11s
    sec = click_sec + 11

    s_fields = ri.build_session_request(gaid, auuid, sec,
                                        click_sec=click_sec)
    c_fields = ri.build_click_request(gaid, auuid, sec, referrer,
                                      click_sec=click_sec)
    a_fields = ri.build_attribution_request(gaid, auuid, sec + 3)

    # real Authorization blobs (offline mint) so the header structure
    # compare sees the genuine param list + blob length
    s_auth = ri.sign(s_fields, "session", sec)
    c_auth = ri.sign(c_fields, "click", sec)
    a_auth = ri.sign(a_fields, "attribution", sec + 3)

    # call(): POST body  = urllib.parse.urlencode(fields)   (quote_plus)
    #         GET target = path + "?" + urlencode(fields, quote_via=quote)
    s_body = urllib.parse.urlencode(s_fields).encode()
    c_body = urllib.parse.urlencode(c_fields).encode()
    a_query = urllib.parse.urlencode(
        a_fields, quote_via=urllib.parse.quote).encode()

    # call(): putrequest(method, target, skip_host=1, skip_accept_encoding=1)
    #         -> ORIGIN-FORM request line (path only, no scheme://host)
    def wire_headers(is_post, body_len, auth):
        hs = [["Client-SDK", ri.CLIENT_SDK], ["Authorization", auth]]
        if is_post:
            hs.append(["Content-Type", "application/x-www-form-urlencoded"])
        hs.append(["User-Agent", ri.APP_UA])
        hs.append(["Host", "app.adjust.com"])
        hs.append(["Connection", "Keep-Alive"])
        hs.append(["Accept-Encoding", "gzip"])
        if is_post:
            hs.append(["Content-Length", str(body_len)])
        return hs

    out = {
        "last_run": lr,
        "device": dict(ri.DEVICE),
        "app_ua": ri.APP_UA,
        "browser_ua": ri.BROWSER_UA,
        "session": {
            "method": "POST", "target": "/session",
            "headers": wire_headers(True, len(s_body), s_auth),
            "raw_body": s_body, "tokens": split_tokens(s_body),
        },
        "sdk_click": {
            "method": "POST", "target": "/sdk_click",
            "headers": wire_headers(True, len(c_body), c_auth),
            "raw_body": c_body, "tokens": split_tokens(c_body),
        },
        "attribution": {
            "method": "GET", "target": "/attribution?" + a_query.decode(),
            "headers": wire_headers(False, 0, a_auth),
            "raw_body": a_query, "tokens": split_tokens(a_query),
        },
        "event": None,
    }
    os.makedirs(OUR_DIR, exist_ok=True)
    for label in ("session", "sdk_click", "attribution"):
        o = out[label]
        head = "%s %s HTTP/1.1\r\n" % (o["method"], o["target"])
        for k, v in o["headers"]:
            head += "%s: %s\r\n" % (k, v)
        blob = head.encode() + b"\r\n" + (
            o["raw_body"] if o["method"] == "POST" else b"")
        open(os.path.join(OUR_DIR, f"{label}.txt"), "wb").write(blob)
    return out


# ---------------------------------------------------------------- diffing
def diff_headers(label, g, o):
    gh = [[k, v.lstrip(" ")] for k, v in g["headers"]]
    oh = [[k, v.lstrip(" ")] for k, v in o["headers"]]
    gnames = [k for k, _ in gh]
    onames = [k for k, _ in oh]
    res = {"golden_order": gnames, "our_order": onames,
           "same_order_and_set":
               [k.lower() for k in gnames] == [k.lower() for k in onames]}
    diffs = []
    gmap = {k.lower(): v for k, v in gh}
    omap = {k.lower(): v for k, v in oh}
    for k in gmap:
        if k not in omap:
            diffs.append({"class": "golden-sends-we-omit", "header": k})
    for k in omap:
        if k not in gmap:
            diffs.append({"class": "we-send-golden-omits", "header": k})
    for k in gmap:
        if k in omap:
            gv, ov = gmap[k], omap[k]
            if k == "authorization":
                # structural compare: param list + blob length
                gp = dict(re.findall(r'(\w+)="([^"]*)"', gv))
                op = dict(re.findall(r'(\w+)="([^"]*)"', ov))
                struct = {"golden_params": {a: (b if a != "signature" else
                                                b[:8] + "...(%d hex)" % len(b))
                                            for a, b in gp.items()},
                          "our_params": {a: (b if a != "signature" else
                                             b[:8] + "...(%d hex)" % len(b))
                                         for a, b in op.items()},
                          "same_param_keys": sorted(gp) == sorted(op),
                          "same_param_values": all(
                              gp[x] == op[x] for x in gp if x != "signature"),
                          "same_blob_len": len(gp.get("signature", "")) ==
                                           len(op.get("signature", ""))}
                if not (struct["same_param_keys"]
                        and struct["same_param_values"]
                        and struct["same_blob_len"]):
                    diffs.append({"class": "auth-structure", "detail": struct})
                continue
            if gv != ov:
                diffs.append({"class": "value", "header": k,
                              "golden": gv, "ours": ov})
    res["diffs"] = diffs
    report.setdefault("headers", {})[label] = res
    return res


def diff_body(label, g, o):
    gt = g["tokens"]
    ot = o["tokens"]
    gkeys = [k.decode("latin1") for k, _ in gt]
    okeys = [k.decode("latin1") for k, _ in ot]
    res = {"golden_count": len(gt), "our_count": len(ot),
           "golden_order": gkeys, "our_order": okeys,
           "missing_in_ours": [k for k in gkeys if k not in okeys],
           "extra_in_ours": [k for k in okeys if k not in gkeys],
           "order_same": gkeys == okeys, "value_and_encoding": []}
    if gkeys != okeys:
        shared = [k for k in gkeys if k in okeys]
        gpos = {k: i for i, k in enumerate(gkeys)}
        opos = {k: i for i, k in enumerate(okeys)}
        res["moved_keys"] = {k: {"golden_pos": gpos[k], "our_pos": opos[k]}
                             for k in shared if gpos[k] != opos[k]}
        res["first_order_mismatch_idx"] = next(
            (i for i, (a, b) in enumerate(zip(gkeys, okeys)) if a != b), None)
    gmap = {k.decode("latin1"): v for k, v in gt}
    omap = {k.decode("latin1"): v for k, v in ot}
    for k in gkeys:
        if k not in omap:
            continue
        gv, ov = gmap[k], omap[k]
        if gv == ov:
            continue
        gdec = urllib.parse.unquote_plus(gv.decode("latin1"))
        odec = urllib.parse.unquote_plus(ov.decode("latin1"))
        entry = {"field": k, "golden_raw": gv.decode("latin1"),
                 "our_raw": ov.decode("latin1")}
        if gdec == odec:
            entry["class"] = "encoding-only"
            entry["golden_law"] = enc_law(
                gdec, gv.decode("latin1"), golden_side_is_quote_plus(gv))
            entry["our_law"] = enc_law(
                odec, ov.decode("latin1"), True)
        else:
            entry["class"] = "value"
            entry["golden_decoded"] = gdec
            entry["our_decoded"] = odec
            if k in TS_FIELDS:
                gf = "local+digits+Z+offset" if TIME_RE.match(gdec) else \
                    "OTHER:%s" % gdec
                of = "local+digits+Z+offset" if TIME_RE.match(odec) else \
                    "OTHER:%s" % odec
                entry["golden_ts_format"] = gf
                entry["our_ts_format"] = of
        res["value_and_encoding"].append(entry)
    report.setdefault("bodies", {})[label] = res
    return res


def ts_story(label, g, o):
    """Exact created_at / sent_at / click_time formats + relative offsets."""
    def toks(side):
        return {k.decode("latin1"): urllib.parse.unquote_plus(
                    v.decode("latin1")) for k, v in side["tokens"]}

    gt, ot = toks(g), toks(o)

    def sec(s):
        m = re.match(r"^\d{4}-\d{2}-\d{2}T(\d{2}):(\d{2}):(\d{2})\.(\d{3})"
                     r"Z(\+|-)(\d{2})(\d{2})$", s)
        if not m:
            return None
        h, mi, se, ms, sign, oh, om = m.groups()
        total = int(h) * 3600 + int(mi) * 60 + int(se) + int(ms) / 1000.0
        off = int(oh) * 3600 + int(om) * 60
        if sign == "-":
            off = -off
        return total - off  # rough UTC-seconds-of-day

    story = {"golden": {}, "ours": {}}
    for k in sorted(TS_FIELDS):
        if k in gt:
            story["golden"][k] = gt[k]
        if k in ot:
            story["ours"][k] = ot[k]
    for name, t in (("golden", gt), ("ours", ot)):
        if "click_time" in t and "created_at" in t:
            a, b = sec(t["click_time"]), sec(t["created_at"])
            if a is not None and b is not None:
                story[name]["click_to_session_s"] = round(b - a, 3)
    report.setdefault("timestamp_story", {})[label] = story


def main():
    g = golden()
    o = ours()
    report["golden_flow_summary"] = {
        lbl: {"status": g[lbl]["status"],
              "response": json.loads(g[lbl]["response_body"])
              if g[lbl]["response_body"].startswith("{")
              else g[lbl]["response_body"]}
        for lbl in g}
    report["click_in_saz"] = None  # verified separately: sids 1-64 contain
    # no clicks.mobpine/adjust click -- the click predates the capture
    report["our_device_profile"] = o["device"]
    report["our_app_ua"] = o["app_ua"]
    report["our_browser_ua"] = o["browser_ua"]

    for lbl in ("session", "sdk_click", "attribution"):
        diff_headers(lbl, g[lbl], o[lbl])
        diff_body(lbl, g[lbl], o[lbl])
        ts_story(lbl, g[lbl], o[lbl])

    # request-line form
    report["request_line"] = {
        lbl: {"golden": "%s %s %s" % (g[lbl]["method"], g[lbl]["target"],
                                      g[lbl]["http_ver"]),
              "ours":
              "%s %s HTTP/1.1" % (o[lbl]["method"], o[lbl]["target"])}
        for lbl in ("session", "sdk_click", "attribution")}

    # space-encoding law demonstrated synthetically: our device_name has no
    # space, so prove the ENCODERS agree with the golden's laws by encoding
    # the golden's own values with run_install.call()'s two encoders
    import run_install as ri2  # already imported inside ours(); sys.path set
    synthetic = {}
    for val in ("moto g42", "Pixel 6a"):
        synthetic[val] = {
            "golden_post_form": "moto+g42" if val == "moto g42" else None,
            "our_post_encoder_quote_plus":
                urllib.parse.urlencode({"d": val}).split("=")[1],
            "our_get_encoder_quote":
                urllib.parse.urlencode({"d": val},
                                       quote_via=urllib.parse.quote
                                       ).split("=")[1],
            "golden_get_form": "moto%20g42" if val == "moto g42" else None,
        }
    report["space_encoding_law"] = {
        "note": "POST bodies use quote_plus (space -> '+'), the GET query "
                "uses quote (space -> '%20') -- same laws as the golden "
                "(sid 42 device_name=moto+g42, sid 44 device_name=moto%20g42)",
        "check": synthetic}
    report["content_length_integrity"] = {
        lbl: {"hdr": g[lbl]["content_length_hdr"],
              "actual_body_len": g[lbl]["body_len"],
              "match": g[lbl]["content_length_hdr"] is None
              or int(g[lbl]["content_length_hdr"]) == g[lbl]["body_len"]}
        for lbl in ("session", "sdk_click", "event")}
    report["golden_absolute_form"] = {
        lbl: g[lbl]["absolute_form"] for lbl in
        ("session", "sdk_click", "attribution", "event")}

    # flow: the event step
    report["event_golden"] = {
        "sid": g["event"]["sid"],
        "tokens": [(k.decode(), urllib.parse.unquote_plus(v.decode()))
                   for k, v in g["event"]["tokens"]],
        "response": json.loads(g["event"]["response_body"]),
        "in_ours": False,
        "note": "golden fires POST /event (event_token y3sjx5) AFTER the "
                "attribution answer; run_install.py has no event step",
    }

    # click story compare
    def tokmap(side):
        return {k.decode("latin1"): urllib.parse.unquote_plus(v.decode("latin1"))
                for k, v in side["tokens"]}

    gt, ot = tokmap(g["sdk_click"]), tokmap(o["sdk_click"])
    report["click_story"] = {
        "golden": {k: gt.get(k) for k in
                   ("source", "referrer_api", "click_time",
                    "click_time_server", "install_begin_time",
                    "install_begin_time_server", "installed_at",
                    "google_play_instant", "referrer")},
        "ours": {k: ot.get(k) for k in
                 ("source", "referrer_api", "click_time",
                  "click_time_server", "install_begin_time",
                  "install_begin_time_server", "installed_at",
                  "google_play_instant", "referrer")},
    }
    report["referrer_param_compare"] = {
        "golden": urllib.parse.parse_qsl(gt.get("referrer", "")),
        "ours": urllib.parse.parse_qsl(ot.get("referrer", "")),
    }

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)

    # ---------------------------------------------------------- console
    print("=" * 78)
    print("GOLDEN flow (all HTTP 200):")
    for lbl in ("session", "sdk_click", "attribution", "event"):
        b = report["golden_flow_summary"][lbl]
        print("  sid %s %-12s %s" % (g[lbl]["sid"], lbl, json.dumps(b)[:150]))
    print()
    for lbl in ("session", "sdk_click", "attribution"):
        h = report["headers"][lbl]
        print("-" * 78)
        print("[%s] headers same set+order: %s" % (lbl, h["same_order_and_set"]))
        if not h["same_order_and_set"]:
            print("   golden :", h["golden_order"])
            print("   ours   :", h["our_order"])
        for d in h["diffs"]:
            if d["class"] == "value":
                print("   HEADER VALUE %s:\n     golden %r\n     ours   %r"
                      % (d["header"], d["golden"], d["ours"]))
            else:
                print("   %s %s %s" % (d["class"], d.get("header", ""),
                                       json.dumps(d.get(
                                           "detail", ""))[:220]))
        b = report["bodies"][lbl]
        print("[%s] fields golden %d / ours %d  order_same=%s" %
              (lbl, b["golden_count"], b["our_count"], b["order_same"]))
        if b["missing_in_ours"]:
            print("   MISSING IN OURS :", b["missing_in_ours"])
        if b["extra_in_ours"]:
            print("   EXTRA IN OURS   :", b["extra_in_ours"])
        if b.get("moved_keys"):
            print("   MOVED           :", b["moved_keys"])
        for vd in b["value_and_encoding"]:
            if vd["class"] == "encoding-only":
                print("   ENCODING %s:\n     golden %s\n     ours   %s"
                      % (vd["field"], vd["golden_raw"][:110],
                         vd["our_raw"][:110]))
            else:
                extra = ""
                if "golden_ts_format" in vd:
                    extra = "  ts_format golden=%s ours=%s" % (
                        vd["golden_ts_format"], vd["our_ts_format"])
                print("   VALUE    %s:\n     golden %s\n     ours   %s%s"
                      % (vd["field"], vd["golden_decoded"][:90],
                         vd["our_decoded"][:90], extra))
    print("-" * 78)
    print("TIMESTAMP STORY:")
    print(json.dumps(report["timestamp_story"], indent=1))
    print("CLICK STORY golden vs ours:")
    print(json.dumps(report["click_story"], indent=1)[:2000])
    print("REQUEST LINE golden vs ours:")
    print(json.dumps(report["request_line"], indent=1))


if __name__ == "__main__":
    main()

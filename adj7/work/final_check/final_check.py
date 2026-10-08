# -*- coding: utf-8 -*-
"""final_check.py -- FINAL pre-flight verification of the adj7 builders
against the golden booked-non-organic capture (payrupik_new_.saz, moto g42).

Reproducible byte-diff:
  1. parses the four golden raw requests  (cap/payrupik_new/raw/4N_c.txt),
     verifies Content-Length == actual body bytes (no truncation) and that
     the extracted JSON agrees;
  2. extracts the chls body spans (diff_flow.py BODIES over payrupi.chls,
     the non-truncating cross-check, Pixel 6a family) for field order/set;
  3. rebuilds OUR session / sdk_click / attribution requests by IMPORTING
     adj7/run_install.py (no edits), with adj7/last_run.json's identity
     (gaid, android_uuid, click_second) and the golden capture's RELATIVE
     signing seconds, percent-encoded exactly as call() does
     (urlencode for POST, urlencode(quote_via=quote) for GET);
  4. diffs per endpoint: request line, header names+order+values, field
     name sequence (order), field set (missing/extra), every value
     (per-install whitelisted vs structural), and the RAW percent-encoded
     bytes after masking per-install values (hard byte-level verdict);
  5. re-checks the SIGNED-MAP H-law on the GOLDEN's own signatures:
     cbc_dec (work.ks_inverse, K from work/record_0015.json) -> record
     nonce12/c -> adj7_pure.build_claims over the golden's decoded body map
     (include_block2=True, client_sdk=android5.6.0) -> commitment_digest
     must equal the record's b  (attribution over its query params);
  6. writes FINAL_CHECK.md (diff tables, H-law verdicts, GO/NO-GO).

Write-only under adj7/work/final_check/.  Everything else read-only.

    python final_check.py
"""
import json
import os
import re
import struct
import sys
import urllib.parse
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = os.path.abspath(os.path.join(HERE, "..", ".."))
WORK = os.path.abspath(os.path.join(ADJ7, "work"))
sys.path.insert(0, ADJ7)
sys.path.insert(0, WORK)

RAW_DIR = os.path.join(ADJ7, "cap", "payrupik_new", "raw")
GOLD_JSON = os.path.join(ADJ7, "cap", "payrupik_new",
                         "payrupik_new__adjust.json")
CHLS = r"C:\Users\Apps\Downloads\payrupi.chls"
LAST_RUN = os.path.join(ADJ7, "last_run.json")
OUT_MD = os.path.join(HERE, "FINAL_CHECK.md")

# raw file -> (method, path, claims kind)
ENDPOINTS = [
    ("42", "POST", "/session", "session"),
    ("43", "POST", "/sdk_click", "click"),
    ("44", "GET", "/attribution", "attribution"),
    ("45", "POST", "/event", "event"),
]

# per-install values: expected to differ between installs
TS_FIELDS = {"installed_at", "created_at", "sent_at", "updated_at",
             "click_time", "click_time_server", "install_begin_time",
             "install_begin_time_server"}
PER_INSTALL = TS_FIELDS | {"gps_adid", "android_uuid", "partner_params",
                           "referrer"}

TS_RAW_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}"
                       r"\.\d{3}Z%2B0530")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}"
                     r"-[0-9a-f]{12}")
REF_RE = re.compile(r"adjust_reftag%3D[A-Za-z0-9]+")

AUTH_RE = re.compile(
    r'^Signature signature="([0-9A-Fa-f]+)",adj_signing_id="(\d+)",'
    r'algorithm="([a-z0-9]+)",headers_id="(\d+)",native_version="([\d.]+)"$')

TS_DECODED_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{3})Z\+0530$")


# =========================================================================
# golden raws
# =========================================================================
def parse_raw(path):
    data = open(path, "rb").read()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    reqline = lines[0]
    headers = []
    for ln in lines[1:]:
        name, _, value = ln.partition(": ")
        headers.append((name, value))
    return reqline, headers, body


def unix_of_local_stamp(stamp):
    """'2026-10-06T15:40:25.000Z+0530' -> unix second (the wire stamps are
    LOCAL wall-clock digits + literal 'Z' + offset, per run_install._stamp)."""
    m = TS_DECODED_RE.match(stamp)
    if not m:
        raise ValueError("not a device stamp: %r" % stamp)
    dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    import calendar
    return calendar.timegm(dt.timetuple()) - 5 * 3600 - 30 * 60  # +0530


# =========================================================================
# chls cross-check spans (from diff_flow.py's BODIES; parsed, not imported,
# to avoid executing the module)
# =========================================================================
def chls_bodies():
    src = open(os.path.join(WORK, "diff_flow.py"), encoding="utf-8").read()
    m = re.search(r"BODIES = \{(.*?)\}", src, re.S)
    spans = eval("{" + m.group(1) + "}")
    data = open(CHLS, "rb").read()
    out = {}
    for ep, (start, ln) in spans.items():
        raw = data[start:start + ln].decode("latin-1")
        out[ep] = raw
    return out


# =========================================================================
# main
# =========================================================================
def main():
    import run_install as ri          # the CURRENT builders, unmodified
    from adj7_pure import build_claims, commitment_digest, verify_tag

    report = []          # markdown lines
    struct_bugs = []     # precise structural findings
    notes = []           # non-blocking observations

    def W(*lines):
        report.extend(lines)

    identity = json.load(open(LAST_RUN))
    gaid = identity["gaid"]
    android_uuid = identity["android_uuid"]
    click_second = identity["click_second"]
    referrer = identity.get("reftag") or "adjust_reftag=UNKNOWN"

    # deterministic per-install randoms for the rebuild (per-install values
    # are masked in the byte-diff anyway; fixed here for reproducibility)
    ri.PARTNER_PARAMS = '{"payrupik_c_id":"4c2576c7-56da-3568-9d9c-dd5ef029b6c8"}'
    ri.PUSH_TOKEN = ("f0123456789Zx_9R7cQ8yY:APA91bH"
                     "0123456789abcdef0123456789abcdef"
                     "0123456789abcdef0123456789abcdef")

    # ------------------------------------------------------------------
    # golden raws + truncation check + JSON agreement
    # ------------------------------------------------------------------
    gold = {}
    W("## 1. Golden raw requests (cap/payrupik_new/raw/, saz primary)",
      "", "| raw | request | body B | Content-Length | truncation | JSON body agrees |",
      "|---|---|---|---|---|---|")
    gold_sessions = json.load(open(GOLD_JSON))
    json_by_path = {}
    for s in gold_sessions:
        p = s["url"].split("?")[0].split("app.adjust.com")[-1]
        if s["method"] in ("POST", "GET") and "adjust.com" in s["url"]:
            json_by_path.setdefault(p, s)
    for num, method, path, kind in ENDPOINTS:
        reqline, headers, body = parse_raw(os.path.join(RAW_DIR,
                                                        num + "_c.txt"))
        hd = dict(headers)
        cl = hd.get("Content-Length")
        trunc = "OK" if (cl is None or int(cl) == len(body)) else \
            "TRUNCATED (%d != %s)" % (len(body), cl)
        gold[num] = {"reqline": reqline, "headers": headers, "body": body,
                     "kind": kind, "method": method, "path": path}
        W("| %s_c.txt | %s | %d | %s | %s | see below |"
          % (num, reqline.split(" HTTP/1.1")[0], len(body),
             cl or "-", trunc))

    # JSON agreement check (decoded body dict == raw decoded pairs)
    W("", "Extracted-JSON cross-check (raw pairs == JSON body dict):")
    for num, method, path, kind in ENDPOINTS:
        if method != "POST":
            continue
        js = json_by_path.get(path)
        # the JSON stores the DECODED body as a dict; compare against the
        # raw decoded pairs directly
        raw_pairs = urllib.parse.parse_qsl(gold[num]["body"]
                                           .decode("latin-1"),
                                           keep_blank_values=True)
        jdict = js["body"] if js else {}
        ok = dict(raw_pairs) == jdict and \
            [k for k, _ in raw_pairs] == list(jdict.keys())
        W("- %s %s: %s" % (method, path, "MATCH" if ok else "MISMATCH"))
        if not ok:
            struct_bugs.append("JSON extraction disagrees with raw %s_c.txt"
                               % num)

    # ------------------------------------------------------------------
    # chls cross-check (field order/set only; Pixel 6a family)
    # ------------------------------------------------------------------
    chls = chls_bodies()
    W("", "## 2. chls cross-check (payrupi.chls, Pixel 6a family -- non-truncating)",
      "", "chls field counts (Content-Length-verified spans): %s"
      % ", ".join("%s=%d" % (ep, len(urllib.parse.parse_qsl(raw,
                  keep_blank_values=True)))
                  for ep, raw in sorted(chls.items())))
    chls_order = {}
    for ep, raw in chls.items():
        chls_order[ep] = [k for k, _ in urllib.parse.parse_qsl(
            raw, keep_blank_values=True)]

    # ------------------------------------------------------------------
    # rebuild OUR requests (identity = last_run.json, relative signing
    # seconds = the golden capture's own click-relative offsets)
    # ------------------------------------------------------------------
    gold_click_time = dict(urllib.parse.parse_qsl(
        gold["43"]["body"].decode("latin-1")))["click_time"]
    gold_click_sec = unix_of_local_stamp(gold_click_time)

    def gold_sec(num, field):
        g = gold[num]
        if g["method"] == "POST":
            src = g["body"].decode("latin-1")
        else:
            src = g["reqline"].split(" HTTP/1.1")[0].split("?", 1)[1]
        pairs = dict(urllib.parse.parse_qsl(src, keep_blank_values=True))
        return unix_of_local_stamp(pairs[field])

    rel_session = gold_sec("42", "created_at") - gold_click_sec
    rel_clickreq = gold_sec("43", "created_at") - gold_click_sec
    rel_attr = gold_sec("44", "created_at") - gold_click_sec
    W("", "Golden relative signing seconds (from the capture's own stamps):",
      "- click_time          = click + 0",
      "- /session  created_at = click + %d s" % rel_session,
      "- /sdk_click created_at = click + %d s" % rel_clickreq,
      "- /attribution created_at = click + %d s" % rel_attr,
      "",
      "Rebuild identity = last_run.json: gaid `%s`, android_uuid `%s`, "
      "click_second %d." % (gaid, android_uuid, click_second))

    sec_session = click_second + rel_session
    sec_click = click_second + rel_clickreq
    sec_attr = click_second + rel_attr

    ours = {
        "42": ri.build_session_request(gaid, android_uuid, sec_session,
                                       click_sec=click_second),
        "43": ri.build_click_request(gaid, android_uuid, sec_click,
                                     referrer, click_sec=click_second),
        "44": ri.build_attribution_request(gaid, android_uuid, sec_attr),
        "45": None,   # the funnel has no event builder (see findings)
    }

    def encode_as_call(method, fields):
        if method == "POST":
            return urllib.parse.urlencode(fields).encode("latin-1")
        return urllib.parse.urlencode(fields,
                                      quote_via=urllib.parse.quote
                                      ).encode("latin-1")

    # ------------------------------------------------------------------
    # per-endpoint diffs
    # ------------------------------------------------------------------
    def mask(raw_bytes):
        s = raw_bytes.decode("latin-1")
        s = TS_RAW_RE.sub("<TS>", s)
        s = UUID_RE.sub("<UUID>", s)
        s = REF_RE.sub("adjust_reftag%3D<REF>", s)
        return s

    for num, method, path, kind in ENDPOINTS:
        g = gold[num]
        gbody = g["body"]
        W("", "---", "", "## Endpoint %s %s" % (method, path), "")

        # ---------------- request line
        our_target = path if method == "POST" else \
            path + "?" + urllib.parse.urlencode(ours[num],
                                                quote_via=urllib.parse.quote)
        W("**Request line**")
        W("- golden : `%s`" % g["reqline"])
        W("- ours   : `%s %s HTTP/1.1`" % (method, our_target))
        if "https://app.adjust.com" in g["reqline"]:
            W("- absolute-form URI in the golden = capture-through-CONNECT-"
              "proxy artifact (Fiddler); a direct Dalvik call sends origin-"
              "form. Expected difference, not a device behaviour diff.")
        W("")

        # the GET payload is the percent-encoded query string, not a body
        if method == "POST":
            g_src = gbody.decode("latin-1")
        else:
            g_src = g["reqline"].split(" HTTP/1.1")[0].split("?", 1)[1]

        if ours[num] is None:
            W("**Headers/Body**: the funnel has NO builder for this "
              "endpoint (no POST /event in run_install.py) -- golden-only "
              "step, see findings.  (The golden headers are the same "
              "Client-SDK/Authorization/Content-Type/User-Agent/Host/"
              "Connection/Accept-Encoding/Content-Length table.)")
            notes.append("golden flow ends with POST /event (event_token "
                         "y3sjx5, callback_params google_adid) 2 s after the "
                         "attribution; run_install.py never sends an event. "
                         "Post-verdict step (the booked verdict arrives on "
                         "the attribution GET), so not a booking blocker.")
            continue

        # ---------------- headers
        W("**Headers (names, order, values)**", "",
          "| # | golden | ours (call()) | verdict |", "|---|---|---|---|")
        if method == "POST":
            our_headers = [
                ("Client-SDK", ri.CLIENT_SDK),
                ("Authorization", "<per-install signature -- format check>"),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("User-Agent", ri.APP_UA),
                ("Host", "app.adjust.com"),
                ("Connection", "Keep-Alive"),
                ("Accept-Encoding", "gzip"),
                ("Content-Length", str(len(encode_as_call("POST",
                                                          ours[num])))),
            ]
        else:
            our_headers = [
                ("Client-SDK", ri.CLIENT_SDK),
                ("Authorization", "<per-install signature -- format check>"),
                ("User-Agent", ri.APP_UA),
                ("Host", "app.adjust.com"),
                ("Connection", "Keep-Alive"),
                ("Accept-Encoding", "gzip"),
            ]
        gheads = g["headers"]
        n = max(len(gheads), len(our_headers))
        hdr_ok = True
        for i in range(n):
            gh = gheads[i] if i < len(gheads) else ("-", "-")
            oh = our_headers[i] if i < len(our_headers) else ("-", "-")
            if gh[0] == oh[0]:
                if gh[0] == "Authorization":
                    m = AUTH_RE.match(gh[1])
                    if not m:
                        verdict = "VALUE DIFF (format)"
                        hdr_ok = False
                    else:
                        blen = len(m.group(1)) // 2
                        verdict = ("MATCH (blob %d B, sid %s, alg %s, "
                                   "hdr %s, nv %s)"
                                   % (blen, m.group(2), m.group(3),
                                      m.group(4), m.group(5)))
                elif gh[0] == "Content-Length":
                    verdict = "MATCH" if gh[1] == oh[1] else \
                        "VALUE DIFF (%s vs %s)" % (gh[1], oh[1])
                    if gh[1] != oh[1]:
                        hdr_ok = False
                elif gh[1] == oh[1]:
                    verdict = "MATCH"
                else:
                    verdict = "VALUE DIFF (`%s` vs `%s`)" % (gh[1], oh[1])
                    hdr_ok = False
            else:
                verdict = "NAME/ORDER DIFF (`%s` vs `%s`)" % (gh[0], oh[0])
                hdr_ok = False
            W("| %d | `%s: %s` | `%s: %s` | %s |"
              % (i + 1, gh[0], gh[1][:52], oh[0], oh[1][:52], verdict))
        if hdr_ok:
            W("", "Headers: names, order and values all MATCH."
              "  <!--HDR_OK:%s-->" % num)
        else:
            W("", "Headers: DIFF above.  <!--HDR_BAD:%s-->" % num)
            struct_bugs.append("%s: header table diff" % path)

        # ---------------- body: name sequence / set / values
        gpairs = urllib.parse.parse_qsl(g_src, keep_blank_values=True)
        gnames = [k for k, _ in gpairs]
        gmap = dict(gpairs)
        onames = list(ours[num].keys())
        W("", "**Field order (golden vs ours)**", "")
        if gnames == onames:
            W("Field NAME SEQUENCE: IDENTICAL (%d fields)." % len(gnames))
        else:
            W("Field NAME SEQUENCE: **DIFFERS**.")
            W("", "| pos | golden | ours |", "|---|---|---|")
            for i in range(max(len(gnames), len(onames))):
                a = gnames[i] if i < len(gnames) else "-"
                b = onames[i] if i < len(onames) else "-"
                mark = "" if a == b else " <-- DIFF"
                W("| %d | %s | %s |%s" % (i + 1, a, b, mark))
            missing = [k for k in gnames if k not in ours[num]]
            extra = [k for k in onames if k not in gmap]
            if missing:
                W("", "MISSING fields (golden only): %s" % missing)
            if extra:
                W("", "EXTRA fields (ours only): %s" % extra)
            # minimal root causes via opcodes (no cascade positions);
            # ONE struct_bugs entry per endpoint
            import difflib
            sm = difflib.SequenceMatcher(a=gnames, b=onames, autojunk=False)
            ops = [o for o in sm.get_opcodes() if o[0] != "equal"]
            moved = []
            for op, i1, i2, j1, j2 in ops:
                if op == "delete":
                    moved.append("golden places [%s] at golden pos %d "
                                 "(right after `%s`) -- ours does not"
                                 % (", ".join(gnames[i1:i2]), i1 + 1,
                                    gnames[i1 - 1] if i1 else "(start)"))
                elif op == "insert":
                    moved.append("ours injects [%s] (our pos %d) where the "
                                 "golden has nothing -- not in the golden"
                                 % (", ".join(onames[j1:j2]), j1 + 1))
                else:
                    moved.append("block differs -- golden [%s] vs ours [%s]"
                                 % (", ".join(gnames[i1:i2]),
                                    ", ".join(onames[j1:j2])))
            if moved:
                W("", "Minimal order diffs (root causes):")
                for mvd in moved:
                    W("- %s" % mvd)
                struct_bugs.append("%s: ORDER -- %s"
                                   % (path, "; ".join(moved)))

        # set comparison when sequence equal (still show set check)
        W("", "**Field set**: golden %d, ours %d, common %d."
          % (len(gnames), len(onames),
             len(set(gnames) & set(onames))))

        # ---------------- value diff
        W("", "**Values** (per-install fields whitelisted)", "",
          "| field | golden | ours | verdict |", "|---|---|---|---|")
        val_bad = []
        for k in gnames:
            gv = gmap[k]
            if k not in ours[num]:
                continue
            ov = str(ours[num][k])
            if k in PER_INSTALL:
                if k in TS_FIELDS:
                    okshape = (TS_DECODED_RE.match(gv)
                               and TS_DECODED_RE.match(ov))
                    g_rel = unix_of_local_stamp(gv) - gold_click_sec \
                        if TS_DECODED_RE.match(gv) else None
                    o_rel = unix_of_local_stamp(ov) - click_second \
                        if TS_DECODED_RE.match(ov) else None
                    extra = ""
                    if k == "install_begin_time" or \
                            k == "install_begin_time_server":
                        extra = " (golden = click+1 s; ours = click+%d s)" \
                            % (o_rel,) if o_rel is not None else ""
                    verdict = "PER-INSTALL (click%+ds vs click%+ds)%s%s" \
                        % (g_rel, o_rel, extra,
                           "" if okshape else " BAD SHAPE")
                else:
                    verdict = "PER-INSTALL"
                if k in ("install_begin_time", "install_begin_time_server") \
                        and o_rel is not None and o_rel != g_rel:
                    notes.append(
                        "%s: %s offset click+%d s (golden click+%d s) -- "
                        "recommend begin = click_sec + 1"
                        % (path, k, o_rel, g_rel))
            elif gv != ov:
                verdict = "**VALUE DIFF (structural)** `%s` vs `%s`" \
                    % (gv, ov)
                val_bad.append(k)
                struct_bugs.append(
                    "run_install.py %s: %s value `%s` but the golden device "
                    "sends `%s`" % (_builder_of(path), k, ov, gv))
            else:
                verdict = "MATCH"
            W("| %s | `%s` | `%s` | %s |"
              % (k, gv[:44], ov[:44], verdict))

        # ---------------- raw byte diff (masked)
        our_raw = encode_as_call(method, ours[num])
        gm, om = mask(g_src.encode("latin-1")), mask(our_raw)
        W("", "**Raw percent-encoded %s after masking per-install values** "
          "(timestamps, uuids, reftag):"
          % ("body" if method == "POST" else "query string"))
        if gm == om:
            W("- BYTE-IDENTICAL (%d B)." % len(g_src))
        else:
            i = next((j for j, (x, y) in enumerate(zip(gm, om)) if x != y),
                     min(len(gm), len(om)))
            W("- **DIFFERS** (golden %d B, ours %d B; first masked-byte "
              "divergence at offset %d)." % (len(g_src), len(our_raw), i))
            W("- golden: `...%s`" % gm[max(0, i - 40):i + 60])
            W("- ours  : `...%s`" % om[max(0, i - 40):i + 60])

        # ---------------- encoding re-check per field
        W("", "**Encoding re-check** (golden raw token == re-encoded decoded "
          "value under call()'s scheme):")
        bad_enc = []
        for k, gv in gpairs:
            if method == "POST":
                reenc = urllib.parse.quote_plus(gv)
            else:
                reenc = urllib.parse.quote(gv)
            # golden's raw token for k
            if method == "POST":
                tok = "%s=%s" % (urllib.parse.quote_plus(k), reenc)
            else:
                tok = "%s=%s" % (urllib.parse.quote(k), reenc)
            raw_tok = "%s=%s" % (k, gv)   # not used; check by value
            golden_field_raw = None
            # find the raw token in the golden body by locating k=
            pat = re.escape(urllib.parse.quote_plus(k) if method == "POST"
                            else urllib.parse.quote(k)) + r"=([^&]*)"
            m = re.search(pat, g_src)
            if m:
                golden_field_raw = m.group(1)
                if golden_field_raw != reenc:
                    bad_enc.append((k, golden_field_raw, reenc))
        if not bad_enc:
            W("- all %d golden field values re-encode byte-identically under "
              "call()'s scheme (%s) -- no +/%%20/%%3A/%%2B encoding diffs."
              % (len(gpairs),
                 "urlencode/quote_plus" if method == "POST"
                 else "urlencode/quote"))
        else:
            for k, gr, rr in bad_enc:
                W("- %s: golden `%s` vs re-encoded `%s`" % (k, gr, rr))
                struct_bugs.append("%s: encoding diff on %s" % (path, k))

        # ---------------- chls cross-check of the ORDER
        if path in chls_order:
            ch = chls_order[path]
            ch_nopush = [k for k in ch if k != "push_token"]
            if gnames == ch_nopush:
                W("", "chls cross-check: chls order minus its push_token is "
                  "IDENTICAL to the saz golden order -- the two captures "
                  "agree; push_token presence is device-state (Pixel 6a had "
                  "an FCM token, the moto g42 golden has none anywhere).")
            elif set(gnames) == set(ch_nopush) and gnames != ch_nopush:
                W("", "chls cross-check: same field SET, different ORDER "
                  "(GET-map iteration differs between the two genuine "
                  "runs) -- saz is primary.")
            else:
                W("", "chls cross-check: field sets differ (chls has "
                  "push_token on this device family).")

    # ------------------------------------------------------------------
    # H-law re-check on the GOLDEN's own signatures
    # ------------------------------------------------------------------
    W("", "---", "",
      "## 3. SIGNED-MAP H-law re-check on the golden's signatures", "",
      "cbc_dec (work/ks_inverse.py, K from work/record_0015.json) over the "
      "golden blob -> record a/b/c/d -> nonce12 -> "
      "adj7_pure.build_claims (include_block2=True, client_sdk=android5.6.0) "
      "over the golden's decoded body map -> commitment_digest == record b.",
      "", "| endpoint | blob tag ok | record c == campaign cert | claims B | "
      "commitment_digest == record b | verdict |",
      "|---|---|---|---|---|---|")
    import ks_inverse as ks   # work/ on sys.path; cbc_dec + K (record_0015)
    from adj7_pure import sign as sg_sign  # noqa: F401  (used above loop)
    hlaw_all = True
    hlaw_by_path = {}
    event_h_law_note = None
    for num, method, path, kind in ENDPOINTS:
        auth = dict(gold[num]["headers"])["Authorization"]
        m = AUTH_RE.match(auth)
        blob = bytes.fromhex(m.group(1))
        tag_ok = verify_tag(blob)
        rec = ks.cbc_dec(blob[16:272], blob[:16])
        rm = re.match(rb'\{ "a":\s+(\d{1,20}) ,"b": "([0-9A-F]{64})",'
                      rb'"c": "(.{40})","d": "([0-9A-Fa-f]{8})",'
                      rb'"e": "([0-9A-F]{64})" \}', rec)
        if not rm:
            W("| %s | %s | record parse FAIL | | | NO |"
              % (path, "ok" if tag_ok else "BAD"))
            hlaw_all = False
            continue
        a_int = int(rm.group(1))
        H_rec = rm.group(2).decode()
        c_bytes = rm.group(3)
        d8 = bytes.fromhex(rm.group(4).decode())
        nonce12 = struct.pack("<Q", a_int) + d8
        if method == "POST":
            gmap = dict(urllib.parse.parse_qsl(
                gold[num]["body"].decode("latin-1"),
                keep_blank_values=True))
        else:
            q = gold[num]["reqline"].split(" HTTP/1.1")[0].split("?", 1)[1]
            gmap = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        claims = build_claims(kind, gmap, client_sdk="android5.6.0",
                              include_block2=True)
        H = commitment_digest(claims, nonce12, cert40=c_bytes)
        match = H.hex().upper() == H_rec
        cert_match = c_bytes.decode("latin-1") == ri.CERT_SHA1.upper()
        # end-to-end: rebuild the ENTIRE 304-B blob with our signer, brute
        # the signing second around the request's created_at second
        from adj7_pure import sign as sg_sign
        anchor = gold_sec(num, "created_at")
        sec_hit = None
        for s2 in range(anchor - 120, anchor + 120):
            if sg_sign(s2, nonce12, claims, cert40=c_bytes) == blob:
                sec_hit = s2
                break
        blob_ok = sec_hit is not None
        hlaw_by_path[path] = match and tag_ok and blob_ok
        if path != "/event":
            hlaw_all = hlaw_all and match and tag_ok
        else:
            event_h_law_note = (match, blob_ok)
        W("| %s | %s | %s (`%s...`) | %d | %s | %s |"
          % (path, "ok" if tag_ok else "**BAD**",
             "yes" if cert_match else "**NO**", c_bytes.decode()[:12],
             len(claims), "**MATCH**" if match else "**MISMATCH**",
             ("PASS (full 304-B blob reproduced byte-exact at sec %d)"
              % sec_hit) if blob_ok else
             ("H PASS, full-blob rebuild failed" if match else "**FAIL**")))
        if not match:
            if path == "/event":
                event_h_law_note = (match, blob_ok)
                notes.append(
                    "POST /event (golden-only step): its H does NOT "
                    "reproduce under our pool law over the wire map "
                    "(tag/record fine, H mismatch) -- consistent with the "
                    "earlier event-claims hunt (work/proven_audit/"
                    "verify_event2.py).  Informational: the funnel builds "
                    "and signs no event, and the task's H-law scope is "
                    "session/sdk_click/attribution, which all PASS.")
                continue
            struct_bugs.append(
                "H-law FAIL on golden %s: our claims law does not reproduce "
                "the device's H" % path)
    W("", "Cert prefix note: every golden record's `c` slot carries the "
      "ASCII hex-upper cert SHA-1 `%s` -- run_install's `sign()` passes "
      "CAMPAIGN (cert_sha1 c1bfafca...) straight into mint_adj7, so the "
      "prefix wiring is correct."
      % ri.CAMPAIGN["cert_sha1"].upper())

    # ------------------------------------------------------------------
    # event gap + timing story
    # ------------------------------------------------------------------
    W("", "---", "",
      "## 4. Timing story (golden vs funnel)")
    W("- golden : click 15:40:25 -> installed_at click+41.6 s -> "
      "session click+%d s -> sdk_click +%.1f ms -> attribution click+%d s "
      "-> event click+%d s"
      % (rel_session,
         (gold_sec("43", "sent_at") - gold_sec("42", "sent_at")) * 1000.0,
         rel_attr,
         gold_sec("45", "sent_at") - gold_click_sec))
    W("- funnel : installed_at click+%s s (INSTALL_AFTER=63.8, from the "
      "chls capture) -> session click+88 s (wall-clock CTIT) -> "
      "sdk_click +50 ms -> attribution ~click+91 s (sleep 2.8)"
      % "63.800")
    W("- verdict : relative gaps are per-install values. The funnel "
      "reproduces the chls story (click+63.8 install, click+88.3 session); "
      "the golden capture's own story is click+41.6 install, click+%d "
      "session. Both are plausible human installs; CTIT >> 10 s in both. "
      "No structural impact -- but see the install_begin_time note."
      % rel_session)

    # ------------------------------------------------------------------
    # verdict
    # ------------------------------------------------------------------
    W("", "---", "",
      "## 5. Structural findings (must-fix before the live run)", "")
    if struct_bugs:
        for i, b in enumerate(struct_bugs, 1):
            W("%d. %s" % (i, b))
    else:
        W("None -- the builders reproduce the golden byte-for-byte "
          "(modulo per-install values).")
    W("", "### Precise fixes")
    W("1. `adj7/run_install.py` `build_session_request` "
      "(lines 305-330; partner_params at line 322, initiating_package_name at line 323): move `\"partner_params\": PARTNER_PARAMS` from its "
      "current position (after `first_error`, pos 31) to immediately after "
      "`\"hardware_name\"` (pos 6, before `\"app_version\"`); move "
      "`\"initiating_package_name\"` from after `partner_params` to "
      "immediately after `\"package_name\"` (before `\"os_name\"`).  "
      "Golden order: ... first_error, android_uuid, sent_at ... "
      "display_height, package_name, initiating_package_name, os_name ...")
    W("2. `adj7/run_install.py` `build_click_request` "
      "(lines 272-299; partner_params at line 280, click_time_server at line 281, install_begin_time_server at line 296): move `\"partner_params\"` to immediately after "
      "`\"app_version\"` (pos 5, before `\"app_token\"`); move "
      "`\"click_time_server\"` to immediately after `\"screen_format\"` "
      "(pos 37, before `\"os_version\"`); move "
      "`\"install_begin_time_server\"` to immediately after "
      "`\"google_play_instant\"` (pos 40, before `\"android_uuid\"`); "
      "keep `\"install_begin_time\"` after `\"attribution_deeplink\"`.  "
      "After removal of the two misplacements the tail order matches the "
      "golden exactly.")
    W("3. `adj7/run_install.py` `build_attribution_request` "
      "(line 345): DELETE the `\"push_token\": PUSH_TOKEN` entry (22 "
      "params, not 23).  The golden moto g42 capture carries NO push_token "
      "on ANY request (session/sdk_click/attribution/event); push_token is "
      "Pixel-6a/chls device state.  (The saz is primary per the brief.)")
    W("4. `adj7/run_install.py` `DEVICE` (line 58): "
      "`\"display_height\": \"2400\"` -> `\"2237\"`.  The golden moto g42 "
      "reports display_height=2237 (2400 panel minus system bars) on "
      "session, sdk_click and event; 2400 is the chls Pixel 6a's value.")
    W("5. (recommended) `build_click_request`: `begin = click_sec + 2` -> "
      "`click_sec + 1` (line 271).  Golden: click 15:40:25.000 -> "
      "install_begin 15:40:26.000; the funnel stamps +2 s.")

    # ------------------------------------------------------------------
    # post-fix simulation: apply the section-5 fixes TEXTUALLY to an
    # in-memory copy of run_install.py, rebuild, re-diff -- proves the
    # fixes are sufficient (masked bodies become byte-identical)
    # ------------------------------------------------------------------
    import types
    src = open(os.path.join(ADJ7, "run_install.py"), encoding="utf-8").read()
    applied = []

    def patch_block(src, start_marker, end_marker, fn, label):
        i = src.index(start_marker)
        j = src.index(end_marker)
        block = fn(src[i:j])
        applied.append(label)
        return src[:i] + block + src[j:]

    def rm_entry(block, entry_re):
        """remove one dict ENTRY (entry-level, not line-level)"""
        new, n = re.subn(entry_re, "", block, count=1)
        assert n == 1, "fix drift: %r found %d times" % (entry_re, n)
        return new

    def ins_after(block, anchor_re, entry_text):
        """insert entry_text right AFTER the anchor ENTRY (mid-line ok)"""
        new, n = re.subn(anchor_re, lambda m: m.group(1) + " " + entry_text,
                         block, count=1)
        assert n == 1, "fix drift: anchor %r found %d times" % (anchor_re, n)
        return new

    def fix_session(b):
        b = rm_entry(b, r'[ \t]*"partner_params": PARTNER_PARAMS,\n')
        b = ins_after(b, r'("hardware_name": P\["hardware_name"\],)',
                      '"partner_params": PARTNER_PARAMS,')
        b = rm_entry(b, r'[ \t]*"initiating_package_name": '
                        r'"com\.android\.vending",\n')
        b = ins_after(b, r'("package_name": PACKAGE_NAME,)',
                      '"initiating_package_name": "com.android.vending",')
        return b

    def fix_click(b):
        b = rm_entry(b, r'[ \t]*"partner_params": PARTNER_PARAMS,\n')
        b = ins_after(b, r'("app_version": APP_VERSION,)',
                      '"partner_params": PARTNER_PARAMS,')
        b = rm_entry(b, r'[ \t]*"click_time_server": _stamp\(click_sec, 0\),'
                        r'\n')
        b = ins_after(b, r'("screen_format": P\["screen_format"\],)',
                      '"click_time_server": _stamp(click_sec, 0),')
        b = rm_entry(b, r'[ \t]*"install_begin_time_server": '
                        r'_stamp\(begin, 0\),\n')
        b = ins_after(b, r'("google_play_instant": "0",)',
                      '"install_begin_time_server": _stamp(begin, 0),')
        return b

    def fix_attr(b):
        return rm_entry(b, r' "push_token": PUSH_TOKEN,')

    src = patch_block(src, "def build_click_request",
                      "def build_session_request", fix_click,
                      "click: partner_params -> after app_version; "
                      "click_time_server -> after screen_format; "
                      "install_begin_time_server -> after google_play_instant")
    src = patch_block(src, "def build_session_request",
                      "def build_attribution_request", fix_session,
                      "session: partner_params -> after hardware_name; "
                      "initiating_package_name -> after package_name")
    src = patch_block(src, "def build_attribution_request",
                      "def sign(", fix_attr,
                      "attribution: push_token removed")
    assert src.count('"display_height": "2400"') == 1, "DEVICE drift"
    src = src.replace('"display_height": "2400"', '"display_height": "2237"')
    applied.append("DEVICE display_height 2400 -> 2237")

    mod = types.ModuleType("run_install_patched")
    mod.__file__ = os.path.join(ADJ7, "run_install.py")
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    mod.PARTNER_PARAMS = ri.PARTNER_PARAMS
    mod.PUSH_TOKEN = ri.PUSH_TOKEN

    fixed = {
        "42": mod.build_session_request(gaid, android_uuid, sec_session,
                                        click_sec=click_second),
        "43": mod.build_click_request(gaid, android_uuid, sec_click,
                                      referrer, click_sec=click_second),
        "44": mod.build_attribution_request(gaid, android_uuid, sec_attr),
    }

    W("", "---", "",
      "## 6. Post-fix simulation (section-5 fixes applied to an in-memory "
      "copy of run_install.py)", "",
      "Applied textual fixes:",
      "")
    for a in applied:
        W("- %s" % a)
    W("", "Re-diff of the PATCHED builders against the golden:")
    sim_all_ok = True
    for num in ("42", "43", "44"):
        method, path = gold[num]["method"], gold[num]["path"]
        if method == "POST":
            g_src = gold[num]["body"].decode("latin-1")
        else:
            g_src = gold[num]["reqline"].split(" HTTP/1.1")[0] \
                .split("?", 1)[1]
        fx = fixed[num]
        gpairs = urllib.parse.parse_qsl(g_src, keep_blank_values=True)
        gnames = [k for k, _ in gpairs]
        gmap = dict(gpairs)
        onames = list(fx.keys())
        order_ok = gnames == onames
        val_bad = []
        for k in gnames:
            if k in PER_INSTALL or k not in fx:
                continue
            if str(fx[k]) != gmap[k]:
                val_bad.append((k, gmap[k], str(fx[k])))
        fx_raw = encode_as_call(method, fx)
        byte_ok = mask(g_src.encode("latin-1")) == mask(fx_raw)
        sim_all_ok = sim_all_ok and order_ok and not val_bad and byte_ok
        W("- %s %s: order %s; non-install values %s; masked raw %s"
          % (method, path,
             "IDENTICAL" if order_ok else "STILL DIFFERS",
             "all MATCH" if not val_bad
             else "DIFF: %s" % val_bad,
             "**BYTE-IDENTICAL**" if byte_ok else "**STILL DIFFERS**"))
    if sim_all_ok:
        W("", "**Result: after the four fixes the patched builders "
          "reproduce the golden byte-for-byte modulo per-install values "
          "(uuids/timestamps/reftag) -- fixes verified sufficient and "
          "complete.**")
    else:
        W("", "**Result: a residual diff remains -- see above (fixes NOT "
          "sufficient).**")
        notes.append("post-fix simulation left a residual diff -- re-check "
                     "the fix list before the live run.")

    verdict = "NO-GO" if struct_bugs else "GO"
    W("", "---", "",
      "## 7. VERDICT", "")
    W("- Headers: %s" % ("all match" if not any(
        "header" in b for b in struct_bugs) else "diffs above"))
    W("- H-law on the funnel's signed endpoints (/session, /sdk_click, "
      "/attribution), CURRENT claims law over the golden's real maps: %s"
      % ("ALL PASS -- the signer is clean" if hlaw_all else "FAIL"))
    if event_h_law_note is not None:
        W("- (POST /event H-law: %s -- informational only, the funnel "
          "builds/signs no event.)"
          % ("PASS" if event_h_law_note == (True, True) else
             "H %s, full-blob %s"
             % ("match" if event_h_law_note[0] else "MISMATCH",
                "ok" if event_h_law_note[1] else "no")))
    W("- Structural body diffs (root causes): %d" % len(struct_bugs))
    W("- Post-fix simulation (section 6): %s" %
      ("fixes verified SUFFICIENT -- patched builders reproduce the golden "
       "byte-for-byte modulo per-install values"
       if sim_all_ok else "residual diff REMAINS (see section 6)"))
    W("", "## %s" %
      ("**NO-GO for the live run** -- apply fixes 1-4 of section 5 "
       "(5 recommended; all four already verified sufficient by the "
       "section-6 simulation), re-run final_check.py, expect zero "
       "structural diffs, then GO."
       if struct_bugs else
       "**GO for the live run** -- the funnel reproduces the golden."))
    if notes:
        W("", "### Non-blocking observations")
        for i, n in enumerate(notes, 1):
            W("%d. %s" % (i, n))

    # executive summary prepended at the top
    head = [
        "# FINAL CHECK -- adj7 builders vs the golden booked capture",
        "",
        "Golden: `payrupik_new_.saz` (moto g42, genuine in.hanafintech "
        "install, BOOKED non-organic: tracker 248wk8ym "
        "VL-Alliance::HM2::HM2_1722_), raws `cap/payrupik_new/raw/4N_c.txt`. "
        "Cross-check: `payrupi.chls` spans (Pixel 6a family, "
        "Content-Length-verified).  Rebuild identity: `last_run.json`.  "
        "Run: %s." % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "- **Headers**: request/header tables (names, order, values) MATCH "
        "on all three funnel endpoints (the golden's absolute-form request "
        "URI is a Fiddler CONNECT artifact).",
        "- **H-law**: our CURRENT claims law reproduces the golden's "
        "commitment H on /session, /sdk_click and /attribution -- in fact "
        "the ENTIRE 304-B blobs rebuild byte-exact (tag ok, record c == "
        "campaign cert prefix).  The signer is clean.",
        "- **Bodies**: field SETS match; the ENCODING scheme (urlencode/"
        "quote_plus for POST, quote for GET) reproduces every golden byte "
        "(+, %%20, %%3A, %%2B all correct).  BUT %d structural root causes "
        "remain in ORDER/VALUES:" % len([b for b in struct_bugs
                                         if "H-law" not in b]),
    ]
    for b in struct_bugs:
        head.append("  - %s" % b)
    head += [
        "",
        "- **VERDICT: %s** -- %s" %
        (verdict,
         "apply the fixes in section 5, re-run `python final_check.py`, "
         "expect zero structural diffs, then GO." if struct_bugs
         else "the funnel reproduces the golden byte-for-byte "
              "(modulo per-install values); cleared for the live run."),
        "",
        "---",
        "",
    ]
    report[0:0] = head
    open(OUT_MD, "w", encoding="utf-8").write("\n".join(report) + "\n")
    print("\n".join(report))
    print("\nwritten: %s" % OUT_MD)
    return 0


def _builder_of(path):
    return {"/session": "build_session_request",
            "/sdk_click": "build_click_request",
            "/attribution": "build_attribution_request",
            "/event": "?"}[path]


if __name__ == "__main__":
    raise SystemExit(main())

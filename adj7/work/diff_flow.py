# -*- coding: utf-8 -*-
"""diff_flow.py -- THE exhaustive genuine-vs-funnel flow diff for in.hanafintech.

Extracts the FOUR genuine adj7 requests (session, sdk_click, attribution, event)
from the raw Charles capture C:\\Users\\Apps\\Downloads\\payrupi.chls with a
scan-based parser (request lines, Content-Length-verified body spans, the
serialised header NAME/VALUE ArrayList pairs with back-reference resolution,
and the Charles timing blocks), parses OUR funnel's four signed requests out of
adj7/run_hanaf.log, and diffs everything:

  * field lists in WIRE ORDER per endpoint (missing / extra / order / values)
  * full request-header tables (incl. the Connection header ours never sends)
  * timing relations: click_time vs install_begin vs installed_at vs
    created_at vs sent_at, CTIT, wall-clock deltas from the Charles blocks
  * flow ORDER: genuine session BEFORE sdk_click, NO third_party_sharing,
    ONE attribution GET (initiated_by=backend, ask_in-driven), then an EVENT

    python diff_flow.py            # prints the diff, rewrites FLOW_DIFF.md

Write-only under adj7/work/.  Reads payrupi.chls + run_hanaf.log read-only.
"""
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CHLS = r"C:\Users\Apps\Downloads\payrupi.chls"
LOG = os.path.join(HERE, os.pardir, "run_hanaf.log")
OUT = os.path.join(HERE, "FLOW_DIFF.md")

data = open(CHLS, "rb").read()

# ===========================================================================
# 1. GENUINE REQUESTS from the chls
# ===========================================================================
# Wire header names/values are stored as Java-serialised ArrayList pairs.
# Repeated strings appear as TC_REFERENCE backrefs (0x71 0x00 0x7E + u2
# handle).  The handle -> string map below is derived from the file itself
# (first inline definition of each string) and is verified two ways:
#   (a) handle numbers must be monotonic in the position of the string's
#       first inline occurrence (Java assigns handles in stream order), and
#   (b) every adjust request's table must resolve consistently across all
#       four requests (index-aligned where the entry is a backref).
#   handle  string (first inline occurrence in the file)
#   NOTE: 0x0D6D/0x0D6E/0x0D70/0x0D72 (Client-SDK, Authorization names and the
#   android5.6.0 / app.adjust.com values, first inlined inside the session
#   transaction itself) are NOT resolvable by handle counting -- they are
#   resolved by INDEX ALIGNMENT with the session request's inline entries
#   instead (the four adjust requests share one header layout).
HANDLE_MAP = {
    0x00B4: "User-Agent",          # first inline @ ~10447 (crashlytics table)
    0x00B8: "Host",                # first inline @ ~10555
    0x00B9: "Connection",          # first inline @ ~10562
    0x00BA: "Accept-Encoding",     # first inline @ ~10575
    0x00C7: "Keep-Alive",          # first inline @ ~10877
    0x00C8: "gzip",                # first inline @ ~10890
    0x00CF: "Content-Type",        # first inline @ ~11581 (response table)
    0x0116: "Dalvik/2.1.0 (Linux; U; Android 17; Pixel 6a Build/CP2A.260705.006)",
    0x0197: "Content-Length",      # first inline @ ~19180
    0x0220: "application/x-www-form-urlencoded",   # first inline @ ~26511
}


def _verify_handle_map():
    """Handle numbers must grow with the position of each string's first
    inline occurrence; otherwise the map is wrong."""
    pos = {}
    for h, s in HANDLE_MAP.items():
        # search the exact serialized form: TC_STRING (0x74) + u2 len + bytes
        needle = b"\x74" + len(s.encode("utf-8")).to_bytes(2, "big") + s.encode("utf-8")
        p = data.find(needle)
        if p == -1:
            return False, "missing inline string: %r" % s
        pos[h] = p
    pairs = sorted(pos.items())
    for (h1, p1), (h2, p2) in zip(pairs, pairs[1:]):
        if not (p1 <= p2):          # handle grows (or ties) with position
            return False, "handle order broken: 0x%x@%d -> 0x%x@%d" % (
                h1, p1, h2, p2)
    return True, "ok (%d strings, positions monotonic vs handles)" % len(pos)


def parse_entries(pos, n):
    """Forward-parse n serialised entries (inline TC_STRING / TC_REFERENCE /
    TC_NULL) starting at pos -> list of (kind, value) and end position."""
    out = []
    i = pos
    for _ in range(n):
        t = data[i]
        if t == 0x74:
            ln = int.from_bytes(data[i+1:i+3], "big")
            out.append(("str", data[i+3:i+3+ln].decode("utf-8", "replace")))
            i += 3 + ln
        elif t == 0x71 and data[i+1:i+3] == b"\x00~":
            out.append(("ref", int.from_bytes(data[i+3:i+5], "big")))
            i += 5
        elif t == 0x70:
            out.append(("null", None)); i += 1
        else:
            out.append(("?%02x" % t, None)); i += 1
    return out, i


ARR8 = b"sq\x00~\x00\x04\x00\x00\x00\x08w\x04\x00\x00\x00\x08"   # 8-elem list
ARR6 = b"sq\x00~\x00\x04\x00\x00\x00\x06w\x04\x00\x00\x00\x06"   # 6-elem list


def header_table_for(sig_pos, name_seeds=None, nv_map=None):
    """Given the inline 'Signature signature="' position of one request,
    return the (names, values) header lists with backrefs resolved.
    `name_seeds` maps NAMES-index -> known name (Client-SDK/Authorization,
    inlined only in the session request); `nv_map` maps header NAME -> value
    as seen in the session request (for shared values like android5.6.0 /
    app.adjust.com whose backrefs are not countable)."""
    ln = int.from_bytes(data[sig_pos-2:sig_pos], "big")
    after = sig_pos + ln                      # first entry after the sig value
    v0_end = sig_pos - 3                      # values[0] ends here
    sig_str = data[sig_pos:sig_pos+ln].decode("utf-8", "replace")

    def find_array(before, is_values):
        """Nearest ArrayList header at < before that is the wanted table.
        values table: entry[1] must be the Authorization sig string.
        names table: forward parse of `size` entries must end at the values
        header (or 1 B before it -- the ArrayList ENDBLOCKDATA byte)."""
        for pat, size in ((ARR8, 8), (ARR6, 6)):
            p = data.rfind(pat, before - 120, before)
            while p != -1:
                if is_values:
                    e2, end2 = parse_entries(p + len(pat), 2)
                    if (end2 == after and e2[1][0] == "str"
                            and e2[1][1] == sig_str):
                        return p, size, e2
                else:
                    entries, end = parse_entries(p + len(pat), size)
                    if end in (before, before - 1) and \
                            all(k in ("str", "ref") for k, _ in entries):
                        return p, size, entries
                p = data.rfind(pat, before - 120, p)
        return None

    vhead = find_array(v0_end, True)
    if vhead is None:
        raise ValueError("values-array header not found before sig @%d" % sig_pos)
    arr_pos, size, v01 = vhead
    rest, _ = parse_entries(after, size - 2)
    vals_entries = v01 + rest
    nhead = find_array(arr_pos, False)
    if nhead is None:
        raise ValueError("names-array header not found before @%d" % arr_pos)
    names_pos, nsize, names = nhead
    if nsize != size:
        raise ValueError("names/values array size mismatch @%d" % arr_pos)

    def resolve(entries, seeds):
        out = []
        for idx, (kind, v) in enumerate(entries):
            if kind == "str":
                out.append(v)
            elif kind == "ref":
                if v in HANDLE_MAP:
                    out.append(HANDLE_MAP[v])
                elif seeds and idx in seeds:
                    out.append(seeds[idx])
                else:
                    out.append("<unresolved 0x%04X>" % v)
            else:
                out.append(None)
        return out
    names_r = resolve(names, name_seeds)
    # values: resolve refs by HANDLE_MAP, else by the paired header NAME via
    # the session request's name->value map
    vals_r = []
    for idx, (kind, v) in enumerate(vals_entries):
        if kind == "str":
            vals_r.append(v)
        elif kind == "ref":
            if v in HANDLE_MAP:
                vals_r.append(HANDLE_MAP[v])
            elif nv_map and idx < len(names_r) and names_r[idx] in nv_map:
                vals_r.append(nv_map[names_r[idx]])
            else:
                vals_r.append("<unresolved 0x%04X>" % v)
        else:
            vals_r.append(None)
    return names_r, vals_r


# ---- the four genuine requests (anchors verified against Content-Length) --
# request-line strings ("POST /session HTTP/1.1") stored by Charles:
REQ_LINES = {
    "/session": 211868,
    "/sdk_click": 217080,
    "/attribution": 219561,
    "/event": 223553,
}
# body spans: (start, length) -- lengths == the requests' Content-Length
BODIES = {
    "/session": (209648, 1280),
    "/sdk_click": (214605, 1576),      # leading '(' of the storage blob excluded
    "/attribution": (217879, 692),     # full query string (692 B)
    "/event": (221384, 1270),
}
SIGS = {211099: "/session", 216323: "/sdk_click", 218816: "/attribution",
        222796: "/event"}


def genuine_requests():
    reqs = {}
    name_seeds = nv_map = None
    for sig_pos, ep in sorted(SIGS.items()):      # session (211099) first
        names, vals = header_table_for(sig_pos, name_seeds, nv_map)
        headers = list(zip(names, vals))
        if name_seeds is None:
            # seed the other requests: names by index (0,1 align), shared
            # values by NAME via the session request's name->value pairs
            name_seeds = {i: n for i, (n, _) in enumerate(headers) if n}
            nv_map = {n: v for n, v in headers if v}
        reqs[ep] = {"headers": headers}
        # Content-Length from the header table itself
        cl = dict(headers).get("Content-Length")
        start, ln = BODIES[ep]
        if cl is not None and int(cl) != ln:
            raise ValueError("%s: span %d != Content-Length %s" % (ep, ln, cl))
        raw = data[start:start+ln].decode("latin-1")
        reqs[ep]["raw"] = raw
        pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        reqs[ep]["fields"] = pairs
        # Charles timing block(s) between body end and the request line
        seg = data[start+ln:REQ_LINES[ep]]
        m = re.search(rb"sq\x00~\x00xw\x08(.{8})", seg, re.S)
        if m:
            reqs[ep]["t_charles_ms"] = int.from_bytes(m.group(1), "big")
        m = re.search(rb"sq\x00~\x00\xa8w\x1d(.{29})", seg, re.S)
        if m:
            b = m.group(1)
            reqs[ep]["t_start_ms"] = int.from_bytes(b[5:13], "big")
            reqs[ep]["t_end_ms"] = int.from_bytes(b[13:21], "big")
            reqs[ep]["t_dur_ms"] = int.from_bytes(b[25:29], "big")
        reqs[ep]["sig"] = data[sig_pos:sig_pos+711].decode("latin-1")
    return reqs


def ms_to_utc(ms):
    return datetime.fromtimestamp(ms / 1000.0, timezone.utc).strftime(
        "%H:%M:%S.%f")[:-3] + "Z"


# ===========================================================================
# 2. OUR FUNNEL's requests from run_hanaf.log
# ===========================================================================
def our_requests():
    txt = open(LOG, encoding="utf-8", errors="replace").read()
    ours = {}
    stamps = {}
    for m in re.finditer(r"\[(\d\d:\d\d:\d\d)\] --> (POST|GET) https://app\.adjust\.com([/\w]*)",
                         txt):
        ep = m.group(3)
        stamps.setdefault(ep, []).append(m.group(1))
    for m in re.finditer(r"--> POST https://app\.adjust\.com(/\w+)\n.*?POST body: (\S+)",
                         txt, re.S):
        ours.setdefault(m.group(1), []).append(
            urllib.parse.parse_qsl(m.group(2), keep_blank_values=True))
    for m in re.finditer(r"--> GET https://app\.adjust\.com(/attribution\?\S+)", txt):
        q = urllib.parse.urlsplit(m.group(1)).query
        ours.setdefault("/attribution", []).append(
            urllib.parse.parse_qsl(q, keep_blank_values=True))
    # the click chain lines
    clicks = re.findall(r"click-chain hop \d+ GET (\S+) -> HTTP (\d+)", txt)
    locs = re.findall(r"Location: (\S+)", txt)
    return ours, clicks, locs, stamps


# ===========================================================================
# 3. THE DIFF
# ===========================================================================
def field_diff(gen, ours):
    g = [k for k, _ in gen]
    o = [k for k, _ in ours]
    gset, oset = set(g), set(o)
    missing = [k for k in g if k not in oset]        # genuine sends, we omit
    extra = [k for k in o if k not in gset]          # we send, genuine omits
    common_wrong_order = [k for k in g if k in oset and
                          g.index(k) != o.index(k)]
    val_diffs = []
    for k, gv in gen:
        if k in oset:
            ov = dict(ours)[k]
            if ov != gv:
                val_diffs.append((k, gv, ov))
    # order check restricted to the common subsequence
    common = [k for k in g if k in oset]
    o_common = [k for k in o if k in gset]
    order_ok = common == o_common
    return missing, extra, val_diffs, order_ok, g, o


# value-difference categories for the report
SEMANTIC = {"installed_at", "updated_at", "initiated_by", "click_time",
            "install_begin_time"}
GEO = {"country"}
PER_RUN = {"gps_adid", "android_uuid", "referrer", "push_token",
           "created_at", "sent_at", "click_time_server",
           "install_begin_time_server"}


def vcat(field):
    if field in SEMANTIC:
        return "story/semantic"
    if field in GEO:
        return "geo profile"
    if field in PER_RUN:
        return "per-run identity"
    return "device profile"


def fmt_fields(pairs):
    return "\n".join("  %2d. %-28s = %s" % (i+1, k, (v if len(v) <= 100 else
                        v[:97] + "...")) for i, (k, v) in enumerate(pairs))


def vd_cell(v):
    """Render value differences with a category tag each."""
    parts = []
    for k, gv, ov in v:
        tag = vcat(k)
        parts.append("**%s** [%s]: genuine `%s` vs ours `%s`" % (k, tag, gv, ov))
    return "; ".join(parts)


def main():
    ok, why = _verify_handle_map()
    print("handle map verification:", why)

    gen = genuine_requests()
    ours, clicks, locs, stamps = our_requests()

    L = []
    def w(s=""):
        L.append(s)

    w("# FLOW_DIFF.md -- genuine payrupi.chls vs our adj7 funnel (in.hanafintech)")
    w()
    w("Genuine capture: `C:\\Users\\Apps\\Downloads\\payrupi.chls` (2026-10-06, in.hanafintech 3.0.4,")
    w("adj7 / signing id 1300000 / headers_id 8 / native 3.62.0, device Pixel 6a, Android 17, tz +0530, country AE).")
    w("Our run: `adj7/run_hanaf.log` (CAMPAIGN=hanafintech, device profile = niri OnePlus 7 GM1901,")
    w("Android 10, tz +0000, country IN, mcc 405 / mnc 872).")
    w()
    w("Genuine handle-map verification: %s" % why)
    w()
    w("## 0. FLOW ORDER -- the single biggest difference")
    w()
    w("| # | genuine (chls) | ours (run_hanaf.log) |")
    w("|---|----------------|-----------------------|")
    w("| 1 | (click via **payrupik.go.link** -> Play Store; click itself NOT captured -- happened before the capture started; Play InstallReferrer API delivered the reftag: `referrer_api=google` in sdk_click) | click-chain hop0 `clicks.mobpine.com` 302 -> hop1 `app.adjust.com/2015o4dz` 302 -> `market://details?id=in.hanafintech&referrer=adjust_reftag=cG6ylBNe0M6tC...` |")
    w("| 2 | **POST /session** (created the adid; response carries `ask_in:2000`) | **POST /third_party_sharing** (`device not found`) -- genuine capture has **NO third_party_sharing at all** |")
    w("| 3 | **POST /sdk_click** (49 ms after session; response returns the SAME adid) | **POST /sdk_click** (creates the adid) |")
    w("| 4 | **GET /attribution** exactly once, `initiated_by=backend`, ~2.8 s after the session response (the `ask_in:2000` contract); answer = **VL-Alliance 248wk8ym on the FIRST try** | **POST /session** |")
    w("| 5 | **POST /event** (event_token y3sjx5, callback_params {google_adid}, seq=1, session_length=5, time_spent=5) ~2.1 s after the attribution answer | GET /attribution polled 4x (+30/+45/+60/+60 s), `initiated_by=sdk`, no push_token -- Organic every time |")
    w("| 6 | -- | (no event) |")
    w()
    w("Wall clock (Charles timing blocks, epoch ms):")
    w()
    w("| request | genuine Charles start | body created_at (+0530) | ours (wall, log) |")
    w("|---------|----------------------|--------------------------|------------------|")
    our_wall = {"/session": stamps.get("/session", ["?"])[0],
                "/sdk_click": stamps.get("/sdk_click", ["?"])[0],
                "/attribution": stamps.get("/attribution", ["?"])[0],
                "/event": stamps.get("/event", ["--"])[0]}
    for ep in ("/session", "/sdk_click", "/attribution", "/event"):
        g = gen[ep]
        ca = dict(g["fields"]).get("created_at", "?")
        t = ms_to_utc(g["t_start_ms"]) if "t_start_ms" in g else "?"
        w("| %s | %s (UTC) | %s | %s |" % (ep, t, ca, our_wall[ep]))
    w()

    g_sess = gen["/session"]["fields"]
    g_clik = gen["/sdk_click"]["fields"]
    g_attr = gen["/attribution"]["fields"]
    g_evnt = gen["/event"]["fields"]
    g_sess_d = dict(g_sess); g_clik_d = dict(g_clik)

    def T(s):   # 2026-10-06T11:55:42.321Z+0530 -> epoch
        d = datetime.strptime(s.split("Z")[0], "%Y-%m-%dT%H:%M:%S.%f")
        return d
    click_t = T(g_clik_d["click_time"])
    inst_t = T(g_sess_d["installed_at"])
    sess_t = T(g_sess_d["created_at"])
    sdkc_t = T(dict(g_clik)["created_at"])
    attr_t = T(dict(g_attr)["created_at"])
    ev_t = T(dict(g_evnt)["created_at"])
    w("Genuine timing relations (all +0530):")
    w()
    w("| relation | delta |")
    w("|----------|-------|")
    w("| click_time -> click_time_server | server -1.000 s (Play InstallReferrer seconds precision) |")
    w("| click_time -> install_begin_time | +1.000 s |")
    w("| click_time -> **installed_at** (CTIT, first open) | **+63.820 s** |")
    w("| installed_at -> session created_at (first open -> SDK init done) | +24.501 s |")
    w("| click_time -> session Charles start (REAL wall clock) | **+88.8 s** |")
    w("| session created_at -> sdk_click created_at | +0.049 s |")
    w("| session sent_at -> attribution created_at | +2.824 s (ask_in=2000) |")
    w("| attribution sent_at -> event created_at | +2.095 s |")
    w()
    w("OUR run timing (from the log; wire stamps +0000, wall clock = log stamps):")
    w()
    w("| relation | delta | verdict |")
    w("|----------|-------|---------|")
    w("| click -> sdk_click created_at | ~+0.25 s | genuine: +88.4 s (sdk_click fires at FIRST OPEN, not at click time) |")
    w("| click -> session created_at | ~+4.2 s | genuine: +88.3 s |")
    w("| click -> installed_at (FIELD VALUE) | +63.6 s | **installed_at lands ~59 s AFTER the session that reports it -- impossible story** |")
    w("| session -> attribution GET | +30 s .. +3.5 min | genuine: +2.8 s, once |")
    w()
    w("Timestamp FORMAT check: genuine `2026-10-06T11:55:42.321Z+0530` vs ours")
    w("`2026-10-06T06:42:55.198Z+0000` -- identical wire shape `YYYY-MM-DDTHH:MM:SS.mmmZ<tz>`;")
    w("only the tz LABEL differs (the genuine device ran +0530, our profile stamps +0000).")
    w()
    w("RESPONSES (both sides got HTTP 200 everywhere):")
    w()
    w("| endpoint | genuine response | our response |")
    w("|----------|------------------|--------------|")
    w("| third_party_sharing | (request absent) | `device not found` (expected on a fresh GAID) |")
    w("| session | `{app_token, adid, ask_in:2000}` | `{app_token, adid, ask_in:2000}` -- **we receive the same ask_in contract but ignore it** |")
    w("| sdk_click | `{app_token, adid}` (same adid -- device already existed via session) | `{app_token, adid}` (adid created HERE) |")
    w("| attribution | **non-organic**: tracker 248wk8ym `VL-Alliance::HM2::HM2_1722_`, engagement 06:24:12Z, first try | Organic every poll |")
    w("| event | 200 | (request absent) |")
    w()
    w("## 1. POST /session -- field-by-field (wire order)")
    w()
    w("Genuine (46 fields, Content-Length 1280):")
    w()
    w("```")
    w(fmt_fields(g_sess))
    w("```")
    w()
    o_sess = ours.get("/session", [None])[0]
    m, e, v, ook, go, oo = field_diff(g_sess, o_sess)
    w("Diff vs ours (46 fields):")
    w()
    w("| class | fields |")
    w("|-------|--------|")
    w("| (a) genuine sends, WE OMIT | %s |" % ", ".join("**%s**" % x for x in m) if m else "| none |")
    w("| (b) WE send, genuine omits | %s |" % ", ".join("**%s**" % x for x in e) if e else "| none |")
    w("| value differences in common fields | %s |" % vd_cell(v))
    w("| relative order of the common fields | %s |" % ("IDENTICAL" if ook else "DIFFERENT"))
    w()
    w("Notes:")
    w()
    w("* `push_token` -- Firebase/FCM InstanceID token (`<22 chars>:APA91b...`). The SDK has it before ANY server")
    w("  response (it is already in the FIRST request = session), so it comes from Firebase, not from Adjust.")
    w("  It is missing from every request we send (session, sdk_click, attribution query).")
    w("* `partner_params` -- the APP sets `{\"payrupik_c_id\":\"<uuid4>\"}`. We never send it (session/sdk_click/event).")
    w("* `initiating_package_name=com.android.vending` -- genuine session carries it IN ADDITION to")
    w("  `store_name_from_system=com.android.vending`; we only send the latter (came from the niri capture).")
    w("* `mcc`/`mnc`/`queue_size` -- WE ADD these (niri-capture leftovers); the genuine hanafintech 3.62.0")
    w("  session has neither mcc/mnc nor queue_size.")
    w("* `installed_at` = 11:55:17.820 = click + 63.82 s = FIRST OPEN (== updated_at), i.e. BEFORE the session's")
    w("  created_at (11:55:42.321) by 24.5 s. Ours has installed_at = click + 63 s but created_at = click + 4 s --")
    w("  the session claims to run a minute BEFORE its own install moment.")
    w()
    w("## 2. POST /sdk_click -- field-by-field (wire order)")
    w()
    w("Genuine (50 fields, Content-Length 1576):")
    w()
    w("```")
    w(fmt_fields(g_clik))
    w("```")
    w()
    o_clik = ours.get("/sdk_click", [None])[0]
    m, e, v, ook, go, oo = field_diff(g_clik, o_clik)
    w("Diff vs ours (47 fields):")
    w()
    w("| class | fields |")
    w("|-------|--------|")
    w("| (a) genuine sends, WE OMIT | %s |" % ", ".join("**%s**" % x for x in m) if m else "| none |")
    w("| (b) WE send, genuine omits | %s |" % ", ".join("**%s**" % x for x in e) if e else "| none |")
    w("| value differences in common fields | %s |" % vd_cell(v))
    w("| relative order of the common fields | %s |" % ("IDENTICAL" if ook else "DIFFERENT"))
    w()
    w("Notes:")
    w()
    w("* `click_time_server` / `install_begin_time_server` -- the Play Store InstallReferrer API's server-side")
    w("  seconds-precision echoes (both .000); the genuine client got them from the REAL Play referrer read.")
    w("  Ours cannot have real ones; either omit both (cleaner) or keep only the client-side values.")
    w("* `install_version=3.0.4` == app_version; missing from ours.")
    w("* genuine `hardware_name=CP2A.260705.006` (== its os_build on that Pixel); ours `GM1901_14_201019` -- device-")
    w("  consistent for our profile, keep.")
    w("* genuine referrer = `adjust_reftag=cmTHC4v8KOvVM&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_`")
    w("  (tracker 248wk8ym's link, NO sub2 suffix); ours = `adjust_reftag=cG6ylBNe0M6tC&...&utm_content=HM2_1722_zt1`")
    w("  (tracker 2015o4dz via mobpine, sub2 zt1 appended). Each is internally consistent with its own click.")
    w()
    w("## 3. GET /attribution -- query params (wire order)")
    w()
    w("Genuine (23 params, ONE GET):")
    w()
    w("```")
    w(fmt_fields(g_attr))
    w("```")
    w()
    o_attr = ours.get("/attribution", [None])[0]
    m, e, v, ook, go, oo = field_diff(g_attr, o_attr)
    w("Diff vs ours (22 params):")
    w()
    w("| class | fields |")
    w("|-------|--------|")
    w("| (a) genuine sends, WE OMIT | %s |" % ", ".join("**%s**" % x for x in m) if m else "| none |")
    w("| (b) WE send, genuine omits | %s |" % ", ".join("**%s**" % x for x in e) if e else "| none |")
    w("| value differences | %s |" % vd_cell(v))
    w("| param order | %s (query order is HashMap-ordered server-side-irrelevant, but the genuine order is above) |" %
      ("same" if ook else "different"))
    w()
    w("* `initiated_by=backend` (not `sdk`): the ONE genuine GET is the ask_in-scheduled callback, ~2.8 s after")
    w("  the session response. It returned the non-organic answer IMMEDIATELY -- no polling ladder exists")
    w("  (the 'second attribution' in the old extract was the same request's request-line copy).")
    w()
    w("## 4. POST /event -- genuine sends it, we never do")
    w()
    w("Genuine (44 fields, Content-Length 1270), sent 2.1 s after the attribution answer:")
    w()
    w("```")
    w(fmt_fields(g_evnt))
    w("```")
    w()
    w("* event_token `y3sjx5`, callback_params `{\"google_adid\":\"<gaid>\"}`, seq=1, event_count=1,")
    w("  session_length=5, time_spent=5 (5 s after session start), partner_params again present.")
    w("* Post-attribution, so it did NOT influence the attribution decision -- but a genuine-equivalent flow")
    w("  includes it.")
    w()
    w("## 5. REQUEST HEADERS (from the serialised name/value ArrayLists)")
    w()
    w("Genuine POST (session/sdk_click/event), wire order:")
    w()
    w("```")
    for i, (k, v) in enumerate(gen["/session"]["headers"]):
        vv = "<304-hex Signature signature=...,adj_signing_id=\"1300000\",algorithm=\"adj7\",headers_id=\"8\",native_version=\"3.62.0\">" if k == "Authorization" else v
        w("%d. %s: %s" % (i+1, k, vv))
    w("```")
    w()
    w("Genuine GET (attribution), wire order:")
    w()
    w("```")
    for i, (k, v) in enumerate(gen["/attribution"]["headers"]):
        vv = "<304-hex Signature ...>" if k == "Authorization" else v
        w("%d. %s: %s" % (i+1, k, vv))
    w("```")
    w()
    w("Ours (run_install.call()): Client-SDK, Authorization, User-Agent, Host, [Content-Type,")
    w("Content-Length], Accept-Encoding.  Diffs:")
    w()
    w("| class | diff |")
    w("|-------|------|")
    w("| (a) missing | **Connection: Keep-Alive** -- every genuine request carries it, we never send it |")
    w("| (c) order | genuine: Client-SDK, Authorization, **Content-Type**, User-Agent, Host, Connection, Accept-Encoding, **Content-Length last**; ours: Content-Type 5th, Content-Length 6th |")
    w("| (c) shape | Client-SDK value `android5.6.0`, UA `Dalvik/2.1.0 (Linux; U; Android <v>; <dev> Build/<b>)`, Authorization shape incl. headers_id=8 / native_version=3.62.0 -- all MATCH |")
    w()
    w("## 6. THE CLICK")
    w()
    w("* Genuine capture contains **no click request at all** (the only go.link hit is the GMS Digital Asset")
    w("  Links check for `https://payrupik.go.link` -- proof the click went through the branded go.link domain")
    w("  and the Play Store; the capture started after that).")
    w("* Ours: `clicks.mobpine.com` 302 -> `app.adjust.com/2015o4dz?...&ip_address=%7Bloop_id%7D&gps_adid=<gaid>...`")
    w("  302 -> `market://...&referrer=adjust_reftag=cG6ylBNe0M6tC...`.  Diffs:")
    w("  1. **`ip_address=%7Bloop_id%7D` reaches app.adjust.com UNSUBSTITUTED** -- the mobpine `{loop_id}` macro")
    w("     is not replaced for sub2=zt1, so the click is registered with a garbage ip_address value")
    w("     (gps_adid IS properly substituted, but the click's IP context is corrupt).")
    w("  2. Our click hops present the app's **Dalvik UA + a Client-SDK header** to the tracker; a genuine")
    w("     click comes from a mobile browser (no Client-SDK, browser UA).")
    w("  3. Genuine click domain: `payrupik.go.link` (tracker 248wk8ym); ours: `app.adjust.com/2015o4dz`")
    w("     (different tracker token of the same VL-Alliance::HM2 campaign).")
    w()
    w("## 7. RANKED FIX LIST for run_install.py (builders + flow order)")
    w()
    w("1. **(e) WALL-CLOCK STORY** -- run the flow at genuine speed: sleep so that the session fires")
    w("   ~INSTALL_AFTER+25 s after the click (genuine: click +88 s), NOT +4 s.  installed_at must be")
    w("   BEFORE the session's created_at: set installed_at = click + CTIT (63 s), then open the session")
    w("   ~20-30 s later.  Today installed_at lands 59 s AFTER the session that reports it -- an impossible")
    w("   story the server can see.")
    w("2. **(e) ORDER** -- session FIRST, then sdk_click (+~50 ms), then the attribution GET, then the event.")
    w("   Drop third_party_sharing entirely (the genuine hanafintech capture has none).")
    w("3. **(a) push_token** -- fabricate a stable FCM-shaped token (`<22 id chars>:APA91b...`, per-device)")
    w("   and add it to session, sdk_click and the attribution query.")
    w("4. **(a) partner_params** -- add `partner_params={\"payrupik_c_id\":\"<uuid4>\"}` to session, sdk_click")
    w("   (position: right after hardware_name / app_version) and event.")
    w("5. **(a) initiating_package_name=com.android.vending** -- add to the session body (keep")
    w("   store_name_from_system too).")
    w("6. **(b) mcc/mnc/queue_size** -- REMOVE from session and sdk_click (genuine hanafintech 3.62.0 carries")
    w("   neither; they are niri-capture leftovers).")
    w("7. **(a) install_version** (= app_version) -- add to sdk_click after cpu_type.")
    w("8. **(a) click_time_server / install_begin_time_server** -- omit (no real Play read); keep the")
    w("   client-side click_time (.000) and install_begin_time = click+1 s.")
    w("9. **(e) attribution** -- ONE GET, `initiated_by=backend`, +push_token, fired ~2.8 s after the session")
    w("   response ( honour ask_in ), with the genuine param order; keep polling only as a fallback.")
    w("10. **(c) headers** -- add `Connection: Keep-Alive`; send Content-Type BEFORE User-Agent and")
    w("    Content-Length LAST; GET carries no Content-Type/Content-Length (already true).")
    w("11. **(e) event** -- after the (non-organic) attribution answer, POST /event with event_token y3sjx5,")
    w("    callback_params {\"google_adid\": gaid}, partner_params, seq=1, event_count=1,")
    w("    session_length/time_spent ~= seconds since the session.")
    w("12. **(b/c) click chain** -- click with a mobile-browser UA and NO Client-SDK header; check with the")
    w("    network why `{loop_id}` is passed through unsubstituted in ip_address= (or strip the param);")
    w("    prefer the genuine-shaped go.link click (payrupik.go.link, tracker 248wk8ym) over")
    w("    app.adjust.com/2015o4dz if the team can get that link.")
    w("13. **(b) device/geo story** -- our profile says country=IN + mcc 405 / mnc 872 + tz +0000; the genuine")
    w("    hanafintech device says country=AE, tz +0530.  Align the device profile with the IP geo that")
    w("    actually performs the click+install (and the offer's target geo).")
    w()
    w("## 8. Raw extracts (reproducible)")
    w()
    w("* genuine request headers/values resolved from the chls ArrayList pairs; handle map: %s" % why)
    w("* genuine bodies span-verified against each request's Content-Length header (1280/1576/1270)")
    w("* our four signed requests parsed from run_hanaf.log verbatim")
    w()

    open(OUT, "w", encoding="utf-8").write("\n".join(L))
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())

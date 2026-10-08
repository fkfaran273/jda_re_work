# -*- coding: utf-8 -*-
"""deep_audit.py -- reproducible side-by-side: proven adj9 funnel vs our adj7
funnel vs the golden capture (payrupik_new, BOOKED non-organic).

    python deep_audit.py                 # offline only -- no network, no clicks
    python deep_audit.py --click-trace   # + ONE live click-chain trace with a
                                         #   throwaway gaid (spends one click,
                                         #   no install, no API calls)

Everything runs against the two runners' own code (imported, never copied):
  proven : manual_run/run_install.py   (books non-organic, adj9)
  ours   : adj7/run_install.py         (books Organic, adj7)
  golden : adj7/cap/payrupik_new/payrupik_new__adjust.json (sid 42/43/44/45)

Sections printed:
  [1] flow & timing side-by-side
  [2] per-endpoint field diffs vs the golden (order, missing, extra, values)
  [3] request headers vs the golden
  [4] transport / encoding checks
  [5] the click phase: structural diff + the _fill_device_id regression
  [6] signing-second consistency per request
  [7] click-chain live trace (only with --click-trace)
"""
import importlib.util
import json
import os
import re
import sys
import urllib.parse
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))                      # ...\com.penti.app
ADJ7 = os.path.join(ROOT, "adj7")
MANUAL = os.path.join(ROOT, "manual_run")
GOLDEN_JSON = os.path.join(ADJ7, "cap", "payrupik_new",
                           "payrupik_new__adjust.json")
TRACE = "--click-trace" in sys.argv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


print("=" * 79)
print("DEEP AUDIT  proven adj9 (manual_run) vs ours adj7 (adj7) vs golden")
print("=" * 79)

# ---------------------------------------------------------------- imports --
ours = load_module(os.path.join(ADJ7, "run_install.py"), "adj7_runner")
prov = load_module(os.path.join(MANUAL, "run_install.py"), "adj9_runner")

golden = json.load(open(GOLDEN_JSON, encoding="utf-8"))
G = {rec["sid"]: rec for rec in golden}

# A fixed per-install identity shared by every rebuild in this audit.
GAID = "11111111-2222-4333-8444-555555555555"
AUUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CLICK = 1791309253                    # our last live run's click_second
SEC = CLICK + 86                      # a signing second in our story
REF = ("adjust_reftag=cyTimCwlC7gce&utm_source=VL-Alliance"
       "&utm_campaign=HM2&utm_content=HM2_1722_")
GOLDEN_PP = G["42"]["body"]["partner_params"]

# Rebuild OUR three bodies with the golden's partner_params for a clean
# value comparison (the runner would mint a fresh uuid4 -- by design).
ours.PARTNER_PARAMS = GOLDEN_PP
o_session = ours.build_session_request(GAID, AUUUID, SEC, click_sec=CLICK)
o_click = ours.build_click_request(GAID, AUUUID, SEC, REF, click_sec=CLICK)
o_attr = ours.build_attribution_request(GAID, AUUUID, SEC)

# Rebuild the PROVEN three bodies: feed it the adj7 campaign/device in its
# own layout, DRY_RUN it, and capture the fields through _headers.
prov.DRY_RUN = True
prov.GAP = 0
prov.campaign_data = {
    "package_name": ours.PACKAGE_NAME,
    "app_version_name": ours.APP_VERSION,
    "adjust": {"app_token": ours.APP_TOKEN, "sdk": ours.CLIENT_SDK},
    "poll_delays": [3, 8, 20],
    # adj9_pure.sign_request needs these; values are irrelevant here --
    # only the FIELD CAPTURE matters, not the blob it prints
    "cert_sha1": ours.CERT_SHA1,
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "head_phase": (0x40,),
}
prov.DEVICE = {
    "api_level": ours.P["api_level"], "os_version": ours.P["os_version"],
    "device_name": ours.P["device_name"],
    "device_manufacturer": ours.P["device_manufacturer"],
    "hardware_name": ours.P["hardware_name"], "os_build": ours.P["os_build"],
    "language": ours.P["language"], "country": ours.P["country"],
    "display_width": ours.P["display_width"],
    "display_height": ours.P["display_height"],
    "screen_density": ours.P["screen_density"],
    "screen_size": ours.P["screen_size"],
    "screen_format": ours.P["screen_format"], "cpu_type": ours.P["cpu_type"],
    "connectivity_type": ours.P["connectivity_type"],
    "timezone": ours.P["timezone"],
    "mcc": "", "mnc": "",
    "enqueue_size": "0", "first_error": "0", "last_error": "0",
    "retry_count": "0", "wait_time": "0.0", "wait_total": "0.0",
}
prov.RUN.update({"gaid": GAID, "android_uuid": AUUUID,
                 "click_sec": CLICK, "referrer": REF, "t0": 0.0})

captured = {}
_orig_headers = prov._headers
def _capture(campaign, device, fields, kind, sec):
    captured[kind] = dict(fields)
    return _orig_headers(campaign, device, fields, kind, sec)
prov._headers = _capture
prov.session(prov.campaign_data, prov.DEVICE)
prov.sdk_click(prov.campaign_data, prov.DEVICE)
prov.attribution(prov.campaign_data, prov.DEVICE)
prov._headers = _orig_headers
p_session, p_click, p_attr = (captured["session"], captured["click"],
                              captured["attribution"])

# ------------------------------------------------------------- [1] flow --
print()
print("[1] FLOW & TIMING (server-visible story)")
print("-" * 79)
print("""proven adj9 : click(direct app.adjust.com) -> +30s -> session
               (installed_at=click+14) -> +30s -> sdk_click(click_time=click,
               taken AFTER the click) -> attribution poll +3/+8/+20
               initiated_by=sdk   [click_sec recorded AFTER the click]
ours   adj7 : click(mobpine->adjust) -> +88s wall -> session
               (installed_at=click+63) -> +0.05s -> sdk_click -> +2.8s
               attribution initiated_by=backend -> +30s re-ask if Organic
               [click_second recorded BEFORE the click]
golden      : click -> +433s -> session(installed_at=click+41.6s)
               -> +0.101s -> sdk_click -> +3.21s attribution(backend)
               -> +1.6s event(y3sjx5)
               engagement_time(server click record) = click_time - 1s""")

g_engagement = "2026-10-06T10:10:24Z"          # sid 44 response
g_click_time = G["43"]["body"]["click_time"]   # 15:40:25.000Z+0530
print("  golden server engagement %s ; claimed click_time %s (+0530)"
      % (g_engagement, g_click_time))
print("  -> genuine sign: claimed click_time is 1s AFTER the server record")
print("  ours  : click_second=%d taken BEFORE open_click_link -> the click")
print("          request lands ~1s later, so the claim is 1s BEFORE it")
print("          (run_install.py L400-403; proven records it after,")
print("           manual_run/run_install.py L743-745)")

# -------------------------------------------------- [2] field diffs ------
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+0530")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                     r"[0-9a-f]{12}")


def pat(v):
    v = TIME_RE.sub("<T>", str(v))
    v = UUID_RE.sub("<U>", v)
    v = v.replace(GOLDEN_PP, "<PP>")
    v = re.sub(r"adjust_reftag=[^&]+", "adjust_reftag=<RT>", v)
    return v


def diff_endpoint(name, gold_body, ours_f, prov_f):
    gk = list(gold_body.keys())
    ok = list(ours_f.keys())
    pk = list(prov_f.keys())
    print()
    print("[%s] %s -- golden %d fields | ours %d | proven %d"
          % (2, name, len(gk), len(ok), len(pk)))
    print("  order: ours==golden? %s   proven==golden? %s"
          % (ok == gk, pk == gk))
    miss = [k for k in gk if k not in ours_f]
    extra = [k for k in ours_f if k not in gold_body]
    if miss:
        print("  OURS MISSING : %s" % miss)
    else:
        print("  OURS MISSING : (none)")
    if extra:
        print("  OURS EXTRA   : %s" % extra)
    else:
        print("  OURS EXTRA   : (none)")
    bad = [(k, gold_body[k], ours_f[k]) for k in gk
           if k in ours_f and pat(gold_body[k]) != pat(ours_f[k])]
    if bad:
        for k, gv, ov in bad:
            print("  VALUE PATTERN DIFF %s: golden=%r ours=%r" % (k, gv, ov))
    else:
        print("  VALUE PATTERNS : identical (times/uuids/reftag normalised)")


diff_endpoint("POST /session", G["42"]["body"], o_session, p_session)
diff_endpoint("POST /sdk_click", G["43"]["body"], o_click, p_click)
diff_endpoint("GET  /attribution", G["44"]["body"], o_attr, p_attr)

# ------------------------------------------------ [3] request headers ----
print()
print("[3] REQUEST HEADERS vs golden")
print("-" * 79)


def hdr_tuples(sid):
    return [(k.lower(), v) for k, v in G[sid]["request_headers"]]


g_post = hdr_tuples("42")
g_get = hdr_tuples("44")
our_post = [("client-sdk", ours.CLIENT_SDK), ("authorization", "<blob>"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("user-agent", ours.APP_UA), ("host", "app.adjust.com"),
            ("connection", "Keep-Alive"), ("accept-encoding", "gzip"),
            ("content-length", "<n>")]
our_get = [("client-sdk", ours.CLIENT_SDK), ("authorization", "<blob>"),
           ("user-agent", ours.APP_UA), ("host", "app.adjust.com"),
           ("connection", "Keep-Alive"), ("accept-encoding", "gzip")]
print("  golden POST order :", [k for k, _ in g_post])
print("  ours   POST order :", [k for k, _ in our_post])
print("  POST names equal  :", [k for k, _ in g_post] == [k for k, _ in our_post])
print("  golden GET order  :", [k for k, _ in g_get])
print("  ours   GET order  :", [k for k, _ in our_get])
print("  GET names equal   :", [k for k, _ in g_get] == [k for k, _ in our_get])
g_ua = dict(g_post).get("user-agent", "")
print("  UA golden == ours :", g_ua == ours.APP_UA)
print("  proven headers    : Client-SDK, Authorization, User-Agent,"
      " Content-Type (+requests defaults Accept/Accept-Encoding/"
      "Connection/Host/Content-Length) -- DIFFERENT set from the golden")
print("                      and the proven still books -> header set/order")
print("                      is NOT the discriminator")

# ---------------------------------------------- [4] transport/encoding ---
print()
print("[4] TRANSPORT & ENCODING")
print("-" * 79)
b = {"device_name": "moto g42", "created_at": "a:b c+d"}
qp = urllib.parse.urlencode(b)
q = urllib.parse.urlencode(b, quote_via=urllib.parse.quote)
print("  POST quote_plus   : %s   (golden 42/43 raw: device_name=moto+g42)"
      % qp)
print("  GET  quote        : %s   (golden 44 raw: device_name=moto%%20g42)"
      % q)
print("  ours   : POST urlencode(fields) [quote_plus] ; GET quote_via=quote")
print("         -> BOTH match the golden. encoding is NOT the discriminator")
print("  request-line form : golden absolute-form (Fiddler-proxied phone);")
print("  ours origin-form; REPLAY probe G booked over origin-form -> blind")
print("  HTTP version      : golden TLS1.3/h2-capable Dalvik; ours HTTP/1.1;")
print("  REPLAY VERBATIM-H1 booked over HTTP/1.1 -> blind")

# ------------------------------------------------------ [5] click phase --
print()
print("[5] THE CLICK PHASE -- structural diff + _fill_device_id regression")
print("-" * 79)
print("""proven open_click_link              | ours open_click_link
------------------------------------+--------------------------------------
single pass, max 8 hops             | TWO passes (attempt 1,2), max 12 hops
fill() keeps '&' via +r'\\1'         | _fill_device_id LOST the \\1 (r'')
no {loop_id} handling               | strips &ip_address={loop_id} macros
Location header only                | + JS location.replace + body search
appends gps_adid once (initial URL) | same append (initial URL)
BROWSER_HEADERS 10 entries          | same 10 entries + explicit Host
click_sec = AFTER the click         | click_second = BEFORE the click""")

cases = [
    ("mid-URL empty adj param",
     "https://x.go.link/c?adj_tracker=248wk8ym&adj_gps_adid="
     "&adj_adgroup=HM2&idfa=zz"),
    ("trailing empty adj param",
     "https://x.go.link/c?adj_tracker=248wk8ym&adj_gps_adid="),
    ("macro form",
     "https://x.go.link/c?adj_gps_adid=%7Bgps_adid%7D&adj_adgroup=HM2"),
    ("mid-URL empty plain param",
     "https://app.adjust.com/abc?campaign=HM2&gps_adid=&creative=x"),
]
print("  regression (synthetic, no network):")
for label, url in cases:
    o = ours._fill_device_id(url, GAID)
    p = prov.fill(url, GAID) if False else None
    # proven fill() is a closure inside open_click_link -- rebuild it here
    import re as _re
    u = url
    u = _re.sub(r'adj_gps_adid=(&|$)', 'adj_gps_adid=' + GAID + r'\1', u)
    u = _re.sub(r'(?<!adj_)gps_adid=(&|$)', 'gps_adid=' + GAID + r'\1', u)
    u = _re.sub(r'adj_gps_adid=%7B[^&]*%7D', 'adj_gps_adid=' + GAID, u)
    u = _re.sub(r'(?<!adj_)gps_adid=%7B[^&]*%7D', 'gps_adid=' + GAID, u)
    u = _re.sub(r'adj_gps_adid=[{][^&]*[}]', 'adj_gps_adid=' + GAID, u)
    u = _re.sub(r'(?<!adj_)gps_adid=[{][^&]*[}]', 'gps_adid=' + GAID, u)
    same = (o == u)
    print("  - %s" % label)
    print("      in    : %s" % url)
    print("      proven: %s" % u)
    print("      ours  : %s   %s" % (o, "<-- DIFFERS (bug)" if not same
                                     else "(same)"))

# ------------------------------------------- [6] signing-second split ----
print()
print("[6] SIGNING-SECOND CONSISTENCY (header second vs created_at second)")
print("-" * 79)
print("""golden/oracle law : make_header(created_at second) == blob[:16] for
                    every genuine call -- the device signs IN the created_at
                    second (REPLAY_RULE_RESULT.md 'delta +0s')
proven            : one sec = signing_second() feeds stamps AND
                    _headers(..., sec) -- always consistent
ours  /session    : sec = signing_second() once (L439) -- consistent
ours  /sdk_click  : built with signing_second() (L460) then signed with a
                    SECOND signing_second() inside signed_call (L417)
ours  /attribution: built with signing_second() (L472) then signed with
                    another signing_second() (L473)
risk              : the two calls straddle a second boundary ~once per
                    1000+ calls -- NOT the systematic cause, but a real
                    divergence from the proven one-sec invariant""")

# ------------------------------------------------ [7] click-chain trace --
if TRACE:
    print()
    print("[7] LIVE CLICK-CHAIN TRACE (throwaway gaid, one click spend)")
    print("-" * 79)
    import gzip
    import http.client
    tgaid = str(uuid.uuid4())
    url = ours._fill_device_id(ours._subst(ours.LINK, tgaid), tgaid)
    if "gps_adid=" not in url:
        url += "&gps_adid=" + tgaid
    print("  throwaway gaid: %s" % tgaid)
    print("  hop 0 GET %s" % url)

    def show_params(u, tag):
        for name in ("gps_adid", "adj_gps_adid", "ip_address", "adj_reftag",
                     "click_id", "referrer"):
            for m in re.finditer(r"([?&])((?:adj_)?%s)=([^&]*)" % name, u):
                print("      %-14s %s=%s" % (tag, m.group(2), m.group(3)[:60]))

    for hop in range(8):
        if not url.startswith("http"):
            print("  hop %d non-http target: %s" % (hop, url[:120]))
            ref = ours._reftag_in(url)
            if ref:
                print("  reftag inside: %s" % ref)
            break
        scheme, rest = url.split("://", 1)
        host, _, path = rest.partition("/")
        cls = (http.client.HTTPSConnection if scheme == "https"
               else http.client.HTTPConnection)
        c = cls(host, 443 if scheme == "https" else 80, timeout=25)
        c.putrequest("GET", "/" + path, skip_host=1, skip_accept_encoding=1)
        for k, v in ours.BROWSER_HEADERS.items():
            c.putheader(k, v)
        c.putheader("Host", host)
        c.endheaders()
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == bytes((0x1f, 0x8b)):
            raw = gzip.decompress(raw)
        c.close()
        loc = dict((k.lower(), v) for k, v in r.getheaders()).get("location")
        print("  hop %d GET %s -> HTTP %d" % (hop, url[:100], r.status))
        show_params(url, "request")
        if loc:
            print("      Location: %s" % loc[:160])
            show_params(loc, "location")
            loc = ours._fill_device_id(
                loc.replace("&ip_address=%7Bloop_id%7D", ""), tgaid)
            url = loc
            continue
        text = raw.decode("utf-8", "replace")
        m = re.search(r"location\.replace\(\s*[\"']([^\"']+)[\"']", text)
        if m:
            print("      JS location.replace -> %s" % m.group(1)[:160])
            url = m.group(1)
            continue
        break

print()
print("=" * 79)
print("END -- see DEEP_AUDIT.md next to this script for the ranked report")
print("=" * 79)

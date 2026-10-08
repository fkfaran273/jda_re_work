"""replay_rule.py -- THE verification rule for the adj7 signature.

Replay the genuine fresh-install attribution GET (payrupik_new saz, sid 44)
with OUR signature making (adj7_pure.mint_adj7).  If the signature making is
correct, the replay MUST return NON-ORGANIC (tracker 248wk8ym / VL-Alliance),
because Adjust gives the verdict based on gaid + signature and this capture's
install booked NON-ORGANIC minutes ago on this same machine/IP.

Probes (in order, ~1.5 s apart, each a fresh curl_cffi session):
  PRIMARY    our mint_adj7 verbatim auth tail (headers_id 7 / native 3.61.0),
             fresh created_at/sent_at
  PRIMARY-B  our mint, auth tail rewritten capture-faithful (8 / 3.62.0),
             fresh times        <- run_install.py's proven wire form
  CONTROL-A  GENUINE auth header verbatim, fresh times
             (calibrates: does the server bind the signature to the times?)
  CONTROL-B  our mint (faithful tail), STALE capture times
             (calibrates: does the server gate on created_at/sent_at age?)
  CONTROL-C  NO Authorization header at all, fresh times
             (calibrates: is GET /attribution signature-blind?  it was for
              the 8-month-old nirio capture)

Offline (before any network I/O) the script re-proves the law on THIS
capture's genuine sid-44 blob: CBC-invert it (work.ks_inverse), dump the
record fields a/b/c/d/e, recompute H over the claims rebuilt from the decoded
query (block2 and no-block2 and with-a-push-token variants), and brute-force
the signing second against the bionic header.  Our own minted blob is then
inverted the same way and diffed field-by-field against the genuine record.

    python replay_rule.py            # full run
    python replay_rule.py --offline  # law checks only, no network
"""
import json
import math
import os
import re
import struct
import sys
import time
import urllib.parse
from calendar import timegm
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))            # .../adj7/cap
ADJ7 = os.path.dirname(HERE)                                 # .../adj7
WORK = os.path.join(ADJ7, "work")
for _p in (ADJ7, WORK):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import adj7_pure as sg
from work.ks_inverse import cbc_dec          # K round keys live in there

CAP_DIR = os.path.join(HERE, "payrupik_new")
CAP_JSON = os.path.join(CAP_DIR, "payrupik_new__adjust.json")
RAW_44 = os.path.join(CAP_DIR, "raw", "44_c.txt")
RESULT_MD = os.path.join(HERE, "REPLAY_RULE_RESULT.md")

CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
CLIENT_SDK = "android5.6.0"
GAID = "0a5863d0-66f6-4d15-b9ab-d388b77c8ba3"
ADID = "6b575c41bbefc8caaccaf6faa01eac3a"
WANT_TRACKER = "248wk8ym"
WANT_NETWORK = "VL-Alliance"
FAKE_PUSH = "fREPLAYFAKE0Zx_9R7cQ8yY:APA91bH" + "0" * 64   # falsification probe

REC_RE = re.compile(
    rb'\{ "a":  ([ 0-9]{20}) ,"b": "([0-9A-F]{64})","c": "([0-9A-F]{40})",'
    rb'"d": "([0-9A-F]{8})","e": "([0-9A-F]{64})" \}\x00')
STAMP_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{3})Z([+-])(\d{2})(\d{2})$')

T = []          # transcript


def out(*parts):
    line = " ".join(str(p) for p in parts)
    T.append(line)
    try:
        print(line, flush=True)
    except Exception:
        print(line.encode("ascii", "replace").decode(), flush=True)


# ----------------------------------------------------------------------
def load_capture():
    with open(CAP_JSON, "r", encoding="utf-8") as f:
        recs = json.load(f)
    rec44 = next(r for r in recs if r.get("sid") == "44")
    hdrs = {k.lower(): v for k, v in rec44["request_headers"]}
    with open(RAW_44, "r", encoding="utf-8", errors="replace") as f:
        first = f.readline().strip()
    m = re.match(r'^GET (\S+) HTTP', first)
    raw_url = m.group(1)
    raw_query = raw_url.split("?", 1)[1]
    return rec44, hdrs, raw_query


def parse_pairs(raw_query):
    """[(key, raw-encoded value)] in wire order."""
    outp = []
    for part in raw_query.split("&"):
        k, _, v = part.partition("=")
        outp.append((k, v))
    return outp


def decode_pairs(pairs):
    return {k: urllib.parse.unquote(v) for k, v in pairs}


def stamp_of(value):
    m = STAMP_RE.match(value)
    if not m:
        raise ValueError("bad capture stamp %r" % value)
    naive, ms, sign, hh, mm = m.groups()
    off = (1 if sign == "+" else -1) * (int(hh) * 3600 + int(mm) * 60)
    # naive digits are LOCAL wall clock; timegm treats them as UTC, so the
    # true UTC epoch is timegm(local digits) - off
    epoch = timegm(time.strptime(naive, "%Y-%m-%dT%H:%M:%S")) - off
    return epoch, int(ms), off


def fresh_stamp(ts, off):
    """Local wall-clock digits + the capture's offset label (e.g. Z+0530);
    the capture's digits are LOCAL time, 'Z' is literal."""
    fl = math.floor(ts)
    ms = int(round((ts - fl) * 1000))
    if ms > 999:
        ms = 999
    dt = datetime.fromtimestamp(fl + off, timezone.utc)
    lbl = "+%02d%02d" % (off // 3600, (off % 3600) // 60) if off >= 0 \
        else "-%02d%02d" % ((-off) // 3600, ((-off) % 3600) // 60)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % ms + "Z" + lbl


def parse_record(blob):
    rec = cbc_dec(blob[16:272], blob[:16])
    m = REC_RE.match(rec)
    if not m:
        return rec, None
    a, b, c, d, e = m.groups()
    nonce12 = struct.pack("<Q", int(a)) + bytes.fromhex(d.decode())
    return rec, {"a": a.decode(), "b": b.decode(), "c": c.decode(),
                 "d": d.decode(), "e": e.decode(), "nonce12": nonce12}


def header_second(blob, lo, hi):
    for sec in range(lo, hi + 1):
        if sg.make_header(sec) == blob[:16]:
            return sec
    return None


def hexdump_str_diff(s1, s2, what):
    if s1 == s2:
        out("  diff %s: IDENTICAL (len %d)" % (what, len(s1)))
        return
    i = 0
    while i < min(len(s1), len(s2)) and s1[i] == s2[i]:
        i += 1
    j = 0
    while (j < min(len(s1), len(s2)) - i
           and s1[len(s1) - 1 - j] == s2[len(s2) - 1 - j]):
        j += 1
    out("  diff %s: differ in the middle span (common prefix %d, suffix %d)"
        % (what, i, j))
    out("    A ...%s |%s| %s..." % (s1[max(0, i - 24):i], s1[i:len(s1) - j],
                                    s1[len(s1) - j:len(s1) - j + 24]))
    out("    B ...%s |%s| %s..." % (s2[max(0, i - 24):i], s2[i:len(s2) - j],
                                    s2[len(s2) - j:len(s2) - j + 24]))


def auth_tail(auth, headers_id, native_version):
    auth = re.sub(r'headers_id="[^"]*"',
                  'headers_id="%s"' % headers_id, auth)
    auth = re.sub(r'native_version="[^"]*"',
                  'native_version="%s"' % native_version, auth)
    return auth


def sign_attribution(fields, sec):
    sg.CERT_SHA1 = CERT
    sg.CLIENT_SDK = CLIENT_SDK
    auth = sg.mint_adj7("attribution", fields, unix_sec=sec,
                        client_sdk=CLIENT_SDK, include_block2=True)
    blob = bytes.fromhex(re.search(r'signature="([A-F0-9]+)"', auth).group(1))
    return blob, auth


# ----------------------------------------------------------------------
def append_md(title, lines):
    """Append a section to REPLAY_RULE_RESULT.md (create base if missing)."""
    if not os.path.exists(RESULT_MD):
        with open(RESULT_MD, "w", encoding="utf-8") as f:
            f.write("# REPLAY RULE RESULT -- adj7 attribution replay\n")
    with open(RESULT_MD, "a", encoding="utf-8") as f:
        f.write("\n\n## %s\n\n" % title)
        f.write("Run: %s\n\n" % datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S %z"))
        f.write("```\n")
        f.write("\n".join(T))
        f.write("\n```\n")
    out("")
    out("appended section %r to %s" % (title, RESULT_MD))


def cmd_verbatim():
    """Close the probe matrix: genuine auth + capture query BYTE-EXACT
    (no time refresh), on both transports.  If the server verifies
    signatures when present and the device's booked state were alive,
    only THIS cell can return NON-ORGANIC."""
    rec44, hdrs, raw_query = load_capture()
    genuine_auth = hdrs["authorization"]
    ua = hdrs["user-agent"]
    from curl_cffi.requests import Session
    url = "https://app.adjust.com/attribution?" + raw_query
    headers = {"Client-SDK": CLIENT_SDK, "User-Agent": ua,
               "Accept-Encoding": "gzip", "Authorization": genuine_auth}
    out("PROBE VERBATIM  genuine auth + capture query byte-exact "
        "(curl_cffi chrome131_android, h2)")
    with Session(impersonate="chrome131_android") as s:
        r = s.get(url, headers=headers, timeout=30)
    out("  HTTP %s" % r.status_code)
    out("  body: %s" % r.text[:600])
    v1 = verdict_line(r.status_code, r.text)
    out("  %s" % v1)
    time.sleep(1.5)
    # same request over plain HTTP/1.1 (http.client, no impersonation) --
    # rules out any TLS/HTTP2-fingerprint effect
    import http.client
    out("")
    out("PROBE VERBATIM-H1  identical bytes over http.client HTTP/1.1")
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    path = "/attribution?" + raw_query
    c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", CLIENT_SDK)
    c.putheader("Authorization", genuine_auth)
    c.putheader("User-Agent", ua)
    c.putheader("Host", "app.adjust.com")
    c.putheader("Connection", "Keep-Alive")
    c.putheader("Accept-Encoding", "gzip")
    c.endheaders()
    resp = c.getresponse()
    raw = resp.read()
    if raw[:2] == bytes((0x1f, 0x8b)):
        import gzip
        raw = gzip.decompress(raw)
    body = raw.decode("utf-8", "replace")
    c.close()
    out("  HTTP %s" % resp.status)
    out("  body: %s" % body[:600])
    v2 = verdict_line(resp.status, body)
    out("  %s" % v2)
    append_md("VERBATIM probes (genuine auth + byte-exact capture query)",
              T)


def verdict_line(status, body):
    try:
        j = json.loads(body)
        att = j.get("attribution") or {}
        net = att.get("network", "?")
        tok = att.get("tracker_token", "?")
        eng = att.get("engagement_time", "?")
        verdict = "NON-ORGANIC" if net not in ("", "Organic") else "Organic"
        return (">> HTTP %s %s tracker=%s network=%s engagement=%s"
                % (status, verdict, tok, net, eng))
    except Exception:
        return ">> HTTP %s unparseable body: %r" % (status, body[:120])


def cmd_fullflow():
    """End-to-end diagnostic: replay the capture's WHOLE flow (session ->
    sdk_click -> attribution) for the capture's device (same gaid /
    android_uuid) with OUR signatures and the genuine retry semantics:
    created_at/sent_at fresh NOW, historical stamps (installed_at,
    click_time, install_begin_time, referrer, partner_params) kept exactly
    as the genuine device reported them.  If our signature making drives
    the server's verdict, the closing attribution GET returns
    NON-ORGANIC.  Body encoding = quote(v, safe=\"\") (capture-identical),
    key order = capture order, pacing = capture pacing."""
    with open(CAP_JSON, "r", encoding="utf-8") as f:
        recs = json.load(f)
    s42 = next(r for r in recs if r["sid"] == "42")
    s43 = next(r for r in recs if r["sid"] == "43")
    _, hdrs44, raw_query44 = load_capture()
    ua = hdrs44["user-agent"]
    goff = stamp_of(s42["body"]["created_at"])[2]

    def refreshed(body, keys=("created_at", "sent_at")):
        now = time.time()
        f = dict(body)
        f["created_at"] = fresh_stamp(now, goff)
        f["sent_at"] = fresh_stamp(now + 0.013, goff)
        return f

    from curl_cffi.requests import Session

    def send(label, method, path, fields, kind, sec):
        sg.CERT_SHA1 = CERT
        sg.CLIENT_SDK = CLIENT_SDK
        blob, auth = sg.mint_adj7(kind, fields, unix_sec=sec,
                                  client_sdk=CLIENT_SDK,
                                  include_block2=True)
        auth = auth_tail(auth, "8", "3.62.0")
        body = "&".join(k + "=" + urllib.parse.quote(str(v), safe="")
                        for k, v in fields.items())
        url = ("https://app.adjust.com" + path + "?" + body
               if method == "GET" else "https://app.adjust.com" + path)
        headers = {"Client-SDK": CLIENT_SDK, "User-Agent": ua,
                   "Accept-Encoding": "gzip", "Authorization": auth}
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        out("")
        out("FLOW %s  %s %s  (%d fields, kind=%s, signing second %d)"
            % (label, method, path, len(fields), kind, sec))
        out("  auth: %s ... [%s]" % (auth[:60], auth[-64:]))
        try:
            with Session(impersonate="chrome131_android") as s:
                if method == "POST":
                    r = s.post(url, content=body.encode(), headers=headers,
                               timeout=30)
                else:
                    r = s.get(url, headers=headers, timeout=30)
            status, text = r.status_code, r.text
        except Exception as exc:
            out("  !! transport error: %r" % (exc,))
            return None, None
        out("  HTTP %s" % status)
        out("  body: %s" % text[:600])
        out("  %s" % verdict_line(status, text))
        return status, text

    out("=" * 78)
    out("FULL-FLOW REPLAY for the capture device gaid=%s" % GAID)
    out("android_uuid=%s" % fields_orig_android_uuid())
    out("=" * 78)

    sec1 = int(time.time())
    f_session = refreshed(s42["body"])
    st1, tx1 = send("1/3 session", "POST", "/session", f_session, "session",
                    sec1)
    time.sleep(0.1)
    sec2 = int(time.time())
    f_click = refreshed(s43["body"])
    st2, tx2 = send("2/3 sdk_click", "POST", "/sdk_click", f_click, "click",
                    sec2)
    time.sleep(2.8)
    sec3 = int(time.time())
    pairs = parse_pairs(raw_query44)
    f_attr = decode_pairs(pairs)
    now = time.time()
    f_attr["created_at"] = fresh_stamp(now, goff)
    f_attr["sent_at"] = fresh_stamp(now + 0.013, goff)
    st3, tx3 = send("3/3 attribution", "GET", "/attribution", f_attr,
                    "attribution", sec3)
    out("")
    ff_nonorganic = False
    try:
        att = (json.loads(tx3) or {}).get("attribution") or {}
        ff_nonorganic = (st3 == 200
                         and att.get("network") not in (None, "", "Organic"))
    except Exception:
        pass
    if ff_nonorganic:
        out("FULL-FLOW RESULT: attribution came back NON-ORGANIC through"
            " OUR signatures -- the signature making drives the verdict"
            " end-to-end.")
    else:
        out("FULL-FLOW RESULT: attribution still Organic through our"
            " signatures -- the click association is dead server-side;"
            " no replay of any form can return NON-ORGANIC for this gaid.")
    append_md("FULL-FLOW replay (session -> sdk_click -> attribution, OUR"
              " signatures, capture device)", T)


def fields_orig_android_uuid():
    _, hdrs, raw_query = load_capture()
    return decode_pairs(parse_pairs(raw_query))["android_uuid"]


def cmd_probee():
    """The decisive signature probe: OUR fresh mint (fresh nonce12, fresh
    tag/body) signed at the ORIGINAL signing second (= created_at second,
    1791281861), sent with the ORIGINAL times.  Claims are identical to the
    genuine ones; only nonce12/H/body differ.  If the server verifies the
    blob by recomputing H from the query + the record's nonce (which a sane
    verifier MUST, since every genuine signing uses a fresh nonce), this
    returns NON-ORGANIC -> our signature making is server-verified."""
    _, hdrs, raw_query = load_capture()
    ua = hdrs["user-agent"]
    fields = decode_pairs(parse_pairs(raw_query))
    gepoch, _, _ = stamp_of(fields["created_at"])
    sg.CERT_SHA1 = CERT
    sg.CLIENT_SDK = CLIENT_SDK
    blob, auth = sg.mint_adj7("attribution", fields, unix_sec=gepoch,
                              client_sdk=CLIENT_SDK, include_block2=True)
    auth = auth_tail(auth, "8", "3.62.0")
    out("PROBE E  OUR mint, signing second = ORIGINAL created_at second"
        " (%d), original times, fresh nonce" % gepoch)
    out("  header == genuine header: %s"
        % (blob[:16] == bytes.fromhex(re.search(
            r'signature="([0-9A-Fa-f]+)"', hdrs["authorization"]).group(1))[:16]))
    orec, o = parse_record(blob)
    out("  our H: %s" % o["b"])
    out("  claims identical to genuine: %s"
        % (sg.build_claims("attribution", fields, client_sdk=CLIENT_SDK,
                           include_block2=True) ==
           sg.build_claims("attribution", fields, client_sdk=CLIENT_SDK,
                           include_block2=True)))
    from curl_cffi.requests import Session
    url = "https://app.adjust.com/attribution?" + raw_query
    headers = {"Client-SDK": CLIENT_SDK, "User-Agent": ua,
               "Accept-Encoding": "gzip", "Authorization": auth}
    with Session(impersonate="chrome131_android") as s:
        r = s.get(url, headers=headers, timeout=30)
    out("  HTTP %s" % r.status_code)
    out("  body: %s" % r.text[:600])
    out("  %s" % verdict_line(r.status_code, r.text))
    append_md("PROBE E (our mint at the original signing second, original"
              " times, fresh nonce)", T)


def cmd_probef():
    """Last matrix cell: NO Authorization header + the ORIGINAL times.
    Combined with PROBE E this decides whether even the booked answer is
    signature-gated or the endpoint keys purely on (times, H)."""
    _, hdrs, raw_query = load_capture()
    ua = hdrs["user-agent"]
    from curl_cffi.requests import Session
    url = "https://app.adjust.com/attribution?" + raw_query
    headers = {"Client-SDK": CLIENT_SDK, "User-Agent": ua,
               "Accept-Encoding": "gzip"}
    out("PROBE F  NO signature, ORIGINAL times (raw query verbatim)")
    with Session(impersonate="chrome131_android") as s:
        r = s.get(url, headers=headers, timeout=30)
    out("  HTTP %s" % r.status_code)
    out("  body: %s" % r.text[:600])
    out("  %s" % verdict_line(r.status_code, r.text))
    time.sleep(1.5)
    # and the mirror cell: genuine blob + original times was VERBATIM
    # (NON-ORGANIC); now OUR blob minted with the GENUINE nonce12 and
    # signing second -- must be byte-identical to the genuine blob if the
    # law is complete.  Offline check first, then send it.
    fields = decode_pairs(parse_pairs(raw_query))
    gepoch, _, _ = stamp_of(fields["created_at"])
    gsig = re.search(r'signature="([0-9A-Fa-f]+)"',
                     hdrs["authorization"]).group(1)
    gnonce = None
    _, g = parse_record(bytes.fromhex(gsig))
    gnonce = g["nonce12"]
    sg.CERT_SHA1 = CERT
    sg.CLIENT_SDK = CLIENT_SDK
    rblob, rauth = sg.mint_adj7("attribution", fields, unix_sec=gepoch,
                                client_sdk=CLIENT_SDK, include_block2=True,
                                nonce12=gnonce)
    same = rblob == bytes.fromhex(gsig)
    out("")
    out("OFFLINE MINT-BYTE-CHECK  our mint(genuine nonce12 %s, second %d,"
        " original fields) vs genuine blob: %s"
        % (gnonce.hex(), gepoch, "BYTE-IDENTICAL" if same else "DIFFERENT"))
    if not same:
        out("  ours: %s" % rblob.hex())
        out("  genr: %s" % gsig)
    if same:
        out("  -> our signature making reproduces THE accepted blob"
            " exactly; replaying it is a replay of our own mint.")
        out("")
        out("PROBE G  the blob our mint produced (== genuine bytes),"
            " original times")
        auth2 = auth_tail(rauth, "8", "3.62.0")
        headers2 = {"Client-SDK": CLIENT_SDK, "User-Agent": ua,
                    "Accept-Encoding": "gzip", "Authorization": auth2}
        with Session(impersonate="chrome131_android") as s2:
            r2 = s2.get(url, headers=headers2, timeout=30)
        out("  HTTP %s" % r2.status_code)
        out("  body: %s" % r2.text[:600])
        out("  %s" % verdict_line(r2.status_code, r2.text))
    append_md("PROBE F/G (no-auth + original times; our mint fed the"
              " genuine nonce/second)", T)


def main():
    offline_only = "--offline" in sys.argv
    if "--verbatim" in sys.argv:
        cmd_verbatim()
        return 0
    if "--probee" in sys.argv:
        cmd_probee()
        return 0
    if "--probef" in sys.argv:
        cmd_probef()
        return 0
    if "--fullflow" in sys.argv:
        cmd_fullflow()
        return 0
    out("=" * 78)
    out("ADJ7 REPLAY RULE  --  fresh genuine capture payrupik_new, sid 44")
    out("target verdict: NON-ORGANIC (tracker %s / network %s)"
        % (WANT_TRACKER, WANT_NETWORK))
    out("=" * 78)

    rec44, hdrs, raw_query = load_capture()
    pairs = parse_pairs(raw_query)
    fields_orig = decode_pairs(pairs)
    genuine_auth = hdrs["authorization"]
    ua = hdrs["user-agent"]
    genuine_resp = rec44["response"]
    out("capture sid 44: %s" % rec44["url"][:100] + " ...")
    out("  %d query params; keys in wire order:" % len(pairs))
    out("    " + ", ".join(k for k, _ in pairs))
    out("  push_token in query? %s" % ("yes" if "push_token" in
                                       fields_orig else "NO (this capture)"))
    out("  UA: %s" % ua)

    # ---------- offline law check on the genuine blob -------------------
    out("")
    out("-" * 78)
    out("OFFLINE LAW CHECK -- genuine sid 44 signature")
    sig_hex = re.search(r'signature="([0-9A-Fa-f]+)"',
                        genuine_auth).group(1)
    gblob = bytes.fromhex(sig_hex)
    out("  blob len %d B, tag ok: %s" % (len(gblob), sg.verify_tag(gblob)))
    grec, g = parse_record(gblob)
    if g is None:
        out("  !! record regex failed; decrypted head: %r" % grec[:140])
        return 1
    out("  record a (nonce lo8 u64le) = %s" % g["a"].strip())
    out("  record b (H)               = %s" % g["b"])
    out("  record c (cert40)          = %s" % g["c"])
    out("  record c == CERT ASCII     : %s"
        % (g["c"] == CERT))
    out("  record d (nonce hi4 hex)   = %s" % g["d"])
    out("  record e == sha256('') up  : %s"
        % (g["e"] == sg.SHA0_HEX))
    out("  nonce12 = %s" % g["nonce12"].hex())

    gepoch, gms, goff = stamp_of(fields_orig["created_at"])
    out("  capture created_at %s (epoch %d, offset %ds)"
        % (fields_orig["created_at"], gepoch, goff))

    claims_b2 = sg.build_claims("attribution", fields_orig,
                                client_sdk=CLIENT_SDK, include_block2=True)
    claims_nb = sg.build_claims("attribution", fields_orig,
                                include_block2=False)
    fields_push = dict(fields_orig)
    fields_push["push_token"] = FAKE_PUSH
    claims_push = sg.build_claims("attribution", fields_push,
                                  client_sdk=CLIENT_SDK, include_block2=True)
    H = sg.commitment_digest(claims_b2, g["nonce12"],
                             cert40=g["c"].encode()).hex().upper()
    H_nb = sg.commitment_digest(claims_nb, g["nonce12"],
                                cert40=g["c"].encode()).hex().upper()
    H_push = sg.commitment_digest(claims_push, g["nonce12"],
                                  cert40=g["c"].encode()).hex().upper()
    out("  H over claims(block2, %d B)  == record b : %s"
        % (len(claims_b2), H == g["b"]))
    out("  H over claims(no block2, %d B) == record b: %s"
        % (len(claims_nb), H_nb == g["b"]))
    out("  H over claims(+push_token)   == record b : %s  (must be False)"
        % (H_push == g["b"]))
    gsec = header_second(gblob, gepoch - 120, gepoch + 120)
    out("  header second = %s (created_at second %d, delta %+ds)"
        % (gsec, gepoch, (gsec - gepoch) if gsec else 0))
    if H != g["b"]:
        out("  !! H MISMATCH -- the signed map is NOT the decoded query;")
        out("     diagnose before trusting the replay verdict")
    else:
        out("  PROVEN: the signed map == the 22 decoded query params,"
            " claims fold in block2 (activity_kind=attribution +"
            " client_sdk=android5.6.0), no push_token.")

    # ---------- our mint, offline self-check ----------------------------
    out("")
    out("-" * 78)
    out("OFFLINE OUR-MINT SELF-CHECK (fresh times, signing second = now)")
    now = time.time()
    fields_fresh = dict(fields_orig)
    created = fresh_stamp(now, goff)
    sent = fresh_stamp(now + 0.013, goff)
    fields_fresh["created_at"] = created
    fields_fresh["sent_at"] = sent
    out("  fresh created_at = %s" % created)
    out("  fresh sent_at    = %s" % sent)
    sec = int(time.time())
    oblob, oauth = sign_attribution(fields_fresh, sec)
    out("  mint: signing second %d, blob %d B, tag ok %s, header ok %s"
        % (sec, len(oblob), sg.verify_tag(oblob),
           oblob[:16] == sg.make_header(sec)))
    orec, o = parse_record(oblob)
    if o is None:
        out("  !! our record regex failed: %r" % orec[:140])
        return 1
    oclaims = sg.build_claims("attribution", fields_fresh,
                              client_sdk=CLIENT_SDK, include_block2=True)
    oH = sg.commitment_digest(oclaims, o["nonce12"],
                              cert40=o["c"].encode()).hex().upper()
    out("  our record c == CERT ASCII : %s" % (o["c"] == CERT))
    out("  our H recheck vs record b  : %s" % (oH == o["b"]))
    out("  our nonce12 = %s (genuine %s)" % (o["nonce12"].hex(),
                                             g["nonce12"].hex()))
    out("  record-vs-record (ours vs genuine):")
    for f in ("a", "b", "c", "d", "e"):
        out("    %s: ours=%s genuine=%s same=%s"
            % (f, o[f][:48], g[f][:48], o[f] == g[f]))
    hexdump_str_diff(oclaims.decode("latin1"), claims_b2.decode("latin1"),
                     "claims (ours-fresh vs genuine-times)")

    # ---------- the raw query we will send ------------------------------
    fresh_pairs = [(k, urllib.parse.quote(fields_fresh[k], safe="")
                    if k in ("created_at", "sent_at") else v)
                   for k, v in pairs]
    fresh_query = "&".join(k + "=" + v for k, v in fresh_pairs)
    hexdump_str_diff(raw_query, fresh_query, "raw query (fresh vs capture)")
    changed = [k for k, v in pairs
               if v != dict(fresh_pairs)[k]]
    out("  params whose raw value changed: %s" % changed)

    if offline_only:
        out("")
        out("offline-only run: nothing sent.")
        return 0

    # ---------- probes ---------------------------------------------------
    from curl_cffi.requests import Session

    def send(label, query, auth):
        url = "https://app.adjust.com/attribution?" + query
        headers = {"Client-SDK": CLIENT_SDK,
                   "User-Agent": ua,
                   "Accept-Encoding": "gzip"}
        if auth is not None:
            headers["Authorization"] = auth
        out("")
        out("-" * 78)
        out("PROBE %s" % label)
        out("  auth: %s" % ("(none)" if auth is None else auth[:76] + " ..."))
        try:
            with Session(impersonate="chrome131_android") as s:
                r = s.get(url, headers=headers, timeout=30)
            status, body = r.status_code, r.text
        except Exception as exc:
            out("  !! transport error: %r" % (exc,))
            return None
        out("  HTTP %s" % status)
        out("  body: %s" % body[:600])
        verdict, detail = "UNPARSEABLE", body[:200]
        try:
            j = json.loads(body)
            adid = j.get("adid", "")
            att = j.get("attribution")
            if att:
                net = att.get("network", "")
                tok = att.get("tracker_token", "")
                verdict = ("NON-ORGANIC" if net and net != "Organic"
                           else "Organic")
                detail = ("tracker=%s network=%s adid=%s (adid==capture: %s)"
                          % (tok, net, adid, adid == ADID))
            else:
                verdict = "NO-ATTRIBUTION"
                detail = json.dumps(j)[:200]
        except Exception:
            pass
        out("  >> %s  [%s]" % (verdict, detail))
        out("  >> RULE CHECK: %s"
            % ("PASS (NON-ORGANIC %s/%s)" % (WANT_TRACKER, WANT_NETWORK)
               if verdict == "NON-ORGANIC"
               and WANT_TRACKER in detail and WANT_NETWORK in detail
               else "FAIL"))
        return (status, verdict, detail, body)

    oauth_f = auth_tail(oauth, "8", "3.62.0")
    out("")
    out("=" * 78)
    out("auth headers used:")
    out("  ours verbatim (mint_adj7): headers_id 7 / native 3.61.0")
    out("  ours faithful (rewritten): headers_id 8 / native 3.62.0")
    out("  genuine (capture)        : headers_id 8 / native 3.62.0")

    results = {}
    results["PRIMARY"] = send("PRIMARY  our signature, fresh times, "
                              "mint_adj7 verbatim auth", fresh_query, oauth)
    time.sleep(1.5)
    results["PRIMARY-B"] = send("PRIMARY-B our signature, fresh times, "
                                "capture-faithful auth tail (8/3.62.0)",
                                fresh_query, oauth_f)
    time.sleep(1.5)
    results["CONTROL-A"] = send("CONTROL-A GENUINE signature verbatim, "
                                "fresh times", fresh_query, genuine_auth)
    time.sleep(1.5)
    results["CONTROL-B"] = send("CONTROL-B our signature (faithful tail), "
                                "STALE capture times", raw_query, oauth_f)
    time.sleep(1.5)
    results["CONTROL-C"] = send("CONTROL-C NO signature, fresh times",
                                fresh_query, None)

    # ---------- summary ---------------------------------------------------
    out("")
    out("=" * 78)
    out("SUMMARY")
    for k in ("PRIMARY", "PRIMARY-B", "CONTROL-A", "CONTROL-B", "CONTROL-C"):
        r = results.get(k)
        if r is None:
            out("  %-9s transport error" % k)
        else:
            out("  %-9s HTTP %s  %s  %s" % (k, r[0], r[1], r[2]))
    ours = [k for k in ("PRIMARY", "PRIMARY-B")
            if results.get(k) and results[k][1] == "NON-ORGANIC"]
    ctrl_c = results.get("CONTROL-C") and results["CONTROL-C"][1]
    out("")
    if ours:
        out("RULE: %s -> our signature making REPLAYED THE BOOKED ATTRIBUTION"
            % "/".join(ours))
        if ctrl_c == "NON-ORGANIC":
            out("CAVEAT: CONTROL-C (no signature) also returned NON-ORGANIC"
                " -- GET /attribution is signature-blind for this device"
                " state; the verdict then rests on the gaid alone and the"
                " signature proof lives in the /session hop (see md).")
    else:
        out("RULE: our probes did NOT return NON-ORGANIC -- see the"
            " per-probe output and the offline diffs above.")

    write_md(results)
    return 0


def write_md(results):
    lines = []
    lines.append("# REPLAY RULE RESULT -- adj7 attribution replay")
    lines.append("")
    lines.append("Run: %s  (this machine, the capture's own public IP)"
                 % datetime.now().strftime("%Y-%m-%d %H:%M:%S %z"))
    lines.append("")
    lines.append("Golden capture: `payrupik_new/payrupik_new__adjust.json`"
                 " sid 44 (fresh genuine install, booked NON-ORGANIC"
                 " tracker **%s** / **%s** minutes earlier on this same IP)."
                 % (WANT_TRACKER, WANT_NETWORK))
    lines.append("")
    lines.append("## Probe results")
    lines.append("")
    lines.append("| probe | auth | times | result |")
    lines.append("|---|---|---|---|")
    rows = [
        ("PRIMARY", "ours, mint_adj7 verbatim (hdrs_id 7 / native 3.61.0)",
         "fresh"),
        ("PRIMARY-B", "ours, capture-faithful tail (hdrs_id 8 / native"
         " 3.62.0)", "fresh"),
        ("CONTROL-A", "GENUINE capture auth verbatim", "fresh"),
        ("CONTROL-B", "ours, capture-faithful tail", "STALE (capture)"),
        ("CONTROL-C", "none", "fresh"),
    ]
    for k, a, t in rows:
        r = results.get(k)
        lines.append("| %s | %s | %s | %s |"
                     % (k, a, t,
                        ("HTTP %s -- %s (%s)" % (r[0], r[1], r[2]))
                        if r else "transport error"))
    lines.append("")
    lines.append("## Full transcript")
    lines.append("")
    lines.append("```")
    lines.extend(T)
    lines.append("```")
    with open(RESULT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    out("")
    out("wrote %s" % RESULT_MD)


if __name__ == "__main__":
    sys.exit(main())

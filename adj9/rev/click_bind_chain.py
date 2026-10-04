r"""click_bind_chain.py — user's tracker link clicked with a gps_adid, then the
SAME gps_adid used in the signed /session, /sdk_click and /attribution calls.

Rationale (rev/WALL_A_SLICE_86/87.md, rev/TODAY.md §7.2): non-organic is a
click->install matching outcome, not a signature verdict. The genuine device
flow on the wire (D:\advance_emu\ssl_interception\wire_dumps) is
    /session -> /sdk_click -> /attribution
with Play-referrer click_time / install_begin_time and installed_at = begin+7.4s.
This script mirrors that exactly, with the adj9 signature minted offline by the
proven maker (adj9_full_chain: FinEx body + Random3 header, live-accepted 200 —
slices 81/82).

Flow per attempt:
  0. fresh gps_adid + android_uuid
  1. GET the tracker link with {click_id}/{sub3} expanded (BUG 8: expand first)
     and gps_adid stamped on -> 302 market://...referrer=adjust_reftag=...
  2. /session   (installed_at = click+27.431s, tz +0530, moto g42 identity)
  3. /sdk_click (referrer = the minted reftag string, click_time = click epoch,
                 install_begin_time = click+20s, both *_server = -2s)
  4. /attribution (initiated_by=backend, 22 params, no push_token) + 20 s re-poll

Usage:  python click_bind_chain.py [attempts] [--click-only]
"""
import http.client
import json
import os
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc  # the proven maker (FinEx + Random3 + wire shape)

# --- the user's link, verbatim -------------------------------------------
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
        "&creative=penti_generic&click_id={click_id}&idfa={sub3}"
        "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
        ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D"
        "{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital"
        "%26offer_id%3Dpntvkmdup1mmp"
        "&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
        ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D"
        "{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3D"
        "vkmdigital%26offer_id%3Dpntvkmdup1mmp")

# the click is a browser event -> Chrome-on-Android UA (attempt10's finding)
CLICK_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

CTIT = 20        # click -> install_begin gap (s); genuine winner was 210 s
INS_LAG = 7      # install_begin -> installed_at (s); genuine winner was +7.431
OUT = os.path.join(HERE, "click_bind_result.json")

# the winning non-organic record is on a moto g42 / api31 / os12 / +0530 identity
fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"


def expand(link, gps):
    """Expand macros BEFORE the fetch (TEST_LOG bug 8)."""
    return (link.replace("{click_id}", "clk-" + uuid.uuid4().hex[:12])
                .replace("{sub3}", gps))


def tracker_click(link, gps):
    """GET the tracker link (gps_adid stamped on), follow hops. Returns
    (http, referrer, hops)."""
    parts = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    q["gps_adid"] = gps                      # deterministic adid bind
    hop = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), ""))
    hops, code, ref = [], -1, None
    for _ in range(4):
        pr = urllib.parse.urlsplit(hop)
        if pr.scheme == "market":            # end of the chain
            break
        conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=25)
        try:
            conn.request("GET", urllib.parse.urlunsplit(
                ("", "", pr.path or "/", pr.query, "")),
                headers={"User-Agent": CLICK_UA,
                         "Accept-Encoding": "identity",
                         "Connection": "close"})
            r = conn.getresponse()
            r.read()
            code, loc = r.status, (r.getheader("Location") or "")
        finally:
            conn.close()
        hops.append({"url": hop[:200], "http": code, "location": loc[:300]})
        if "referrer=" in loc:
            ref = urllib.parse.unquote(loc.split("referrer=", 1)[1])
            return code, ref, hops
        if code not in (301, 302, 303, 307, 308) or not loc:
            return code, None, hops
        hop = urllib.parse.urljoin(hop, loc)
    return code, ref, hops


def attempt(i, out, click_only=False):
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    link = expand(LINK, gps)
    t0 = int(time.time())
    print("[%d] gps=%s auid=%s t_click=%d" % (i, gps, auid, t0), flush=True)
    print("[%d] click: %s" % (i, link[:150]), flush=True)
    code, ref, hops = tracker_click(link, gps)
    rec = {"idx": i, "gps": gps, "auid": auid, "t_click": t0,
           "click_http": code, "referrer": ref, "hops": hops,
           "session": None, "click": None, "attr": [], "verdict": None}
    print("[%d] CLICK http=%s" % (i, code), flush=True)
    for h in hops:
        print("      hop %s -> %s %s" % (h["http"], h["url"][:110],
                                         h["location"][:110]), flush=True)
    print("[%d] REFERRER: %s" % (i, ref), flush=True)
    if click_only:
        out.append(rec)
        return
    if not ref or "adjust_reftag=" not in ref:
        rec["verdict"] = "no reftag from tracker"
        out.append(rec)
        return

    # natural funnel timeline, entirely in the past by send time
    tb = t0 + CTIT                                  # install_begin_time
    ins = fc.fmt(tb + INS_LAG, 431)                 # installed_at (.431 like real)
    print("[%d] click_time=%s install_begin=%s installed=%s"
          % (i, fc.fmt(t0, 0).decode(), fc.fmt(tb, 0).decode(),
             ins.decode()), flush=True)

    # 2. /session
    s, r = fc.api_session(gps, auid, ins)
    rec["session"] = [s, r[:600]]
    print("[%d] SESSION %s %s" % (i, s, r[:250]), flush=True)

    # 3. /sdk_click (reftag referrer + Play-shaped click/install times)
    s, r = fc.api_sdk_click(gps, auid, ref, t0, tb, ins)
    rec["click"] = [s, r[:600]]
    print("[%d] CLICK-PKG %s %s" % (i, s, r[:250]), flush=True)

    # never present future stamps: the install must have happened by now
    wait = (tb + INS_LAG + 3) - int(time.time())
    if wait > 0:
        print("[%d] waiting %ds so the install timeline is in the past"
              % (i, wait), flush=True)
        time.sleep(wait)

    # 4. /attribution + re-poll
    s, r = fc.api_attribution(gps, auid, "")
    rec["attr"].append([s, r[:2000]])
    print("[%d] ATTR1 %s %s" % (i, s, r[:1200]), flush=True)
    time.sleep(20)
    s, r = fc.api_attribution(gps, auid, "")
    rec["attr"].append([s, r[:2000]])
    print("[%d] ATTR2 %s %s" % (i, s, r[:1200]), flush=True)
    try:
        a = json.loads(r)["attribution"]
        rec["verdict"] = "%s / %s / eng=%s / inst=%s" % (
            a.get("tracker_token"), a.get("network"),
            a.get("engagement_time"), a.get("installed_at"))
    except Exception:
        rec["verdict"] = "parse-fail"
    print("[%d] VERDICT: %s" % (i, rec["verdict"]), flush=True)
    out.append(rec)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    n = int(args[0]) if args else 1
    click_only = "--click-only" in sys.argv
    out = []
    for i in range(1, n + 1):
        try:
            attempt(i, out, click_only)
        except Exception as e:
            print("[%d] EXC %s: %s" % (i, type(e).__name__, e), flush=True)
            out.append({"idx": i, "error": "%s: %s" % (type(e).__name__, e)})
    json.dump(out, open(OUT, "w"), indent=1)
    print("saved %s" % OUT, flush=True)


if __name__ == "__main__":
    main()
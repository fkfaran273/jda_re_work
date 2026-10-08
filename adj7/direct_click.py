"""direct_click.py -- ONE direct click to the adjust tracker (the adj9
winning shape): app.adjust.com/{token}?campaign=...&adgroup=...&gps_adid=<gaid>
-- no mobpine redirect chain.  Follows Location hops manually with curl_cffi
chrome131_android, fills empty gps_adid macros with the gaid (the
run_install._fill_device_id split-on-& rule), stops at the market:// or
intent:// hop and takes the reftag from its referrer= param.

Writes preclick2.env (LF-only lines, bare values):
    line 1: referrer        (the full urldecoded reftag string)
    line 2: gaid
    line 3: click_server_sec (the adjust response Date epoch)
"""
import email.utils
import re
import sys
import urllib.parse
import uuid

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
TRACKER = "https://app.adjust.com/2015o4dz"

BROWSER_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
BROWSER_HEADERS = {
    "User-Agent": BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


def _fill_device_id(u, gaid):
    """run_install.py's rule: an empty/unfilled gps_adid= macro in the chain
    gets the gaid (an Adjust click without a device id can never join)."""
    out = []
    base, qmark, query = u.partition("?")
    for part in query.split("&"):
        k, sep, v = part.partition("=")
        if (sep and k in ("gps_adid", "adj_gps_adid")
                and (v == "" or v.startswith("%7B") or v.startswith("{"))):
            out.append(k + "=" + gaid)
        else:
            out.append(part)
    return base + qmark + "&".join(out)


def _reftag_in(s):
    if "referrer=" not in s:
        return None
    ref = urllib.parse.unquote(s.split("referrer=", 1)[1])
    ref = ref.split(";S.browser_fallback_url")[0]
    return re.sub(r"&ip_address=%7B[^&]*%7D", "", ref)


def _referrer_from_nonhttp(u):
    """market:// / intent:// hop: the reftag rides in referrer=."""
    # 1) parse the query properly (browser_click.py's way) so trailing
    #    market params (hl=...) don't ride into the referrer value
    q = urllib.parse.urlsplit(u).query
    try:
        parsed = urllib.parse.parse_qs(q, keep_blank_values=True)
    except Exception:
        parsed = {}
    for cand in parsed.get("referrer", []):
        ref = urllib.parse.unquote(cand)
        if "adjust_reftag" in ref:
            return ref
    # 2) run_install's split-on-& fallback
    ref = _reftag_in(u)
    if ref and "adjust_reftag" in ref:
        return ref
    return parsed.get("referrer", [None])[0] or ref


def main():
    gaid = str(uuid.uuid4())
    url = TRACKER + ("?campaign=HM2&adgroup=HM2_1722_&gps_adid=" + gaid)
    click_server_sec = None
    reftag = None

    from curl_cffi import requests as cr
    for hop in range(10):
        if not (url.startswith("http://") or url.startswith("https://")):
            print("HOP %d: non-http stop hop: %s" % (hop, url[:300]))
            reftag = _referrer_from_nonhttp(url)
            break
        r = cr.get(url, headers=BROWSER_HEADERS, timeout=30,
                   impersonate="chrome131_android", allow_redirects=False)
        status = r.status_code
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        text = r.text or ""
        print("HOP %d: HTTP %d  %s" % (hop, status, url[:220]))
        if "app.adjust.com" in url:
            d = hdrs.get("date")
            if d:
                try:
                    click_server_sec = int(
                        email.utils.parsedate_to_datetime(d).timestamp())
                    print("      adjust Date -> click_server_sec=%d"
                          % click_server_sec)
                except Exception as exc:
                    print("      Date parse failed: %r" % (exc,))
        loc = hdrs.get("location")
        if loc:
            loc = _fill_device_id(loc, gaid)
            print("      -> Location: %s" % loc[:220])
            if not (loc.startswith("http://") or loc.startswith("https://")):
                reftag = _referrer_from_nonhttp(loc)
                break
            if "referrer=" in loc:
                cand = _reftag_in(loc)
                if cand and "adjust_reftag" in cand:
                    reftag = cand
                    break
            url = loc
            continue
        # 200 with no Location: look in the body
        if "adjust_reftag" in text:
            cand = _reftag_in(text)
            if cand:
                reftag = cand
                print("      reftag found in body")
                break
        m = re.search(r"(?:window\.|document\.)?location\.replace\("
                      r"\s*[\"']([^\"']+)[\"']", text)
        if m:
            nxt = _fill_device_id(m.group(1), gaid)
            print("      -> location.replace: %s" % nxt[:220])
            if not (nxt.startswith("http://") or nxt.startswith("https://")):
                reftag = _referrer_from_nonhttp(nxt)
                break
            url = nxt
            continue
        print("      no Location, no reftag marker; body head: %r"
              % text[:200])
        break

    print()
    print("GAID=%s" % gaid)
    print("CLICK_SERVER_SEC=%s" % click_server_sec)
    print("REFTAG=%s" % reftag)
    if reftag and "adjust_reftag" in reftag and click_server_sec:
        with open(HERE + r"\preclick2.env", "w", newline="\n") as f:
            f.write("%s\n%s\n%d\n" % (reftag, gaid, click_server_sec))
        print("preclick2.env written (referrer/gaid/click_server_sec)")
        return 0
    print("INCOMPLETE: reftag-with-adjust_reftag or Date missing")
    return 1


if __name__ == "__main__":
    sys.exit(main())

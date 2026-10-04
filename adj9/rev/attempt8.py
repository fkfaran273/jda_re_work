"""attempt8.py — attempt 6's exact funnel, one variable changed: the
adjust-API transport now reproduces the REAL Dalvik request line-for-line
(header order + Connection: Keep-Alive + Accept-Encoding: gzip, per the
SAZ). If our HTTP/1.1 urllib fingerprint was the organic cause, this
flips it.

Funnel: verbatim link click (idfa=<adid>, click_id macro kept literal as
attempt 6), 4-min CTIT wait, /session, /sdk_click (fresh reftag), then
4 /attribution polls. Signer = attrib_test.sign (zero #0 — attempt 7
showed real #0 changes nothing).
"""
import datetime
import gzip
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict

import attrib_test
from attrib_test import COMMON, NoRedirect, log, log_lines

MOTO_UA = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
           "Build/S2SE32.28-28-4") + ")"
CB = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"


def iso(now, off=0.0, ms="000"):
    return (now + datetime.timedelta(seconds=off)).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def dalvik_send(method, path, params):
    """Send with byte-exact Dalvik/HttpURLConnection headers."""
    created, sent = iso(datetime.datetime.now(
        datetime.timezone.utc)), None
    sent = iso(datetime.datetime.now(datetime.timezone.utc), 0, "060")
    blob, status, hdr_ok = attrib_test.sign(created)
    sig_b64 = __import__("base64").b64encode(blob).decode()
    auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)
    p = dict(params)
    p["created_at"] = created
    p["sent_at"] = sent
    lines = []
    if method == "POST":
        body = urllib.parse.urlencode(p).encode()
        head = ["%s %s HTTP/1.1" % (method, path),
                "Client-SDK: android5.7.0",
                "Authorization: %s" % auth,
                "Content-Type: application/x-www-form-urlencoded",
                "User-Agent: %s" % MOTO_UA,
                "Host: app.adjust.com",
                "Connection: Keep-Alive",
                "Accept-Encoding: gzip",
                "Content-Length: %d" % len(body)]
    else:
        qs = urllib.parse.urlencode(p)
        body = b""
        head = ["GET %s?%s HTTP/1.1" % (path, qs),
                "Client-SDK: android5.7.0",
                "Authorization: %s" % auth,
                "User-Agent: %s" % MOTO_UA,
                "Host: app.adjust.com",
                "Connection: Keep-Alive",
                "Accept-Encoding: gzip"]
    raw = ("\r\n".join(head) + "\r\n\r\n").encode() + body
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection(
        ("app.adjust.com", 443), timeout=30), server_hostname="app.adjust.com")
    s.sendall(raw)
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n0\r\n\r\n" in buf or (b"Content-Length" in buf.split(
                b"\r\n\r\n")[0] and len(buf) > 200):
            # read until content-length satisfied or chunk end
            hdr_end = buf.find(b"\r\n\r\n")
            if hdr_end > 0:
                hh = buf[:hdr_end].decode("latin1")
                m = re.search(r"content-length: (\d+)", hh, re.I)
                if m and len(buf) >= hdr_end + 4 + int(m.group(1)):
                    break
                if "chunked" in hh and b"\r\n0\r\n\r\n" in buf:
                    break
    s.close()
    hdr_end = buf.find(b"\r\n\r\n")
    head_txt = buf[:hdr_end].decode("latin1")
    data = buf[hdr_end + 4:]
    if "Content-Length" in head_txt:
        m = re.search(r"content-length: (\d+)", head_txt, re.I)
        if m:
            data = data[:int(m.group(1))]
    elif "chunked" in head_txt.lower():
        out = b""
        while data:
            m = re.match(rb"([0-9a-fA-F]+)\r\n", data)
            if not m:
                break
            n = int(m.group(1), 16)
            out += data[m.end():m.end() + n]
            data = data[m.end() + n + 2:]
        data = out
    if "content-encoding: gzip" in head_txt.lower():
        data = gzip.decompress(data)
    code = int(head_txt.split()[1])
    log("  sig %s law=%s -> %d %s" % (status, hdr_ok, code,
                                      data[:300].decode("utf-8", "replace")))
    return code, data.decode("utf-8", "replace")


def click_new(adid):
    url = ("https://app.adjust.com/1sd1lk6a"
           "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id={click_id}&idfa=" + adid +
           "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
           "&event_callback_bfi71x=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
           "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
           "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Mozilla/5.0 (Linux; Android 12; moto g42) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 "
                      "Mobile Safari/537.36"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=30)
        loc = r.headers.get("Location")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location")
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc or "")
    return (m.group(1) if m else None), loc


def main():
    adid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    attrib_test.IDENT["gps_adid"] = adid
    attrib_test.IDENT["android_uuid"] = auuid
    log("gps_adid/android_uuid: %s / %s" % (adid[:13], auuid[:13]))

    now = datetime.datetime.now(datetime.timezone.utc)
    reftag, loc = click_new(adid)
    log("click reftag=%s" % reftag)
    assert reftag
    click_ts = iso(now, 0, "100")
    attrib_test.IDENT["installed_at"] = iso(now, 190, "400")
    attrib_test.IDENT["updated_at"] = iso(now, 190, "400")

    log("== CTIT wait 250 s ==")
    time.sleep(250)

    log("== 1: /session (Dalvik headers) ==")
    s = dict(attrib_test.IDENT)
    s.update(COMMON)
    s["initiating_package_name"] = "com.android.vending"
    s.update({"session_count": "1", "foreground": "1"})
    dalvik_send("POST", "/session", s)
    time.sleep(1)

    log("== 2: /sdk_click ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    c = dict(attrib_test.IDENT)
    c.update(COMMON)
    c["initiating_package_name"] = "com.android.vending"
    c.update({
        "source": "install_referrer", "referrer": ref,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": click_ts, "click_time_server": click_ts,
        "install_begin_time": iso(now, 120, "200"),
        "install_begin_time_server": iso(now, 120, "200"),
        "session_count": "1", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    dalvik_send("POST", "/sdk_click", c)
    time.sleep(6)

    att = dict(attrib_test.IDENT)
    att.update({k: v for k, v in COMMON.items()
                if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                         "needs_response_details", "attribution_deeplink",
                         "tracking_enabled", "ui_mode",
                         "offline_mode_enabled")})
    att["initiated_by"] = "backend"
    for i, wait in enumerate([0, 30, 60], 1):
        if wait:
            time.sleep(wait)
        log("== 3.%d: /attribution poll %d ==" % (i, i))
        dalvik_send("GET", "/attribution", att)

    open("attempt8.log", "w").write("\n".join(log_lines))
    print("saved attempt8.log", flush=True)


if __name__ == "__main__":
    main()

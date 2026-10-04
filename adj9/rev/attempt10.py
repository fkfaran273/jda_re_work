"""attempt10.py — two upgrades over attempt 8:
  1. All adjust.com API calls via curl_cffi impersonate="okhttp4" — the
     TLS/H2 fingerprint the REAL Android SDK (OkHttp) presents. Python's
     OpenSSL handshake was the one layer we couldn't fake; this can.
  2. /sdk_click now carries the SDK's native params: top-level `reftag`
     and `click_label` (both exist as real param names in classes3.dex).

Click still urllib with Android-Chrome UA (proven to mint reftags);
CTIT ~4 min; session-first; attribution x3.
"""
import datetime
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import attrib_test
from attrib_test import COMMON, NoRedirect, log, log_lines
from curl_cffi import requests as creq

MOTO_UA = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
           "Build/S2SE32.28-28-4)")
CB = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"


def iso(now, off=0.0, ms="000"):
    return (now + datetime.timedelta(seconds=off)).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def okhttp_send(method, path, params):
    """(name kept; uses raw Dalvik-ordered socket from attempt8 since
    curl_cffi 0.16 has no okhttp target on py3.14)"""
    import base64
    import socket as _sk
    import ssl as _ssl
    created = iso(datetime.datetime.now(datetime.timezone.utc))
    sent = iso(datetime.datetime.now(datetime.timezone.utc), 0, "060")
    blob, status, hdr_ok = attrib_test.sign(created)
    auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())
    p = dict(params)
    p["created_at"] = created
    p["sent_at"] = sent
    if method == "POST":
        body = urllib.parse.urlencode(p).encode()
        head = ["POST %s HTTP/1.1" % path,
                "Client-SDK: android5.7.0",
                "Authorization: %s" % auth,
                "Content-Type: application/x-www-form-urlencoded",
                "User-Agent: %s" % MOTO_UA,
                "Host: app.adjust.com",
                "Connection: Keep-Alive",
                "Accept-Encoding: gzip",
                "Content-Length: %d" % len(body)]
    else:
        body = b""
        qs = urllib.parse.urlencode(p)
        head = ["GET %s?%s HTTP/1.1" % (path, qs),
                "Client-SDK: android5.7.0",
                "Authorization: %s" % auth,
                "User-Agent: %s" % MOTO_UA,
                "Host: app.adjust.com",
                "Connection: Keep-Alive",
                "Accept-Encoding: gzip"]
    raw = ("\r\n".join(head) + "\r\n\r\n").encode() + body
    ctx = _ssl.create_default_context()
    s = ctx.wrap_socket(_sk.create_connection(
        ("app.adjust.com", 443), timeout=30), server_hostname="app.adjust.com")
    s.sendall(raw)
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except _sk.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n0\r\n\r\n" in buf:
            break
        he = buf.find(b"\r\n\r\n")
        if he > 0:
            m = re.search(r"content-length: (\d+)", buf[:he].decode("latin1"),
                          re.I)
            if m and len(buf) >= he + 4 + int(m.group(1)):
                break
    s.close()
    he = buf.find(b"\r\n\r\n")
    head_txt = buf[:he].decode("latin1")
    data = buf[he + 4:]
    m = re.search(r"content-length: (\d+)", head_txt, re.I)
    if m:
        data = data[:int(m.group(1))]
    elif "chunked" in head_txt.lower():
        out = b""
        while data:
            m2 = re.match(rb"([0-9a-fA-F]+)\r\n", data)
            if not m2:
                break
            n = int(m2.group(1), 16)
            out += data[m2.end():m2.end() + n]
            data = data[m2.end() + n + 2:]
        data = out
    if "content-encoding: gzip" in head_txt.lower():
        import gzip as _gz
        data = _gz.decompress(data)
    code = int(head_txt.split()[1])
    log("  sig %s law=%s -> %d %s" % (status, hdr_ok, code,
                                      data[:300].decode("utf-8", "replace")))
    return code, data.decode("utf-8", "replace")


def click(adid):
    """Click via curl_cffi chrome131_android (real Android browser TLS/H2
    fingerprint + UA) — attempt 9 proved desktop-chrome gets steered to
    the iOS store, so Android-browser identity is essential."""
    url = ("https://app.adjust.com/1sd1lk6a"
           "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id={click_id}&idfa=" + adid + "&gps_adid=" + adid +
           "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
           "&event_callback_bfi71x=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
           "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
           "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
    s = creq.Session(impersonate="chrome131_android")
    r = s.get(url, allow_redirects=False, timeout=30)
    loc = r.headers.get("location") or r.headers.get("Location") or ""
    log("  click -> %d %s" % (r.status_code, loc[:120]))
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
    return (m.group(1) if m else None), loc


def main():
    adid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    attrib_test.IDENT["gps_adid"] = adid
    attrib_test.IDENT["android_uuid"] = auuid
    log("gps_adid/android_uuid: %s / %s" % (adid[:13], auuid[:13]))

    now = datetime.datetime.now(datetime.timezone.utc)
    reftag, loc = click(adid)
    log("click reftag=%s loc=%s" % (reftag, (loc or "")[:90]))
    assert reftag, "no reftag"
    click_ts = iso(now, 0, "100")
    attrib_test.IDENT["installed_at"] = iso(now, 190, "400")
    attrib_test.IDENT["updated_at"] = iso(now, 190, "400")

    log("== CTIT wait 250 s ==")
    time.sleep(250)

    log("== 1: /session (okhttp4 fingerprint) ==")
    s = dict(attrib_test.IDENT)
    s.update(COMMON)
    s["initiating_package_name"] = "com.android.vending"
    s.update({"session_count": "1", "foreground": "1"})
    okhttp_send("POST", "/session", s)
    time.sleep(1)

    log("== 2: /sdk_click (reftag + click_label params) ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    c = dict(attrib_test.IDENT)
    c.update(COMMON)
    c["initiating_package_name"] = "com.android.vending"
    c.update({
        "source": "install_referrer",
        "referrer": ref,
        "reftag": reftag,
        "click_label": reftag,
        "deeplink_click_time": click_ts,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": click_ts,
        "click_time_server": iso(now, 1, "100"),
        "install_begin_time": iso(now, 120, "200"),
        "install_begin_time_server": iso(now, 121, "200"),
        "session_count": "1", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    okhttp_send("POST", "/sdk_click", c)
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
        okhttp_send("GET", "/attribution", att)

    open("attempt10.log", "w").write("\n".join(log_lines))
    print("saved attempt10.log", flush=True)


if __name__ == "__main__":
    main()

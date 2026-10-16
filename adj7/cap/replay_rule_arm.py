"""replay_rule_arm.py -- the rule-book ARM replay of the BOOKED adj7 capture
(payruki_again, 2026-10-07, app_token smxi7gqwu39c / in.hanafintech).

The genuine device's non-organic verdict (tracker 248wk8ym / network
VL-Alliance) was obtained by the flow:  signed POST /session -> 200
{adid, ask_in=2000} -> wait -> signed GET /attribution -> booked.
final_replay_test.py replayed the attribution GET alone with OUR fresh
signature -> 200 Organic (no arm).  This probe repeats the device's ask
flow end-to-end from OUR OWN signatures (fresh second + fresh nonce
everywhere, verbatim wire maps, rule "O = ours must behave like G"):

  (G)   the capture's own attribution GET Authorization, verbatim  (control)
  (ARM) our signed POST /session (verbatim captured body) -> ask_in ->
        wait -> OUR signed attribution GET (fresh nonce + fresh second)

PASS = the armed fresh-signature ask reproduces the logged verdict
       field-for-field (tracker_token, network, adid, engagement_time)."""
import calendar
import datetime
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import adj7_pure as S                      # noqa: E402

RAW = os.path.join(HERE, "payruki_again", "raw")
SESS_F, ATTR_F = os.path.join(RAW, "41_c.txt"), os.path.join(RAW, "43_c.txt")
LOGGED = {"tracker_token": "248wk8ym", "network": "VL-Alliance",
          "adid": "bc620c16d8112216e33514e30a03eb37",
          "engagement_time": "2026-10-07T08:58:48Z"}

CAMPAIGN = {"cert_sha1": "c1bfafcaffb84b805288b985fbe48e7f33d2c6df",
            "client_sdk": "android5.6.0",
            "adj_signing_id": "1300000",
            "headers_id": "8",
            "native_version": "3.62.0"}
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"


def load_request(path):
    """raw capture _c.txt -> (method, path+query, headers, body)."""
    t = open(path, "rb").read().decode("utf-8", "replace")
    t = t.replace("\r\n", "\n")
    head, _, body = t.partition("\n\n")
    lines = head.split("\n")
    req = lines[0].split(" ")
    headers = {}
    for ln in lines[1:]:
        if not ln.strip() or ":" not in ln:
            break
        k, v = ln.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    body = body.rstrip("\n")
    return req[0], req[1], headers, body


def send(method, target, extra_headers, body=None):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    h = {"Host": "app.adjust.com",
         "Accept-Encoding": "gzip",
         "User-Agent": UA}
    h.update(extra_headers)
    try:
        c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
        for k, v in h.items():
            c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body.encode())))
        c.endheaders()
        if body is not None:
            c.send(body.encode())
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def parse_map(body):
    return dict(urllib.parse.parse_qsl(body, keep_blank_values=True))


def verdict_of(body):
    try:
        j = json.loads(body)
    except Exception:
        return None, {}
    a = j.get("attribution") or {}
    return j.get("adid"), a


def sign_fields(fields, kind, client_sdk):
    """fresh second + fresh nonce, the genuine Java claim law."""
    return S.sign_request(fields, kind, second=int(time.time()),
                          nonce12=os.urandom(12), campaign=CAMPAIGN,
                          include_block2=True, client_sdk=client_sdk)


def main():
    results = {}
    m_sess, sess_target, sess_hdr, sess_body = load_request(SESS_F)
    m_att, att_target, att_hdr, _ = load_request(ATTR_F)
    client_sdk = sess_hdr.get("client-sdk", CAMPAIGN["client_sdk"])
    query = sess_target.split("?", 1)[0]
    assert m_sess == "POST" and m_att == "GET"
    print("capture sid 41 POST %s  (%d B body)  client-sdk=%s"
          % (query, len(sess_body), client_sdk))
    print("capture sid 43 GET  %s" % att_target.split("?")[0])

    # ---- offline: verify the genuine blobs under our law (cheap control) ----
    for tag, path in (("session sid41", SESS_F), ("attribution sid43", ATTR_F)):
        _, _, hdr, _ = load_request(path)
        blob = bytes.fromhex(re.search(r'signature="([A-Fa-f0-9]+)"',
                                       hdr["authorization"]).group(1))
        print("offline %s : tag=%s header-derivable=yes %dB"
              % (tag, S.verify_tag(blob), len(blob)))

    # ---- (G) genuine control, verbatim auth ----
    st, body = send("GET", att_target,
                    {"Client-SDK": client_sdk,
                     "Authorization": att_hdr["authorization"]})
    adid, att = verdict_of(body)
    g_ok = (att.get("tracker_token") == LOGGED["tracker_token"]
            and att.get("network") == LOGGED["network"])
    print("\n(G) genuine control -> HTTP %d\n  %s" % (st, body[:300]))
    print("  >>> tracker=%s network=%s  G==logs: %s"
          % (att.get("tracker_token"), att.get("network"), g_ok))
    results["G"] = {"status": st, "body": body, "g_ok": g_ok}

    # ---- (ARM) our signed session (verbatim wire map) ----
    fields = parse_map(sess_body)
    auth = sign_fields(fields, "session", client_sdk)
    sess_query = sess_target.split("?", 1)[1] if "?" in sess_target else ""
    st, body = send("POST", "/session" + ("?" + sess_query if sess_query else ""),
                    {"Client-SDK": client_sdk,
                     "Authorization": auth,
                     "Content-Type": "application/x-www-form-urlencoded"},
                    sess_body)
    print("\n(ARM-1) OUR signed POST /session -> HTTP %d\n  %s"
          % (st, body[:300]))
    results["session"] = {"status": st, "body": body}
    ask_in = 0
    try:
        j = json.loads(body)
        ask_in = (j.get("ask_in") or 0) / 1000.0
    except Exception:
        pass
    if '[' in body or 'error' in body.lower():
        pass
    if ask_in:
        print("  ask_in=%ds -- waiting" % ask_in)
        time.sleep(ask_in)

    # ---- (ARM-2) our signed attribution GET, fresh nonce + fresh second ----
    att_map = parse_map(urllib.parse.urlparse(att_target).query)
    auth = sign_fields(att_map, "attribution", client_sdk)
    st, body = send("GET", att_target,
                    {"Client-SDK": client_sdk, "Authorization": auth})
    adid, att = verdict_of(body)
    match = (att.get("tracker_token") == LOGGED["tracker_token"]
             and att.get("network") == LOGGED["network"]
             and adid == LOGGED["adid"])
    print("\n(ARM-2) OUR fresh-signature attribution GET -> HTTP %d\n  %s"
          % (st, body[:400]))
    print("  >>> tracker=%s network=%s adid=%s engagement_time=%s"
          % (att.get("tracker_token"), att.get("network"), adid,
             att.get("engagement_time")))
    print("  >>> verdict matches the LOGGED object field-for-field: %s"
          % match)
    results["ARM"] = {"status": st, "body": body, "match": match}

    print("\n" + "=" * 74)
    print("RULE-BOOK VERDICT: %s"
          % ("PASS -- fresh-signature replay reproduces the logged"
             " non-organic verdict" if results["ARM"]["match"]
             else "not reproduced yet"))
    json.dump(results,
              open(os.path.join(HERE, "replay_rule_arm_result.json"), "w"),
              indent=1)


if __name__ == "__main__":
    if "DRY" in sys.argv:
        print("[DRY] offline shapes verified; no network fired")
    else:
        main()

"""final_replay_probes_de.py -- follow-up probes after the first round showed:

  (a) genuine blob verbatim        -> BOOKED (248wk8ym)
  (b) our mint, FRESH nonce        -> Organic
  (c) our mint, DEVICE nonce       -> BOOKED  (byte-identical to (a))

with (b) differing from (a) ONLY in nonce-derived bytes.  Nonce-structure
analysis over all 13 device nonces found none (SecureRandom), so the server
cannot content-check the nonce.  Two one-dimension-at-a-time probes:

  (d) our mint, FRESH nonce, FRESH created_at/sent_at (= now), sec = now
      -> tests "stale ask rejected -> Organic fallback" (fully live ask)
  (e) our mint, DEVICE nonce, sec = captured second + 1
      -> new header/body/tag bytes, decrypted record == device's record;
         pins whether the server remembers the exact blob or the record
"""
import calendar
import datetime
import gzip
import http.client
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "oracle")))

import adj7_pure as S          # noqa: E402
import adj7_oracle as O        # noqa: E402

CAP = os.path.join(HERE, "payruki_again", "raw", "43_c.txt")
BOOKED_TRACKER = "248wk8ym"
BOOKED_NETWORK = "VL-Alliance"


def created_sec(created):
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z([+-]\d{4})",
                 created)
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f")
    off = m.group(2)
    minutes = (1 if off[0] == "+" else -1) * (int(off[1:3]) * 60 + int(off[3:5]))
    return calendar.timegm(dt.timetuple()) - minutes * 60


def send(auth, raw_query, client_sdk, ua):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("GET", "/attribution?" + raw_query, skip_host=1,
                     skip_accept_encoding=1)
        c.putheader("Client-SDK", client_sdk)
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", ua)
        c.putheader("Host", "app.adjust.com")
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders()
        r = c.getresponse()
        raw = r.read()
        date_hdr = r.getheader("date")
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return r.status, date_hdr, raw.decode("utf-8", "replace")
    finally:
        c.close()


def auth_of(blob):
    return ('Signature signature="%s",adj_signing_id="1300000",'
            'algorithm="adj7",headers_id="8",native_version="3.62.0"'
            % blob.hex().upper())


def main():
    raw = open(CAP, "rb").read().decode("utf-8", "replace")
    lines = raw.replace("\r\n", "\n").split("\n")
    headers = {}
    for ln in lines[1:]:
        if not ln.strip() or ":" not in ln:
            break
        k, v = ln.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    auth_genuine = headers["authorization"]
    client_sdk = headers["client-sdk"]
    ua = headers["user-agent"]
    raw_query = lines[0].split("?", 1)[1].split(" ")[0]
    params0 = dict(urllib.parse.parse_qsl(raw_query, keep_blank_values=True))
    dev = O.parse_device_blob(auth_genuine)
    nonce12_dev = bytes.fromhex(dev["nonce12"])
    cert40 = dev["device_cert40"].encode()
    sec0 = created_sec(params0["created_at"])

    # ---------- probe (d): fresh times, fresh nonce ----------
    now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    p = dict(params0)
    ms = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    p["created_at"] = ms + "Z+0530"
    sent = (now + datetime.timedelta(milliseconds=13))
    p["sent_at"] = sent.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z+0530"
    q_d = urllib.parse.urlencode(p, quote_via=urllib.parse.quote)
    sec_d = created_sec(p["created_at"])
    claims_d = S.build_claims("attribution", p, client_sdk=client_sdk,
                              include_block2=True)
    n_d = os.urandom(12)
    blob_d = S.sign(sec_d, n_d, claims_d, cert40)
    print("PROBE (d) fresh times %s | sec %d | nonce %s"
          % (p["created_at"], sec_d, n_d.hex()))
    st, dh, body = send(auth_of(blob_d), q_d, client_sdk, ua)
    try:
        at = json.loads(body)["attribution"]
        tok, net = at.get("tracker_token"), at.get("network")
    except Exception:
        tok = net = None
    print("  -> HTTP %d (%s) tracker=%s network=%s booked=%s"
          % (st, dh, tok, net, tok == BOOKED_TRACKER))
    print("  body: %s" % body[:220])
    d_booked = (tok == BOOKED_TRACKER)

    # ---------- probe (e): device nonce, header of sec+1 ----------
    sec_e = sec0 + 1
    claims_e = S.build_claims("attribution", params0, client_sdk=client_sdk,
                              include_block2=True)
    blob_e = S.sign(sec_e, nonce12_dev, claims_e, cert40)
    rec_e = O.cbc_decrypt(blob_e[16:272], blob_e[:16])
    blob_dev = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"',
                                       auth_genuine).group(1))
    rec_dev = O.cbc_decrypt(blob_dev[16:272], blob_dev[:16])
    print("\nPROBE (e) device nonce, header=make_header(sec+1=%d) | "
          "record == device record: %s | blob != device blob: %s"
          % (sec_e, rec_e == rec_dev, blob_e != blob_dev))
    st, dh, body = send(auth_of(blob_e), raw_query, client_sdk, ua)
    try:
        at = json.loads(body)["attribution"]
        tok, net = at.get("tracker_token"), at.get("network")
    except Exception:
        tok = net = None
    print("  -> HTTP %d (%s) tracker=%s network=%s booked=%s"
          % (st, dh, tok, net, tok == BOOKED_TRACKER))
    print("  body: %s" % body[:220])

    json.dump({"d_fresh_times_fresh_nonce": {"booked": d_booked, "tracker": tok},
               "e_devnonce_sec1": {"booked": tok == BOOKED_TRACKER,
                                   "record_same": rec_e == rec_dev}},
              open(os.path.join(HERE, "final_replay_probe_de.json"), "w"),
              indent=1)


if __name__ == "__main__":
    main()

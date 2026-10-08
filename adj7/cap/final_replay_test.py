"""final_replay_test.py -- THE acceptance test for the adj7 signer,
built exactly like the proven adj8 replay recipe
(C:\\Users\\Users\\Apps\\Downloads\\com.penti.app\\adj8\\replay_attr_test.py):

  * replay the BOOKED capture's attribution GET (payruki_again_same_wifi.saz
    sid 43, the device's own ask that got tracker 248wk8ym / VL-Alliance)
  * ORIGINAL params (no fresh times), ORIGINAL raw query string byte-for-byte
  * signing second = the capture's created_at second (delta 0)
  * transport = http.client with exactly the 5 headers
    Client-SDK / Authorization / User-Agent / Host / Accept-Encoding

Probes (max ~6 network requests, 3 fired):
  (a) GENUINE-AUTH CONTROL  -- the device's original Authorization verbatim
  (b) OUR MINT, FRESH NONCE (os.urandom(12))  -- the actual test
  (c) OUR MINT, DEVICE NONCE (diagnostic -- if the offline byte-identity
      check passes, (c) is byte-identical to (a) on the wire)

Offline first (no network):
  parse the device blob -> record a/b/c/d/e + nonce12; verify tag, header
  second, H-over-our-claims, and FULL BLOB byte-identity of our
  sign(sec, device_nonce, claims, cert40_ascii) vs the device blob.
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
import adj7_oracle as O        # noqa: E402  (cbc_decrypt, parse_device_blob)

CAP = os.path.join(HERE, "payruki_again", "raw", "43_c.txt")
CAMPAIGN = {
    "cert_sha1": "c1bfafcaffb84b805288b985fbe48e7f33d2c6df",
    "client_sdk": "android5.6.0",
    "adj_signing_id": "1300000",
    "headers_id": "8",
    "native_version": "3.62.0",
}
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
    target = "/attribution?" + raw_query
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("GET", target, skip_host=1, skip_accept_encoding=1)
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


def verdict_of(body):
    try:
        j = json.loads(body)
        a = j.get("attribution", {})
        tok = a.get("tracker_token")
        net = a.get("network")
        return tok, net, j.get("adid")
    except Exception:
        return None, None, None


def main():
    # ---------- load the capture ----------
    raw = open(CAP, "rb").read().decode("utf-8", "replace")
    lines = raw.replace("\r\n", "\n").split("\n")
    reqline = lines[0]
    assert reqline.startswith("GET https://app.adjust.com/attribution?"), reqline
    headers = {}
    for ln in lines[1:]:
        if not ln.strip() or ":" not in ln:
            break
        k, v = ln.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    auth_genuine = headers["authorization"]
    client_sdk = headers["client-sdk"]
    ua = headers["user-agent"]
    raw_query = reqline.split("?", 1)[1].split(" ")[0]

    pairs = urllib.parse.parse_qsl(raw_query, keep_blank_values=True)
    params = dict(pairs)
    rebuilt = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    query_identical = rebuilt == raw_query
    print("capture sid 43  |  %d query params  |  rebuilt==raw query: %s"
          % (len(params), query_identical))
    print("  Client-SDK=%s  UA=%s" % (client_sdk, ua))

    # ---------- offline law check on the device blob ----------
    dev = O.parse_device_blob(auth_genuine)
    blob = bytes.fromhex(re.search(r'signature="([A-Fa-f0-9]+)"',
                                   auth_genuine).group(1))
    print("\nOFFLINE LAW CHECK -- genuine device blob (sid 43)")
    print("  blob %d B  tag_ok=%s" % (len(blob), dev["tag_ok"]))
    print("  record a (nonce lo8 u64le) = %s" % dev["nonce_a"])
    print("  record b (H)               = %s" % dev["device_H"])
    print("  record c (cert40)          = %s" % dev["device_cert40"])
    print("  record d (nonce hi4 hex)   = %s" % dev["device_d8"])
    nonce12_dev = bytes.fromhex(dev["nonce12"])
    cert40_dev = dev["device_cert40"].encode()   # ASCII hex chars (the law)

    sec = created_sec(params["created_at"])
    print("  created_at %s -> signing second %d (delta 0)"
          % (params["created_at"], sec))

    claims = S.build_claims("attribution", params, client_sdk=client_sdk,
                            include_block2=True)
    h_ascii = S.commitment_digest(claims, nonce12_dev, cert40_dev).hex().upper()
    h_hexbytes = S.commitment_digest(claims, nonce12_dev,
                                     bytes.fromhex(dev["device_cert40"])
                                     ).hex().upper()
    print("  claims len %d B (block2)" % len(claims))
    print("  H over our claims (cert40=ASCII) == record b : %s"
          % (h_ascii == dev["device_H"]))
    print("  H over our claims (cert40=hex-bytes) == b     : %s  (must be False)"
          % (h_hexbytes == dev["device_H"]))
    print("  header == make_header(sec)                    : %s"
          % (S.make_header(sec) == blob[:16]))

    # the full byte-identity: our signer + the DEVICE's nonce == device blob
    ours_devnonce = S.sign(sec, nonce12_dev, claims, cert40_dev)
    byte_identical = ours_devnonce == blob
    print("  OUR sign(sec, device_nonce12, claims, cert40_ascii) == device blob : %s"
          % byte_identical)

    # ---------- our mint (fresh nonce) + record diff ----------
    nonce12_fresh = os.urandom(12)
    ours_fresh = S.sign(sec, nonce12_fresh, claims, cert40_dev)
    ok_tag = S.verify_tag(ours_fresh)
    rec_dev = O.cbc_decrypt(blob[16:272], blob[:16])
    rec_fresh = O.cbc_decrypt(ours_fresh[16:272], ours_fresh[:16])
    hdr_same = ours_fresh[:16] == blob[:16]

    def rec_fields(rec):
        t = rec.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
        f = {}
        for key, pat in (("a", r'"a":\s*(\d+)'),
                         ("b", r'"b":\s*"([0-9A-F]{64})"'),
                         ("c", r'"c":\s*"([0-9A-F]{40})"'),
                         ("d", r'"d":\s*"([0-9A-F]{8})"'),
                         ("e", r'"e":\s*"([0-9A-F]{64})"')):
            m = re.search(pat, t)
            f[key] = m.group(1) if m else None
        return t, f

    t_dev, f_dev = rec_fields(rec_dev)
    t_fresh, f_fresh = rec_fields(rec_fresh)
    print("  record e == sha256('') upper               : %s"
          % (f_dev["e"] == S.SHA0_HEX))
    print("\nOFFLINE OUR-MINT (fresh nonce %s)" % nonce12_fresh.hex())
    print("  blob %d B tag_ok=%s header==device-head:%s"
          % (len(ours_fresh), ok_tag, hdr_same))
    print("  record-vs-record (ours-fresh vs device):")
    for k in "abcde":
        print("    %s: ours=%s device=%s same=%s"
              % (k, f_fresh[k], f_dev[k], f_fresh[k] == f_dev[k]))
    print("  expected diff only in a/b/d (nonce-derived); c/e + header identical")

    auth_fresh = ('Signature signature="%s",adj_signing_id="%s",algorithm="adj7",'
                  'headers_id="%s",native_version="%s"'
                  % (ours_fresh.hex().upper(), CAMPAIGN["adj_signing_id"],
                     CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    auth_devnonce = ('Signature signature="%s",adj_signing_id="%s",algorithm="adj7",'
                     'headers_id="%s",native_version="%s"'
                     % (ours_devnonce.hex().upper(), CAMPAIGN["adj_signing_id"],
                        CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    print("  (c) our-device-nonce auth == genuine auth verbatim : %s"
          % (auth_devnonce == auth_genuine))

    results = []

    def fire(name, auth):
        st, date_hdr, body = send(auth, raw_query, client_sdk, ua)
        tok, net, adid = verdict_of(body)
        booked = (tok == BOOKED_TRACKER and net == BOOKED_NETWORK)
        print("\n%s" % ("-" * 78))
        print("PROBE %s  -> HTTP %d  (server date: %s)" % (name, st, date_hdr))
        print("  body: %s" % body[:300])
        print("  >> tracker=%s network=%s adid=%s" % (tok, net, adid))
        print("  >> %s" % ("BOOKED NON-ORGANIC RETURNED" if booked
                          else "ORGANIC / not booked"))
        results.append((name, st, tok, net, adid, booked))
        return booked

    # ---------- the three probes, control first ----------
    if "DRY" not in sys.argv:
        fire("(a) GENUINE-AUTH CONTROL (device blob verbatim)", auth_genuine)
        fire("(b) OUR MINT, FRESH NONCE  <-- THE TEST", auth_fresh)
        fire("(c) OUR MINT, DEVICE NONCE (diagnostic)", auth_devnonce)
    else:
        print("\n[DRY RUN -- no network requests fired]")

    print("\n" + "=" * 78)
    print("SUMMARY  (target verdict: tracker %s / network %s)"
          % (BOOKED_TRACKER, BOOKED_NETWORK))
    for name, st, tok, net, adid, booked in results:
        print("  %-46s HTTP %d  tracker=%s network=%s booked=%s"
              % (name, st, tok, net, booked))
    json.dump({"results": [{"name": n, "status": s, "tracker": t,
                            "network": nw, "adid": a, "booked": b}
                           for n, s, t, nw, a, b in results],
               "offline": {"query_identical": query_identical,
                           "byte_identical_device_nonce": byte_identical,
                           "claims_len": len(claims),
                           "h_ascii_match": h_ascii == dev["device_H"],
                           "header_match": S.make_header(sec) == blob[:16],
                           "sec": sec,
                           "nonce12_dev": nonce12_dev.hex(),
                           "fresh_nonce": nonce12_fresh.hex(),
                           "record_device": f_dev,
                           "record_fresh": f_fresh}},
              open(os.path.join(HERE, "final_replay_result.json"), "w"),
              indent=1)


if __name__ == "__main__":
    main()

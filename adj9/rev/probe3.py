r"""probe3.py — the full genuine /attribution corpus, verbatim vs 1-bit flipped.

probe1 showed, for ONE unit: byte-exact genuine blob -> 400 ask_in (throttle);
any change (1 bit anywhere, crafted body, fresh auid) -> 200 Organic.
Question: is that unit special (its record is cooled down), or is it the rule?

The wire dump carries every request's Authorization header, so ALL 12 genuine
/attribution units can be replayed verbatim. Each is then replayed with one body
bit flipped, giving a paired verdict per unit.

Usage: python probe3.py [--flip]
"""
import base64
import http.client
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"
OUT = os.path.join(HERE, "probe3_result.json")


def corpus():
    d = open(DUMP, "rb").read().decode("utf-8", "replace")
    out = []
    for ch in re.split(r"(?=(?:POST|GET) /)", d):
        m = re.match(r"(POST|GET) (\S+) HTTP/1\.1\r\n(.*)", ch, re.DOTALL)
        if not m:
            continue
        method, path, rest = m.groups()
        if not path.startswith("/attribution"):
            continue
        h = {}
        for hm in re.finditer(r"^([\w-]+): (.*)$", rest, re.MULTILINE):
            h[hm.group(1)] = hm.group(2).strip()
        auth = h.get("Authorization", "")
        sm = re.search(r'signature="([^"]+)"', auth)
        if not sm:
            continue
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        out.append({
            "url": "https://app.adjust.com" + path,
            "blob": base64.b64decode(sm.group(1)),
            "auid": q.get("android_uuid", ["?"])[0],
            "gps": q.get("gps_adid", ["?"])[0],
            "ib": q.get("initiated_by", ["?"])[0],
            "created": q.get("created_at", ["?"])[0],
            "ua": h.get("User-Agent", ""),
            "sig8": sm.group(1)[:8],
        })
    return out


def send(url, blob, ua):
    auth = ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())
    pr = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    conn.putrequest("GET", pr.path + "?" + pr.query, skip_host=1,
                    skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", ua)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def short(st, body):
    try:
        o = json.loads(body)
    except Exception:
        return "HTTP %s %s" % (st, body[:60])
    a = o.get("attribution")
    if a:
        return "%s eng=%s inst=%s" % (a.get("tracker_token"),
                                      a.get("engagement_time"),
                                      (a.get("installed_at") or "")[:19])
    return "HTTP %s %s" % (st, json.dumps(o)[:90])


def main():
    do_flip = "--flip" in sys.argv
    items = corpus()
    print("genuine /attribution units in the dump: %d" % len(items), flush=True)
    res = []
    for i, it in enumerate(items):
        st, body = send(it["url"], it["blob"], it["ua"])
        row = dict(it, http=st, verdict=short(st, body), body=body[:400],
                   sig8=it["sig8"], hdr8=it["blob"][:8].hex(),
                   blob_hex=it["blob"].hex())
        row.pop("blob", None)
        print("[%02d] %s %s ib=%-7s created=%s sig=%s hdr=%s -> %s %s"
              % (i, it["auid"][:8], it["gps"][:8], it["ib"],
                 it["created"][:19], it["sig8"], row["hdr8"], st,
                 row["verdict"]), flush=True)
        if do_flip:
            f = bytearray(it["blob"])
            f[16] ^= 0x01
            st2, body2 = send(it["url"], bytes(f), it["ua"])
            row["flip_http"] = st2
            row["flip_verdict"] = short(st2, body2)
            row["flip_body"] = body2[:400]
            print("     flip body[0] -> %s %s" % (st2, row["flip_verdict"]),
                  flush=True)
            time.sleep(2)
        res.append(row)
        time.sleep(2)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()
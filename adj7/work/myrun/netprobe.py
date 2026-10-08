import http.client
import socket
import time

for host, port, path in (
        ("clicks.mobpine.com", 80, "/api/track/v1/click?aff_id=3&offer_id=23483498&sub3=probe"),
        ("app.adjust.com", 443, "/"),
):
    try:
        ip = socket.gethostbyname(host)
    except Exception as ex:
        print(host, "DNS FAIL", repr(ex))
        continue
    cls = http.client.HTTPSConnection if port == 443 else http.client.HTTPConnection
    c = cls(host, port, timeout=15)
    t0 = time.time()
    try:
        c.request("GET", path, headers={"User-Agent": "probe",
                                        "Connection": "close"})
        r = c.getresponse()
        print(host, "->", r.status, "in %.1fs" % (time.time() - t0),
              "ip", ip)
    except Exception as ex:
        print(host, "FAIL", repr(ex), "ip", ip)
    finally:
        c.close()

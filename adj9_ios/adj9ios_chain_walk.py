"""Walk the iOS click chain hop-by-hop (the adj9-android click discipline)."""
import http.client, urllib.parse, uuid, re

CLICK_ID = str(uuid.uuid4())
IDFA = str(uuid.uuid4()).upper()
base = ("https://app.adjust.com/1sd1lk6a?campaign=penti_install&adgroup=vkm_0926_36"
        "&creative=penti_generic&click_id=" + CLICK_ID + "&idfa=" + IDFA)
cb = ("http://ec2-13-126-162-113.ap-south-1.compute.amazonaws.com/api/track/v1/postback"
      "?click_id=" + CLICK_ID + "&p_sub1=adjust&advertising_id=vkmdigital&offer_id=pntvkmmmp")
ev = ("http://ec2-13-126-162-113.ap-south-1.compute.amazonaws.com/api/track/v1/events"
      "?click_id=" + CLICK_ID + "&goal=bfi71x&p_sub1=adjust&advertising_id=vkmdigital"
      "&offer_id=pntvkmmmp")
url = base + "&install_callback=" + urllib.parse.quote(cb, safe="") \
      + "&event_callback_bfi71x=" + urllib.parse.quote(ev, safe="")

print("click_id:", CLICK_ID)
print("idfa     :", IDFA)

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1")

for hop in range(8):
    parts = urllib.parse.urlsplit(url)
    c = http.client.HTTPSConnection(parts.hostname, 443, timeout=25)
    path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
    c.request("GET", path, headers={"User-Agent": BROWSER_UA,
                                    "Accept-Encoding": "identity",
                                    "Connection": "close"})
    r = c.getresponse()
    body = r.read()
    loc = r.getheader("Location") or ""
    setc = r.getheader("Set-Cookie") or ""
    print("")
    print("hop%d: %s %s" % (hop, r.status, parts.hostname + parts.path[:70]))
    if loc:
        print("  Location:", loc[:200])
    if setc:
        print("  Set-Cookie:", setc[:200])
    blob = loc + body[:5000].decode("latin-1")
    m = re.search(r"adjust_reftag(?:%3D|=)([A-Za-z0-9]+)", blob)
    if m:
        print("  *** ADJUST_REFTAG:", m.group(1))
    if not loc:
        mm = re.search(r"window\.location\.href = '([^']+)'", body.decode("latin-1"))
        print("  page redirect:", mm.group(1)[:180] if mm else "(none)")
        break
    url = urllib.parse.urljoin(url, loc)

print("")
print("FINAL url:", url[:250])
open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\_last_click.txt", "w").write(
    "click_id=%s\nidfa=%s\nfinal=%s\n" % (CLICK_ID, IDFA, url))
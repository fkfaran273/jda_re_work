# Byte-exact replay attempt: feed the exact captured request params + signing
# second into the emu and compare the full 304-B blob with the capture.
import json, sys, os, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu

CAPS = {"payruki": r"..\cap\payruki_signed.json",
        "hunch": r"..\cap\hunch_signed.json"}
CLIENT_SDK = {"payruki": "android5.6.0", "hunch": "flutter5.5.0@android5.5.0"}

def sent_second(entry):
    import re, datetime
    if entry["method"] == "POST":
        m = re.search(r"sent_at=([^&]+)", entry.get("body", ""))
    else:
        m = re.search(r"sent_at=([^&]+)", entry["url"])
    s = urllib.parse.unquote(m.group(1))
    # 2026-10-07T13:05:52.420Z+0530  (Z literal + numeric zone)
    s = s.replace("Z+", "+")
    dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")
    return int(dt.timestamp()), dt

def params_of(entry):
    if entry["method"] == "POST":
        pairs = urllib.parse.parse_qsl(entry.get("body", ""), keep_blank_values=True)
    else:
        q = entry["url"].split("?", 1)[1]
        pairs = urllib.parse.parse_qsl(q, keep_blank_values=True)
    return dict(pairs)

def kind_of(url):
    ep = url.split("?")[0].rsplit("/", 1)[-1]
    return {"session": "session", "sdk_click": "click", "attribution": "attribution",
            "event": "event", "info": "info", "third_party_sharing": "third_party_sharing"
            }.get(ep, ep)

which = sys.argv[1] if len(sys.argv) > 1 else "payruki"
rows = [r for r in json.load(open(CAPS[which])) if "blob" in r]
sids = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else None
for r in rows:
    if sids and r["sid"] not in sids:
        continue
    sec0, dt = sent_second(r)
    params = params_of(r)
    params["activity_kind"] = kind_of(r["url"])
    params["client_sdk"] = CLIENT_SDK[which]
    want = bytes.fromhex(r["blob"])
    for delta in (0, -1, 1):
        e = Emu()
        got = e.run(payload=bytes(32), mapobj=params, second=sec0 + delta)
        if got is None:
            print("sid %d: mint failed" % r["sid"])
            break
        if got == want:
            print("sid %d sec=%d(%+d): BYTE-EXACT MATCH  <<<" % (r["sid"], sec0, delta))
            break
        same_head = got[:16] == want[:16]
        diff = next((i for i in range(304) if got[i] != want[i]), None)
        print("sid %d sec=%d(%+d): head_ok=%s first_diff=%s" %
              (r["sid"], sec0, delta, same_head, diff))
        if same_head:
            break

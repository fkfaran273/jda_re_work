"""Verbatim replay of the captured iadsdk attribution/v3 request."""
import http.client, json

HOST = "ca.iadsdk.apple.com"
PATH = "/adserver/attribution/v3"

BODY = ('{"callEventType" : 0, "bundleId" : "com.penti.PentiApp", '
        '"attribution" : false, "readOnly" : false, '
        '"adamId" : "1510355381", '
        '"attributionKey" : "CBdNbt5lrMjV54+CGb9HItWX6Kuc65HsWvZljNMkN4Q="}')

SIGNATURE2 = ("hRSx2pd3AAAABAABEwF5diEal3cAAAAEAAAABPk9eTBQ2wAAABCe2k9AFTjcKnT0xZ2o0TDG94WR"
              "AVDbAAAAIL7Vavk0nSPUi6eY3VI2HZznbhabZWIoDqmonPCYKhF7/Sghx1DbAAACwCejFRhI3YGM"
              "Y3M4iJFGGKNBB1AJIJkP88RFobNrfR/0vx9NySu9UGquSCaw7EBN+EYtq8NKV5NOCbdorWLayDt"
              "iP1pkEWqxfQ6Mc4dBdjvAPlG+bgDLrT9ppQW/Ontxvzp0uB5cIcO1svrb+zIDsMopz4Vo6qu5PFR"
              "KLAqUCtNVO08gtWR0o6NdsA+TLpb53MIKaV8SjpuHjdhuBpI2ynrcNiHq+hFeynb+OWaXnZI3X2"
              "LEpqU6qrnES5x6Y2qd1fIJVpvZ0rW8XGGqTpRq/nYAqtnsJFB2ialXHXyFP4ur26S898S/6azaS"
              "y3DuTyDOd8jx0SJ7buHET551x4Oq3w6TWfg9MbFC93KvT0BBQfT4wn2ZkbWr2XJhPuAYnRrx6yI"
              "BGsUVGNh3Pn5iOCgCEE3RC+8WnWnz1uFNc1E+UkA4kf5rdL+soQZqc4kgGQoqrsDuNb69ZQ5dpy"
              "TB1whEXw0D7SVWIGcvrqGaca6VCEvIZ7W1Zmy4VY3DSFhhN/lu6YLit5np6cHFac4PdPO6fKEAN"
              "Q8XgGcBBzQh3F1LasaYO+N19vc54canDiiU3T2nTZFJ8L3rAiFcC91FOgbuXa5NyeOdnekNA7DD"
              "38fwXD9sVdAMuTnIg/ftAh5a/zoLWPC1lIPnaWBwSX2RgSYGQ3GECUwXt5e+S6GDtXRet6HRxId"
              "MlIOgAw+UyfxQNtJm8f5DLsMxvX/cR3MAzXSrXTPWqovcSl02eDj1gOUj8C1p4RXgG6W8qRia2i"
              "h5D4mCRg8oUDdHe2sDuS2304gV3z2NR12YXhpsNsv/xjY9qDht9saHonUjkgCcR+e6gJC5uxb4U"
              "cEVKQQKd1dkCEkQ+MDi8p8RxXzpO6bDZaUz9tHzFCnFCxA56OgyO0zyj0R5HYas/Fo8252iSMrb"
              "nArnIkXlzlnC7lEykXHr6ke2dD3XCQaslDbAAAAIK7717XOstaobCqbMFrV+SDkK6+f9rWmMTRN"
              "7PI/jDGIAAAAAFDbAAAAAgAA")

HEADERS = {
    "Host": HOST,
    "Content-Type": "application/json",
    "storeFront": "143480-2,29",
    "osBuild": "",
    "timestamp": "2026-10-05T06:16:48Z",
    "osPlatform": "iOS",
    "bundleId": "com.apple.ap.promotedcontent",
    "X-Apple-ActionSignature2": SIGNATURE2,
    "osVersion": "",
    "User-Agent": "promotedcontentd/1.1 CFNetwork/3860.600.12 Darwin/25.5.0",
    "Accept": "*/*",
    "Connection": "close",
}

c = http.client.HTTPSConnection(HOST, 443, timeout=30)
c.request("POST", PATH, body=BODY, headers=HEADERS)
r = c.getresponse()
resp = r.read()
print("status:", r.status)
print("headers:", dict(list(r.getheaders())[:8]))
print("body:", resp[:600])
try:
    j = json.loads(resp)
    if "attributionKey" in j:
        print("\n*** ATTRIBUTIONKEY RETURNED:", j["attributionKey"])
except Exception:
    pass
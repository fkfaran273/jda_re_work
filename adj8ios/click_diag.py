"""Why is appsatiate refusing the click?  Probe the endpoint directly."""
import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from curl_cffi import requests as cr

BASE = "http://clicks.appsatiate.com/api/track/v1/click"
S = cr.Session(impersonate="safari17_0")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
ip = (S.get("https://api.ipify.org", timeout=15).text or "").strip()
print("our egress IP:", ip)
print()

TESTS = [
    ("bare", {"aff_id": "2", "offer_id": "312066"}),
    ("+ua", {"aff_id": "2", "offer_id": "312066", "ua": UA}),
    ("+ip", {"aff_id": "2", "offer_id": "312066", "ip_address": ip}),
    ("+ua+ip", {"aff_id": "2", "offer_id": "312066", "ua": UA, "ip_address": ip}),
    ("+sub_id", {"aff_id": "2", "offer_id": "312066", "sub_id": "manual1"}),
    ("+os/device", {"aff_id": "2", "offer_id": "312066", "ua": UA,
                    "ip_address": ip, "os": "ios", "device_id": "abc",
                    "os_version": "16.7", "app_version": "3.8.0"}),
    ("other offer", {"aff_id": "2", "offer_id": "312065"}),
    ("other aff", {"aff_id": "1", "offer_id": "312066"}),
]
for name, q in TESTS:
    r = S.get(BASE, params=q, headers={"User-Agent": UA}, timeout=30,
              allow_redirects=False)
    loc = (r.headers.get("location") or r.headers.get("Location") or "")
    print("%-14s %s  %s" % (name, r.status_code,
                            ("-> " + loc[:90]) if loc else r.text[:70]))

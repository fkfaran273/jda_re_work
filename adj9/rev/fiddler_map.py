# fiddler_map.py — is the Fiddler POST form (the request data) the content of the
# signed map?  Decode the captured moto canonicals and diff field-for-field
# against the OnePlus Fiddler form body.
import json, re, urllib.parse

# ---- Fiddler form (OnePlus DN2101, /session) ----
FORM = ("store_name_from_system=com.android.vending&gps_adid_attempt=1&api_level=30&"
"hardware_name=DN2101_11_A.20&app_version=3.12.1&app_token=jut9tib0eeps&"
"installed_at=2026-09-08T14%3A00%3A02.774Z%2B0530&created_at=2026-09-08T14%3A05%3A22.928Z%2B0530&"
"wait_total=0.0&device_type=phone&language=tr&gps_adid=1a89cb29-3590-418c-ae2b-122bbd93e38f&"
"foreground=1&connectivity_type=1&mcc=405&device_manufacturer=OnePlus&display_width=1080&"
"device_name=DN2101&needs_response_details=1&os_build=RP1A.200720.011&"
"updated_at=2026-09-08T14%3A00%3A02.774Z%2B0530&cpu_type=arm64-v8a&retry_count=0&"
"screen_size=normal&screen_format=long&last_error=0&gps_adid_src=service&mnc=872&wait_time=0.0&"
"os_version=11&first_error=0&android_uuid=117d0470-c64e-4530-af62-48049861d40a&"
"sent_at=2026-09-08T14%3A05%3A22.942Z%2B0530&offline_mode_enabled=0&environment=production&"
"screen_density=high&attribution_deeplink=1&session_count=1&display_height=2293&"
"package_name=com.penti.app&initiating_package_name=com.android.vending&os_name=android&"
"ui_mode=1&enqueue_size=0&tracking_enabled=1")
fiddler = {}
for kv in FORM.replace("\n", "").split("&"):
    if not kv: continue
    k, v = kv.split("=", 1)
    fiddler[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
print("Fiddler form fields: %d, raw urlencoded len=%d" % (len(fiddler), len(FORM)))

# ---- moto canonicals (captured sign_input map_toString) ----
recs = json.load(open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/pairset.json"))
canons = []
for r in recs:
    h = r.get("canonical_hex")
    if not h: continue
    txt = bytes.fromhex(h).decode("utf-8", "replace")
    m = re.search(r"map_toString=\{(.*)\}\s*\n", txt + "\n", re.S)
    if m:
        inner = m.group(1)
        ent = {}
        order = []
        for part in re.split(r", (?=[^=]+=)", inner):
            if "=" in part:
                k, v = part.split("=", 1)
                ent[k] = v; order.append(k)
        canons.append({"ts": r["ts_in"], "order": order, "ent": ent, "raw": "{%s}" % inner})
print("captured canonicals:", len(canons))
for c in canons:
    print("  ts=%d entries=%d  canonical_len=%d" % (c["ts"], len(c["ent"]), len(c["raw"].encode())))

# pick a /session canonical (has session_count / created_at etc.)
sess = None
for c in canons:
    if "session_count" in c["ent"]:
        sess = c; break
if sess is None:
    sess = canons[0]
print("\nusing canonical ts=%d (%d entries):" % (sess["ts"], len(sess["ent"])))
print("  " + sess["raw"][:400] + "...")

# ---- field-for-field diff ----
mk, fk = set(sess["ent"]), set(fiddler)
print("\n=== map fields == Fiddler form fields (same names) ===")
common = sorted(mk & fk)
print("common: %d" % len(common))
for k in common:
    a, b = sess["ent"][k], fiddler[k]
    same = "SAME" if a == b else "device-specific"
    print("  %-28s moto=%-45s oneplus=%-45s %s" % (k, a[:44], b[:44], same))
print("\nmap-only (signed but NOT in form): %s" % sorted(mk - fk))
for k in sorted(mk - fk):
    print("  %-28s = %s" % (k, sess["ent"][k][:80]))
print("\nform-only (in form but NOT signed): %s" % sorted(fk - mk))
for k in sorted(fk - mk):
    print("  %-28s = %s" % (k, fiddler[k][:80]))

# order check: is the map order the form order?
print("\nmap insertion order (moto):")
print(" ", ", ".join(sess["order"]))
print("\nform order (OnePlus):")
print(" ", ", ".join(list(urllib.parse.parse_qsl(FORM.replace(chr(10), "")))[i][0] for i in range(len(fiddler))))

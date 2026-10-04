import json, uuid, ast

# Build py_tmrv from py_struct_test template
t = open("py_struct_test.py", encoding="utf-8").read()

gaid = "b386932d-7378-445a-8cb8-89addf81b1db"
auid = str(uuid.uuid4())

# identity
t = t.replace("gps = str(uuid.uuid4())", "gps = '" + gaid + "'")
t = t.replace("auid = str(uuid.uuid4())", "auid = '" + auid + "'")
t = t.replace("cline_struct1", "cline_tmrv1")
t = t.replace("py_struct_result.json", "py_tmrv_result.json")

# device data
for old, new in [
    ("moto g42", "TMRV06P5G"),
    ("motorola", "Wingtech"),
    ('"api_level": "31"', '"api_level": "34"'),
    ('"os_version": "12"', '"os_version": "14"'),
    ('"hardware_name": "S2SE32.28-28-4"', '"hardware_name": "MT6833"'),
    ('"os_build": "S2SE32.28-28-4"', '"os_build": "UP1A.231005.007"'),
    ('"display_width": "1080"', '"display_width": "720"'),
    ('"display_height": "2237"', '"display_height": "1545"'),
    ('"screen_density": "high"', '"screen_density": "xhdpi"'),
    ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)",
     "Mozilla/5.0 (Linux; Android 14; TMRV06P5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.8010.36 Mobile Safari/537.36"),
]:
    t = t.replace(old, new)

# add law keys to session_map
old_trk = '"tracking_enabled": "1",'
new_trk = ('"tracking_enabled": "1", "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI", '
           '"adj_signing_id": "1500000", "headers_id": "10", '
           '"native_version": "5.0.0", "algorithm": "adj9", '
           '"client_sdk": "android5.7.0", "initiating_package_name": "com.android.vending", '
           '"store_name_from_system": "com.android.vending",')
t = t.replace(old_trk, new_trk, 1)
old_ib = '"activity_kind": "session"'
new_ib = '"activity_kind": "session", "initiated_by": "sdk"'
t = t.replace(old_ib, new_ib, 1)

open("py_tmrv.py", "w", encoding="utf-8").write(t)
ast.parse(t)
print("written + syntax OK, len=%d" % len(t))

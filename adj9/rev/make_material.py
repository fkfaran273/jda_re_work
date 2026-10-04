"""make_material.py — BUILD-TIME MERGER (run once): consolidates
fin_descs.json (VM slots) + golden_saz.json (wire templates) +
triples (H/blob reference) into adj9_material.json.

Everything the forge needs now lives in ONE file. Field offsets in the
claims blob are LOCATED, not hardcoded. coupled_fields is the contract:
a profile value listed there is swapped into the claims blob (signature)
AND substituted into wire params (HTTP) — equal-length enforced, so
signature/claims can never drift (the year-16026 bug class).
"""
import datetime, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
T = json.load(open(os.path.join(HERE, "..", "device", "triples_tail7.json")))

by = {d["build_idx"]: d for d in D["descs"]}
b = bytes.fromhex(by[10]["data_hex"])

# locate swappable fields in the raw-concat claims blob by regex
TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+0200"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
PATTERNS = {
    "adj_verification": r"KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "android_uuid": UUID,
    "api_level": None,   # positional: right after android_uuid
    "app_token": r"jut9tib0eeps",
    "app_version": r"3\.\d{2}\.\d",
    "created_at": TS,
    "device_name": r"moto g42",
    "device_type": r"phone",
    "environment": r"production",
    "gps_adid": UUID,
    "installed_at": TS,
    "updated_at": TS,
    "os_version": r"(?<=android)12(?=com)",
}
fields = {}
s = b.decode("latin1")
uuids = [m.span() for m in re.finditer(UUID, s)]
fields["android_uuid"] = list(uuids[0]) + [s[uuids[0][0]:uuids[0][1]]]
fields["gps_adid"] = list(uuids[1]) + [s[uuids[1][0]:uuids[1][1]]]
for k, p in PATTERNS.items():
    if k in ("android_uuid", "gps_adid") or p is None:
        continue
    m = re.search(p, s)
    if not m:
        print("!! pattern miss:", k)
        continue
    fields[k] = [m.start(), m.end(), m.group()]
# TS appears 2x: created, installed, updated (3x actually)
ts = [m.span() for m in re.finditer(TS, s)]
fields["created_at"], fields["installed_at"], fields["updated_at"] = \
    [list(x) + [s[x[0]:x[1]]] for x in ts]
fields["api_level"] = [fields["android_uuid"][1],
                       fields["android_uuid"][1] + 2,
                       s[fields["android_uuid"][1]:fields["android_uuid"][1]+2]]

material = {
    "source_files": ["fin_descs.json", "golden_saz.json", "device/triples_tail7.json"],
    "built": datetime.datetime.utcnow().isoformat() + "Z",
    "va_order": D["va_order"],
    "slots": {str(k): {"len_dw": v["len_dw"], "data_hex": v["data_hex"]}
              for k, v in by.items() if k not in (0, 4, 10)},
    "claims_base_hex": by[10]["data_hex"],
    "claims_fields": fields,
    "H_policy": "random 32B per call (HRAND: exits clean iff #0 zeroed - full_chain)",
    "core0_policy": "zeros(144B) + 1 random dword at 140:144",
    "captured_H": {"sess_H": T["sess_H"], "click_H": T["click_H"]},
    "wire_templates": {"session": G["s1"]["params"],
                       "sdk_click": G["s2"]["params"],
                       "sdk_info": G["s3"]["params"]},
    "coupled_fields": ["gps_adid", "android_uuid", "app_token", "app_version",
                       "api_level", "created_at", "device_name", "device_type",
                       "environment", "installed_at", "updated_at",
                       "os_version", "language", "mcc", "mnc"],
    "hard_rules": [
        "claims swaps are equal-length ONLY (raw-concat blob)",
        "never swap 'com.android.vending12' (eats updated_at leading 2)",
        "both installed_at AND updated_at must be refreshed",
        "wire created_at == second-1 of header seed (law: header=created+1s)",
    ],
}
out = os.path.join(HERE, "adj9_material.json")
json.dump(material, open(out, "w"), indent=1)
print("wrote", out, os.path.getsize(out), "bytes")
for k, v in fields.items():
    print("  %-16s %2d..%2d %r" % (k, v[0], v[1], v[2]))

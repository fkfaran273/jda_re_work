"""For sid 45 (event), test whether the genuine H matches the signed-map =
wire params + {activity_kind, client_sdk, endpoint}."""
import json, re, sys, urllib.parse

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7\cap')
import adj7_pure as sg
from decrypt_rec import cbc_decrypt

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
e = next(x for x in D if str(x["sid"]) == "45")
auth = None
for k, v in e["request_headers"]:
    if k.lower() == "authorization":
        auth = v
blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))
rec = cbc_decrypt(blob[16:272], blob[:16]).rstrip(b"\x10").rstrip(b"\x00")
a = re.search(rb'"a":\s+(\d+)', rec).group(1).decode()
H = re.search(rb'"b": "([0-9A-F]+)"', rec).group(1).decode()
c = re.search(rb'"c": "([^"]+)"', rec).group(1)
d8 = re.search(rb'"d": "([0-9A-F]+)"', rec).group(1).decode()
nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(d8)
fields = e["body"] if isinstance(e["body"], dict) else json.loads(e["body"])

def claims_for(m):
    split = sg.CLAIM_POOL.index("session_count")
    profile, tail, block2k = sg.CLAIM_POOL[:split], sg.CLAIM_POOL[split:-2], sg.CLAIM_POOL[-2:]
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(sg.ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2k if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")

acts = ["event", "session", "click", "sdk_click", "attribution"]
for act in acts:
    for cs in ["android5.6.0", ""]:
        for ep in [None, "https://app.adjust.com"]:
            m = dict(fields)
            if act: m["activity_kind"] = act
            if cs: m["client_sdk"] = cs
            if ep: m["endpoint"] = ep
            Hx = sg.commitment_digest(claims_for(m), nonce12, c).hex().upper()
            if Hx == H:
                print("MATCH act=%r cs=%r ep=%r" % (act, cs, ep))

# also try pure wire params (no act/cs) with endpoint:
for ep in (None, "https://app.adjust.com"):
    m = dict(fields)
    if ep: m["endpoint"] = ep
    Hx = sg.commitment_digest(claims_for(m), nonce12, c).hex().upper()
    if Hx == H:
        print("MATCH (base) ep=%r" % ep)
print("done")

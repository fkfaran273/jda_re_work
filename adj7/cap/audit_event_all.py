"""event h exhaustive search: every (activity_kind, client_sdk, endpoint, block2)
variant of every wire/pool order trick may produce the sid45 record H.
"""
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

acts = ["event", "activity", "custom_event", "event_1256973", 
        "event_1256974", "event:custom", "ed", "ev", "track", "pause",
        "access_data", "deep_link", "spend", "analytics", "advertising_id",
        "custom_activity", "install", "attributed", "open", "launch",
        "insured", "signup", "register", "add_cart", "purchase", ""]
css = ["android5.6.0", ""]
eps = [None, "https://app.adjust.com", ""]
found = []
for act in acts:
    for cs in css:
        for ep in eps:
            m = dict(fields)
            if act or cs:
                if act: m["activity_kind"] = act
                if cs: m["client_sdk"] = cs
            if ep is not None and ep != "":
                m["endpoint"] = ep
            m["__test_act__"] = act
            # build claims: profile + id + tail + activity_kind / client_sdk
            split = sg.CLAIM_POOL.index("session_count")
            profile, tail, block2k = (sg.CLAIM_POOL[:split],
                                      sg.CLAIM_POOL[split:-2],
                                      sg.CLAIM_POOL[-2:])
            parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
            parts.append(sg.ADJ_SIGNING_ID)
            parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
            parts += [str(m[k]) for k in block2k if m.get(k) not in (None, "")]
            for k in set(parts) if False else []:
                pass
            claims = "".join(parts).encode("latin1")
            prefix = c
            msg = prefix + nonce12 + sg.SHA0_HEX.encode() + claims
            Hx = sg.sha256_iv0(msg).hex().upper()
            if Hx == H:
                print("MATCH act=%r cs=%r" % (act, cs))
                found.append((act, cs))
if not found:
    print("no match with (wire set !! + spread act/cs/ep)")

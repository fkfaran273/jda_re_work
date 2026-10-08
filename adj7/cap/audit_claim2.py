import json, re, sys, urllib.parse, itertools

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7\cap')
import adj7_pure as sg
from decrypt_rec import cbc_decrypt

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
kinds = ["sdk_click", "click", "install", "event", "session", "attribution", "tps", "sdk_session", ""]
csvals = ["android5.6.0", "android@5.6.0", "android-5.6.0", "Android5.6.0", ""]

for sid in ("42", "43", "44", "45"):
    e = next(x for x in D if str(x["sid"]) == sid)
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
    if e["method"] == "GET":
        fields = dict(urllib.parse.parse_qsl(e["url"].split("?", 1)[1], keep_blank_values=True))
    else:
        fields = e["body"] if isinstance(e["body"], dict) else json.loads(e["body"])
    hits = []
    for act, cs in itertools.product(kinds, csvals):
        m = dict(fields)
        if act:
            m["activity_kind"] = act
        if cs:
            m["client_sdk"] = cs
        claims = sg.build_claims("x", m, include_block2=False) if False else None
        # build claims manually in pool order
        split = sg.CLAIM_POOL.index("session_count")
        profile, tail, block2k = sg.CLAIM_POOL[:split], sg.CLAIM_POOL[split:-2], sg.CLAIM_POOL[-2:]
        parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
        parts.append(sg.ADJ_SIGNING_ID)
        parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
        parts += [str(m[k]) for k in block2k if m.get(k) not in (None, "")]
        claims = "".join(parts).encode("latin1")
        Hx = sg.commitment_digest(claims, nonce12, c).hex().upper()
        if Hx == H:
            hits.append((act, cs))
    print("sid", sid, "matches:", hits)

"""extract.py -- carve the niceone adj8-iOS records from the raw chls.

For each of the 18 `Signature signature="..."` blobs: the wire body (stored
just before the header map, 4-B BE length prefix), the endpoint path (stored
after the header map), and the paired response.  Output: niceone_records.json
"""
import re, json, base64
from urllib.parse import unquote, parse_qsl

RAW = r"C:\Users\Apps\Downloads\niceoneiosauto_6may_lvl2_ios11.chls"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"

txt = open(RAW, "rb").read().decode("latin-1")

sig_m = list(re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', txt))
print("sigs:", len(sig_m))

# body anchors: every stored request body contains bundle_id= (POST bodies)
# GET requests carry params in the URL path?check.
bodies = []
for m in re.finditer(r'bundle_id=([\w.%\-]+)', txt):
    s = m.start()
    if s >= 4:
        n = int.from_bytes(txt[s - 4:s].encode("latin-1"), "big")
        ok = s + n < len(txt) and txt[s + n] in "\x70\x71\x72\x73\x74\x75\x76\x77\x78"
        if ok:
            bodies.append((s, n, txt[s:s + n]))
print("carved bodies:", len(bodies))

ENDPOINTS = ("/session", "/sdk_click", "/attribution", "/event", "/sdk_info",
             "/gdpr_forget_device", "/third_party_sharing")

recs = []
for i, sm in enumerate(sig_m):
    sig = sm.group(1)
    blob = base64.b64decode(sig)
    # nearest carved body before the signature
    prev = [b for b in bodies if b[0] < sm.start()]
    body = prev[-1] if prev else None
    # endpoint: search forward for the first /endpoint string
    fwd = txt[sm.end():sm.end() + 4000]
    path = next((e for e in ENDPOINTS if e in fwd), None)
    # method: "POST"/"GET" strings near the path
    recs.append({
        "i": i,
        "blob_hex": blob.hex(),
        "body_start": body[0] if body else None,
        "body_len": body[2] if body else None,
        "sig_pos": sm.start(),
        "path": path,
    })
    print(f"sig{i:2d} pos={sm.start():8d} blob={len(blob)}B path={path} "
          f"body@{body[0] if body else -1} d={sm.start() - (body[0] if body else 0)}")

# dedupe: same (blob, body) pair appears once per stored copy of the request?
seen, uniq = set(), []
for r in recs:
    key = (r["blob_hex"], r["body_start"])
    if key in seen:
        continue
    seen.add(key)
    uniq.append(r)
print("\nunique (blob,body) pairs:", len(uniq))

# parse params
for r in uniq:
    body = r.pop("body_len")
    start = r.pop("body_start")
    raw_body = txt[start:start + body] if start is not None else None
    if raw_body:
        pairs = parse_qsl(raw_body, keep_blank_values=True)
        params, order = {}, []
        for k, v in pairs:
            params[k] = v
            order.append(k)
        r["order"] = order
        r["params"] = params
        r["sent_at"] = params.get("sent_at")
        r["created_at"] = params.get("created_at")
        r["source"] = params.get("source")
        r["initiated_by"] = params.get("initiated_by")
        r["activity_kind"] = params.get("activity_kind")
        r["n_params"] = len(order)
        r["raw_body"] = raw_body

json.dump(uniq, open(OUT, "w"), indent=1)
print("saved", OUT, len(uniq), "records")
for r in uniq:
    print(f"  rec{r['i']:2d} path={r.get('path')} n={r.get('n_params')} "
          f"sent_at={r.get('sent_at')} act={r.get('activity_kind')} "
          f"src={r.get('source')} init={r.get('initiated_by')}")

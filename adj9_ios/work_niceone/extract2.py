"""extract2.py -- robust carve of niceone adj8-iOS records from the raw chls.

Body starts: any position p where BE32(txt[p-4:p]) == n, txt[p:p+n] is a
query-string ending exactly on a Java-serialization marker, and the body
contains the niceone app_token.  GET params live in the path string stored
right after the request's header map.
"""
import re, json, base64
from urllib.parse import unquote

RAW = r"C:\Users\Apps\Downloads\niceoneiosauto_6may_lvl2_ios11.chls"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"
txt = open(RAW, "rb").read().decode("latin-1")

MARKERS = set("\x70\x71\x72\x73\x74\x75\x76\x77\x78")

# 1) all valid body starts
starts = []
for m in re.finditer(r"[A-Za-z_][A-Za-z_0-9]{2,39}=", txt):
    p = m.start()
    if p < 4:
        continue
    n = int.from_bytes(txt[p - 4:p].encode("latin-1"), "big")
    if not (50 < n < 100000):
        continue
    if p + n >= len(txt) or txt[p + n] not in MARKERS:
        continue
    body = txt[p:p + n]
    if "&" not in body or "app_token=1ri26ekrhwtc" not in body:
        continue
    # exclude url-embedded copies (GET queries): bodies have no leading '/'
    starts.append((p, n, body))
print("valid body starts:", len(starts))

# dedupe overlapping/identical bodies by content
seen, bodies = set(), []
for p, n, b in starts:
    if b in seen:
        continue
    seen.add(b)
    bodies.append((p, n, b))
print("unique bodies:", len(bodies))
for p, n, b in bodies:
    print("  @%d len=%d starts=%s" % (p, n, b[:60]))

# 2) signatures with position
sig_m = list(re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', txt))

# 3) endpoints: first path string AFTER each signature (nearest t\x00<len>/<ep>)
PATH_RE = re.compile(r"t\x00([\x01-\xff])/([a-z_]+)")
def path_after(pos):
    best = None
    m = PATH_RE.search(txt, pos, pos + 6000)
    if m:
        best = "/" + m.group(2)
    return best

recs = []
for i, sm in enumerate(sig_m):
    blob = base64.b64decode(sm.group(1))
    # nearest body BEFORE the signature (POST body) and its distance
    prev = [b for b in bodies if b[0] < sm.start()]
    body = prev[-1] if prev else None
    recs.append({"i": i, "blob_hex": blob.hex(), "sig_pos": sm.start(),
                 "body_pos": body[0], "body_len": body[1],
                 "gap": sm.start() - body[0] if body else None,
                 "path_after": path_after(sm.end())})

# parse params of each body; also parse GET queries from path_after when the
# record has no nearby body (GET)
qsm = re.compile(r"\?([A-Za-z_0-9%.\-=]+)")
for r in recs:
    p = r["body_pos"]
    if p is not None:
        body = txt[p:p + r["body_len"]]
        params, order = {}, []
        for pair in body.split("&"):
            k, _, v = pair.partition("=")
            if k not in params:
                params[k] = unquote(v)
                order.append(k)
        r["params"], r["order"] = params, order
        r["sent_at"] = params.get("sent_at")
        r["kind_hint"] = params.get("activity_kind") or params.get("source") \
            or params.get("initiated_by")

json.dump(recs, open(OUT, "w"), indent=1)
print("\nsaved", OUT)
for r in recs:
    pr = r.get("params", {})
    print(f"rec{r['i']:2d} gap={r['gap']} path_after={r['path_after']} "
          f"n_params={len(pr)} sent_at={r.get('sent_at')} "
          f"act={pr.get('activity_kind')} src={pr.get('source')} "
          f"init={pr.get('initiated_by')} event={pr.get('event_token')}")

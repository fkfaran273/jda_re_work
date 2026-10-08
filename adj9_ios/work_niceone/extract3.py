"""extract3.py -- final carve of the 18 niceone adj8-iOS records.

Entry layout (from raw inspection):
  [w08 charles-request-ts][body string (u32 BE len prefix)]
  [header map: ... path string ... authorization=sig ...]
  [w08 response ts][response JSON string]

Pairing: sig <-> nearest body END before it (gap < 600).  GET /attribution:
params from the nearest `/attribution?query` string before the sig.
"""
import re, json, base64, datetime
from urllib.parse import unquote

RAW = r"C:\Users\Apps\Downloads\niceoneiosauto_6may_lvl2_ios11.chls"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"
txt = open(RAW, "rb").read().decode("latin-1")
MARKERS = set("\x70\x71\x72\x73\x74\x75\x76\x77\x78")

# bodies
bodies = {}
for m in re.finditer(r"[A-Za-z_][A-Za-z_0-9]{2,39}=", txt):
    p = m.start()
    if p < 4:
        continue
    n = int.from_bytes(txt[p - 4:p].encode("latin-1"), "big")
    if not (50 < n < 100000) or p + n >= len(txt) or txt[p + n] not in MARKERS:
        continue
    b = txt[p:p + n]
    if "&" in b and "app_token=1ri26ekrhwtc" in b and b not in bodies:
        bodies[b] = (p, n)
body_list = sorted((p, n, b) for b, (p, n) in bodies.items())

# GET queries: t <u2be len> "/attribution?...." full string
gets = []
for m in re.finditer(r"t([\x00-\xff])([\x00-\xff])/attribution\?", txt):
    ln = (ord(m.group(1)) << 8) | ord(m.group(2))
    q = txt[m.start() + 3:m.start() + 3 + ln]
    if q.startswith("/attribution?") and len(q) == ln:
        gets.append((m.start(), ln, q))
print("GET attribution queries:", [(p, l) for p, l, _ in gets])

def parse_params(raw):
    params, order = {}, []
    for pair in raw.split("&"):
        k, _, v = pair.partition("=")
        if k not in params:
            params[k] = unquote(v)
            order.append(k)
    return params, order

def ms2iso(ms):
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).isoformat()

sig_m = list(re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', txt))

# charles request-ts: w\x08 <8B BE ms> immediately before each body start
def req_ts_before(pos):
    m = re.compile(r"w\x08([\x00-\xff]{8})").search(txt[max(0, pos - 60):pos])
    if m:
        v = int.from_bytes(m.group(1).encode("latin-1"), "big")
        if 1.6e12 < v < 2e12:
            return v
    return None

# response JSON right after the sig's auth entry
def response_after(end):
    m = re.compile(r'\{"app_token":.{0,600}?\}').search(txt, end, end + 3000)
    return m.group(0) if m else None

records = []
for i, sm in enumerate(sig_m):
    blob = base64.b64decode(sm.group(1))
    end = sm.end()
    # nearest body whose END is < 600 before the sig
    cand = [t for t in body_list if t[0] + t[1] < sm.start() and sm.start() - (t[0] + t[1]) < 600]
    # nearest GET query end before sig, gap < 600
    gcand = [g for g in gets if g[0] + 3 + g[1] < sm.start() and sm.start() - (g[0] + 3 + g[1]) < 600]
    is_get = bool(gcand and (not cand or
                             (gcand[-1][0] + gcand[-1][1]) > (cand[-1][0] + cand[-1][1])))
    if is_get:
        _, ln, q = gcand[-1]
        params, order = parse_params(q.split("?", 1)[1])
        material_pos, material_end = gcand[-1][0], gcand[-1][0] + 3 + ln
        path = "/attribution"
    else:
        p, n, b = cand[-1]
        params, order = parse_params(b)
        material_pos, material_end = p, p + n
        path = None
    resp = response_after(end)
    ts = req_ts_before(material_pos)
    records.append({
        "i": i, "blob_hex": blob.hex(), "second_hint": params.get("sent_at"),
        "charles_ms": ts, "charles_iso": ms2iso(ts) if ts else None,
        "params": params, "order": order, "n_params": len(order),
        "path": path or ("/event" if params.get("event_token") else
                         "/session" if params.get("session_count") and not params.get("event_token") else None),
        "source": params.get("source"), "event_token": params.get("event_token"),
        "response": resp[:250] if resp else None,
        "is_get": is_get, "material_pos": material_pos,
    })

json.dump(records, open(OUT, "w"), indent=1)
print("saved", OUT)
for r in records:
    import json as j
    msg = None
    if r["response"]:
        try:
            msg = j.loads(r["response"].rstrip('"}') + '"}') if False else None
        except Exception:
            pass
    print(f"rec{r['i']:2d} GET={int(r['is_get'])} n={r['n_params']:2d} "
          f"ts={r['charles_iso']} src={r.get('source')} evt={r.get('event_token')} "
          f"sess={'Y' if r['params'].get('session_count') else '-'}")
    print(f"        resp: {r['response'][:150] if r['response'] else None}")

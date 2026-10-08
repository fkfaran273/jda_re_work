"""Extract niceone capture: requests (full queries + signatures), responses, records."""
import re, json, base64, struct, datetime
import urllib.parse as up

raw = open(r"C:\Users\Apps\Downloads\niceoneautoios_ctlogs_8oct_ios11.chls", "rb").read()
txt = raw.decode("latin-1")

sigs = [m for m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]{256})",adj_signing_id="1500000"', txt)]
print("signatures:", len(sigs))

# carve the full query run containing needs_response_details BEFORE each signature
def query_before(pos):
    cands = [m.start() for m in re.finditer(r'needs_response_details=1&', txt[:pos])]
    for c in reversed(cands):
        start = c
        while start > 0 and (txt[start-1].isalnum() or txt[start-1] in "=%&_.-+~:"):
            start -= 1
        end = c
        while end < len(txt) and (txt[end].isalnum() or txt[end] in "=%&_.-+~:"):
            end += 1
        q = txt[start:end]
        if re.search(r'att_status=\d', q) and ("idfv=" in q or "idfa=" in q):
            # the query whose signature follows within ~2500 chars
            if pos - end < 3000:
                return q, start, end
    return None, None, None

recs = []
for i, m in enumerate(sigs):
    q, qs, qe = query_before(m.start())
    sig = m.group(1)
    blob = base64.b64decode(sig)
    hdr = blob[:16]
    # invert the MINSTD header near the capture window (Oct 8, 05:00-13:00 UTC)
    t0 = int(datetime.datetime(2026, 10, 8, 4, 0, tzinfo=datetime.timezone.utc).timestamp())
    sec = None
    P = 2147483647
    def fwd(seed):
        x = seed % P
        if x == 0: x = 1
        d = []
        for _ in range(8):
            x = (16807 * x) % P
            d.append(x)
        return b"".join(struct.pack(">I", (d[2*j] ^ d[2*j+1]) & 0xFFFFFFFF) for j in range(4))
    for off in range(-3600, 3601):
        if fwd(t0 + off) == hdr:
            sec = t0 + off
            break
    import urllib.parse
    params = dict(urllib.parse.parse_qsl(q, keep_blank_values=True)) if q else {}
    recs.append({"i": i+1, "sig": sig, "second": sec, "query": q,
                 "params": params, "header": hdr.hex()})
    path_hint = "?"
    if q:
        kinds = [k for k in ("/session", "/sdk_click", "/event", "/attribution") if k in txt[max(0,qs-2000):qs]]
        path_hint = kinds[-1] if kinds else "?"
    print(f"sig{i+1}: second={sec} | query {len(q) if q else 0} ch, {len(params)} params | path-hint {path_hint}")
    if params:
        interesting = {k: params[k] for k in ("app_token", "bundle_id", "idfa", "idfv",
                                              "att_status", "os_version", "device_name",
                                              "attribution_token") if k in params}
        print("   ", json.dumps(interesting, indent=1)[:400])

# responses: all attribution JSONs
print("\n=== attribution responses ===")
for m in re.finditer(r'\{"app_token":"[^"]+","adid":"[^"]+","attribution":\{[^}]*\}', txt):
    print("  ", m.group(0)[:330])

json.dump(recs, open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\_niceone_reqs.json", "w"), indent=1)
print("\nsaved _niceone_reqs.json")
PYEOF
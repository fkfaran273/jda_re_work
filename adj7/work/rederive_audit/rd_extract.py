"""Fresh-eyes extraction of adj7 device rows from RAW sources only.
Sources:
  1. wire dump  D:\\advance_emu\\ssl_interception\\wire_dumps\\app.adjust.com_dev2srv.bin
     (requests concatenated; body cut EXACTLY at Content-Length)
  2. saz        C:\\Users\\Apps\\Downloads\\payruki_again.saz  (raw/NN_c.txt)
  3. cap raw    cap\\{payrupik_new,hunchdate,burger}\\raw\\NN_c.txt
Output: rows_fresh.json  (deduped by signature hex)
"""
import json, re, os, io, zipfile
from urllib.parse import urlsplit, parse_qs, unquote_plus

WIRE = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"
SAZ  = r"C:\Users\Apps\Downloads\payruki_again.saz"
CAPS = [r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\raw",
        r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\hunchdate\raw",
        r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\burger\raw"]

REQ = re.compile(rb"(?m)^(POST|GET|PUT) (\S+) HTTP/1\.[01]")

def parse_request(raw: bytes, src: str, label: str):
    """raw = one client request (headers CRLF CRLF body). Returns dict or None."""
    hm = raw.find(b"\r\n\r\n")
    if hm < 0:
        return None
    head, rest = raw[:hm], raw[hm + 4:]
    lines = head.decode("latin1").split("\r\n")
    reqline = lines[0]
    m = re.match(r"(POST|GET|PUT) (\S+) HTTP/1\.[01]", reqline)
    if not m:
        return None
    method, target = m.group(1), m.group(2)
    headers = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
    hl = {k.lower(): v for k, v in headers}
    auth = hl.get("authorization", "")
    am = re.search(r'algorithm="([^"]+)"', auth)
    if not am or am.group(1) != "adj7":
        return None
    sm = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    if not sm:
        return None
    sig = sm.group(1).upper()
    # body: cut EXACTLY at Content-Length
    cl = None
    for k, v in headers:
        if k.lower() == "content-length":
            cl = int(v)
    body_bytes = rest[:cl] if cl is not None else rest
    if cl is not None and len(rest) < cl:
        body_bytes = rest  # truncated capture; keep what's there
    body_text = body_bytes.decode("latin1")
    # fields: URL query first, then body
    fields = {}
    if "?" in target:
        q = urlsplit(target).query
        for k, vs in parse_qs(q, keep_blank_values=True).items():
            fields[k] = vs[0]
    cb = body_text.strip()
    if cb.startswith("{"):
        try:
            j = json.loads(cb)
            if isinstance(j, dict):
                fields.update({k: str(v) for k, v in j.items()})
                body_fmt = "json"
        except Exception:
            body_fmt = "?"
        else:
            pass
    else:
        body_fmt = "form"
        if "=" in body_text:
            for kv in body_text.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    fields[unquote_plus(k)] = unquote_plus(v)
    if cb.startswith("{"):
        pass
    path = target.split("?")[0]
    kind_path = path.rstrip("/").split("/")[-1]
    csdk = hl.get("client-sdk", "")
    return {"src": src, "label": label, "method": method, "path": path,
            "kind_path": kind_path, "client_sdk_header": csdk,
            "content_type": hl.get("content-type", ""),
            "body_format": body_fmt if cb.startswith("{") else "form",
            "body_len": cl if cl is not None else 0,
            "fields": fields, "sig": sig, "auth": auth,
            "body_raw": body_text}

rows = []

# --- 1. wire dump ------------------------------------------------------
data = open(WIRE, "rb").read()
offs = [(m.start(), m.group(1), m.group(2)) for m in REQ.finditer(data)]
for i, (off, meth, target) in enumerate(offs):
    end = offs[i + 1][0] if i + 1 < len(offs) else len(data)
    seg = data[off:end]
    r = parse_request(seg, "wire_dev2srv", "req%02d@%d" % (i, off))
    if r:
        rows.append(r)
print("wire dump: %d requests scanned, %d adj7 rows" % (len(offs), len(rows)))

# --- 2. saz ------------------------------------------------------------
z = zipfile.ZipFile(SAZ)
n_saz = 0
for name in sorted(z.namelist()):
    if not re.match(r"raw/\d+_c\.txt$", name):
        continue
    raw = z.read(name)
    r = parse_request(raw, "saz_payruki_again", name)
    if r:
        rows.append(r)
        n_saz += 1
print("saz: %d adj7 rows" % n_saz)

# --- 3. cap raw dirs ---------------------------------------------------
n_cap = 0
for d in CAPS:
    for name in sorted(os.listdir(d)):
        if not name.endswith("_c.txt"):
            continue
        raw = open(os.path.join(d, name), "rb").read()
        r = parse_request(raw, "cap_" + os.path.basename(os.path.dirname(d)), name)
        if r:
            rows.append(r)
            n_cap += 1
print("cap raws: %d adj7 rows" % n_cap)

# --- dedupe by sig -----------------------------------------------------
seen = {}
for r in rows:
    if r["sig"] in seen:
        seen[r["sig"]]["srcs"].append(r["src"] + ":" + r["label"])
    else:
        r["srcs"] = [r["src"] + ":" + r["label"]]
        seen[r["sig"]] = r
out = list(seen.values())
out.sort(key=lambda r: (r["path"], r["sig"]))
json.dump(out, open(os.path.join(os.path.dirname(__file__), "rows_fresh.json"), "w"), indent=1)
print("TOTAL unique adj7 rows:", len(out))
for i, r in enumerate(out):
    print("%2d %-14s %-12s csdk=%-26s keys=%2d sig=%s..." %
          (i, r["src"], r["kind_path"], r["client_sdk_header"], len(r["fields"]), r["sig"][:12]))

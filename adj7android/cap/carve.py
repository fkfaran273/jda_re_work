# Fresh saz carver: pull every signed Adjust request out of a Fiddler raw dir
import os, re, sys, json, urllib.parse

def carve(rawdir, out_json):
    rows = []
    for fn in sorted(os.listdir(rawdir)):
        if not fn.endswith("_c.txt"):
            continue
        sid = int(fn.split("_")[0])
        raw = open(os.path.join(rawdir, fn), "rb").read()
        # header/body split
        sep = raw.find(b"\r\n\r\n")
        if sep < 0:
            sep = raw.find(b"\n\n"); hl = 2
        else:
            hl = 4
        head = raw[:sep].decode("utf-8", "replace")
        body = raw[sep + hl:]
        lines = head.splitlines()
        if not lines:
            continue
        reqline = lines[0]
        m = re.match(r"([A-Z]+) (\S+) HTTP/[\d.]+", reqline)
        if not m:
            continue
        method, url = m.group(1), m.group(2)
        hdrs = []
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs.append([k.strip(), v.strip()])
        H = {k.lower(): v for k, v in hdrs}
        auth = H.get("authorization", "")
        sm = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
        row = dict(sid=sid, method=method, url=url, headers=hdrs)
        if sm:
            row.update(
                blob=sm.group(1).upper(),
                adj_signing_id=re.search(r'adj_signing_id="([^"]*)"', auth).group(1),
                algorithm=re.search(r'algorithm="([^"]*)"', auth).group(1),
                headers_id=re.search(r'headers_id="([^"]*)"', auth).group(1),
                native_version=re.search(r'native_version="([^"]*)"', auth).group(1),
                client_sdk=H.get("client-sdk", ""),
            )
        if method == "POST":
            row["body"] = body.decode("utf-8", "replace")
        rows.append(row)
    json.dump(rows, open(out_json, "w"), indent=1)
    signed = [r for r in rows if "blob" in r]
    print("%s: %d requests, %d signed" % (out_json, len(rows), len(signed)))
    for r in signed:
        print("  sid %3d %-6s %s\n         sdk=%s nv=%s hi=%s blob[%d]" % (
            r["sid"], r["method"], r["url"].split("?")[0], r["client_sdk"],
            r["native_version"], r["headers_id"], len(r["blob"]) // 2))
    return rows

if __name__ == "__main__":
    carve(r"payruki\raw", r"payruki_signed.json")
    carve(r"hunch\raw", r"hunch_signed.json")

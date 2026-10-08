"""Scan extracted saz captures -> all app.adjust.com signed requests.

Prints per capture: sid, method, host, path, auth params (algorithm,
headers_id, adj_signing_id, native_version), blob length.  Writes
findings/scan_<name>.json with full details for the verifier.
"""
import json
import os
import re
import sys

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings")


def read_raw(path):
    with open(path, "rb") as f:
        return f.read()


def parse_request(data):
    # split headers/body at CRLFCRLF
    i = data.find(b"\r\n\r\n")
    if i < 0:
        head, body = data, b""
    else:
        head, body = data[:i], data[i + 4:]
    lines = head.split(b"\r\n")
    try:
        reqline = lines[0].decode("latin1")
    except Exception:
        reqline = ""
    m = re.match(r"(\S+)\s+(\S+)\s+HTTP/([\d.]+)", reqline)
    method, path = (m.group(1), m.group(2)) if m else ("", "")
    headers = []
    for ln in lines[1:]:
        j = ln.find(b":")
        if j > 0:
            headers.append((ln[:j].decode("latin1").strip(),
                            ln[j + 1:].decode("latin1").strip()))
    host = next((v for k, v in headers if k.lower() == "host"), "")
    return method, path, host, headers, body


def main():
    names = sys.argv[1:] or sorted(os.listdir(BASE))
    for name in names:
        d = os.path.join(BASE, name, "raw")
        sids = sorted({f.split("_")[0] for f in os.listdir(d)
                       if f.endswith("_c.txt")}, key=lambda s: int(s))
        rows = []
        for sid in sids:
            data = read_raw(os.path.join(d, "%s_c.txt" % sid))
            method, path, host, headers, body = parse_request(data)
            if ".adjust." not in host.lower() and "adjust" not in path.lower():
                continue
            auth = next((v for k, v in headers
                         if k.lower() == "authorization"), "")
            m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
            blob = m.group(1) if m else ""
            ap = dict(re.findall(r'(\w+)="([^"]*)"', auth))
            # full URL: path includes query for GET; body for POST
            rows.append({
                "sid": sid, "method": method, "path": path, "host": host,
                "auth_params": ap, "blob_len": len(blob),
                "blob": blob,
                "n_headers": len(headers),
                "header_names": [k for k, v in headers],
                "body_b64": body.decode("latin1"),
            })
        out = {"capture": name, "n_sessions": len(sids), "signed": rows}
        with open(os.path.join(OUT, "scan_%s.json" % name), "w") as f:
            json.dump(out, f, indent=1)
        print("== %s: %d sessions, %d adjust signed-ish" %
              (name, len(sids), len(rows)))
        for r in rows:
            print("  sid%-4s %-4s %-22s %-60s alg=%s hid=%s sid2=%s nv=%s blob=%d"
                  % (r["sid"], r["method"], r["host"],
                     r["path"][:60],
                     r["auth_params"].get("algorithm"),
                     r["auth_params"].get("headers_id"),
                     r["auth_params"].get("adj_signing_id"),
                     r["auth_params"].get("native_version"),
                     r["blob_len"]))


if __name__ == "__main__":
    main()

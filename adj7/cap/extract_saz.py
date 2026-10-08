"""extract_saz.py — pull every Adjust session out of a Fiddler .saz into JSON + raw files.

    python extract_saz.py <file.saz> <out_dir> [--host-substr adjust.com]

Writes into <out_dir>:
    raw/<NN>_c.txt / _s.txt      the raw HTTP request/response of each hit
    <saz>_adjust.json            structured records (headers, decoded body, response)
"""
import gzip
import json
import os
import re
import sys
import zipfile
from urllib.parse import unquote, parse_qsl

def split_http(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    start = lines[0]
    headers = []
    for h in lines[1:]:
        if ":" in h:
            k, v = h.split(":", 1)
            headers.append((k.strip(), v.strip()))
    hmap = {k.lower(): v for k, v in headers}
    # dechunk
    if hmap.get("transfer-encoding", "").lower() == "chunked":
        out = b""
        rest = body
        while rest:
            m = re.match(rb"([0-9a-fA-F]+)[^\r\n]*\r\n", rest)
            if not m:
                break
            n = int(m.group(1), 16)
            out += rest[m.end():m.end() + n]
            rest = rest[m.end() + n:]
            if rest.startswith(b"\r\n"):
                rest = rest[2:]
            if n == 0:
                break
        body = out
    if hmap.get("content-encoding", "").lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    return start, headers, hmap, body

def parse_body(body, ctype):
    if b"application/x-www-form-urlencoded" in ctype.encode():
        try:
            return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
        except Exception:
            return body.decode("utf-8", "replace")
    if b"json" in ctype.encode():
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except Exception:
            pass
    try:
        return body.decode("utf-8", "replace")
    except Exception:
        return body.hex()

def main():
    saz, outdir = sys.argv[1], sys.argv[2]
    hostsub = "adjust.com"
    if len(sys.argv) > 3:
        hostsub = sys.argv[3]
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    z = zipfile.ZipFile(saz)
    names = sorted(n for n in z.namelist() if re.match(r"raw/\d+_c\.txt$", n))
    records = []
    for n in names:
        sid = re.search(r"(\d+)_c", n).group(1)
        creq = z.open(n).read()
        try:
            sresp = z.open(n[:-5] + "s.txt").read()
        except KeyError:
            sresp = b""
        try:
            meta = z.open(n[:-5] + "m.xml").read().decode("utf-8", "replace")
        except KeyError:
            meta = ""
        start, hdrs, hmap, body = split_http(creq)
        rstart, rhdrs, rhmap, rbody = split_http(sresp)
        target = start.split(" ")[1] if " " in start else ""
        if hostsub not in target:
            continue
        # timestamps from metadata
        tmap = dict(re.findall(r'\[FieldName="([^"]+)"\][^<]*<Value>([^<]*)</Value>', meta))
        with open(os.path.join(outdir, "raw", f"{sid}_c.txt"), "wb") as f:
            f.write(creq)
        with open(os.path.join(outdir, "raw", f"{sid}_s.txt"), "wb") as f:
            f.write(sresp)
        rec = {
            "sid": sid,
            "method": start.split(" ")[0],
            "url": target,
            "client_ip": tmap.get("ClientIP", ""),
            "begin": tmap.get("ClientBeginRequest", ""),
            "done": tmap.get("ClientDoneResponse", ""),
            "request_headers": hdrs,
            "body": parse_body(body, hmap.get("content-type", "")),
            "status": (rstart.split(" ")[1] if len(rstart.split(" ")) > 1 else "?"),
            "response_headers": rhdrs,
            "response": rbody.decode("utf-8", "replace"),
        }
        records.append(rec)
    outjson = os.path.join(outdir, os.path.splitext(os.path.basename(saz))[0] + "_adjust.json")
    with open(outjson, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=1, ensure_ascii=False)
    print(f"{len(records)} adjust sessions -> {outjson}")
    for r in records:
        auth = next((v for k, v in r["request_headers"] if k.lower() == "authorization"), "")
        sig = re.search(r'signature="([^"]+)"', auth)
        print(f'{r["sid"]} {r["method"]:5s} {r["status"]:>3s} {r["url"][:70]:70s} sig={len(sig.group(1)) if sig else 0}')

if __name__ == "__main__":
    main()

"""_sub_event_hunt.py — hunt Android Adjust POST /event requests with adj9
signatures across all captures on this machine.  Read-only over captures.
Outputs _sub_event_hunt_out.json with every match (request line, headers,
body) for downstream claims-law derivation."""
from __future__ import annotations

import glob
import io
import json
import os
import re
import sys
import zipfile

DL = r"C:/Users/Apps/Downloads"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "_sub_event_hunt_out.json")

SIG_RE = re.compile(r'signature="([A-Za-z0-9+/=]{100,400})"')


def saz_requests(path):
    """Yield (session_id, request_bytes) for every raw/NNNN_c.txt entry."""
    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        print("  [bad zip] %s: %s" % (path, e), file=sys.stderr)
        return
    with zf:
        names = [n for n in zf.namelist()
                 if n.startswith("raw/") and n.endswith("_c.txt")]
        # numeric sort for ordering
        def num(n):
            m = re.search(r"(\d+)_c\.txt$", n)
            return int(m.group(1)) if m else 0
        for n in sorted(names, key=num):
            try:
                data = zf.read(n)
            except Exception:
                continue
            sid = num(n)
            yield sid, data


def parse_request(data):
    """Split a raw HTTP request into (request_line, headers_dict, body)."""
    if isinstance(data, bytes):
        sep = data.find(b"\r\n\r\n")
        sep_len = 4
        if sep < 0:
            sep = data.find(b"\n\n")
            sep_len = 2
        if sep < 0:
            head, body = data, b""
        else:
            head, body = data[:sep], data[sep + sep_len:]
    try:
        text = head.decode("latin1")
    except Exception:
        text = ""
    lines = text.replace("\r\n", "\n").split("\n")
    req_line = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return req_line, headers, body


def classify(req_line, headers, body):
    """Return a hit record if this is an Adjust request with a signature."""
    if "signature=\"" not in req_line and True:
        auth = ""
        for k in ("authorization",):
            v = headers.get(k, "")
            if "signature=\"" in v:
                auth = v
        if not auth:
            return None
    else:
        auth = req_line
    rl = req_line
    if "/event" not in rl:
        return None
    m = SIG_RE.search(auth)
    sig = m.group(1) if m else None
    return {
        "request_line": rl,
        "host": headers.get("host", ""),
        "client_sdk": headers.get("client-sdk", ""),
        "user_agent": headers.get("user-agent", "")[:120],
        "signature_b64": sig,
        "auth_full": auth[:400],
        "body_text": body.decode("latin1", "replace"),
        "body_len": len(body),
    }


def scan_saz(path, hits, seen_paths):
    n_req = 0
    for sid, data in saz_requests(path):
        n_req += 1
        req_line, headers, body = parse_request(data)
        h = classify(req_line, headers, body)
        if h:
            h.update({"capture": path, "session": sid})
            hits.append(h)
    return n_req


def scan_har(path, hits):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            har = json.load(f)
    except Exception as e:
        print("  [bad har] %s: %s" % (path, e), file=sys.stderr)
        return 0
    n = 0
    for ent in har.get("log", {}).get("entries", []):
        n += 1
        req = ent.get("request", {})
        url = req.get("url", "")
        if "/event" not in url:
            continue
        headers = {h.get("name", "").lower(): h.get("value", "")
                   for h in req.get("headers", [])}
        auth = headers.get("authorization", "")
        if "signature=\"" not in auth:
            continue
        m = SIG_RE.search(auth)
        body = req.get("postData", {}).get("text", "")
        hits.append({
            "capture": path, "request_line": "HAR " + req.get("method", "")
            + " " + url, "host": headers.get("host", ""),
            "client_sdk": headers.get("client-sdk", ""),
            "signature_b64": m.group(1) if m else None,
            "auth_full": auth[:400],
            "body_text": body, "body_len": len(body),
        })
    return n


def main():
    hits = []
    stats = []

    saz_files = set(glob.glob(os.path.join(DL, "*.saz")))
    saz_files |= set(glob.glob(os.path.join(DL, "com.penti.app", "**", "*.saz"),
                               recursive=True))
    # bounded D:/ lookups
    for d in (r"D:/Downloads - Copy", r"D:/Downloads", r"D:/"):
        if os.path.isdir(d):
            saz_files |= set(glob.glob(os.path.join(d, "*.saz")))
            break

    for p in sorted(saz_files):
        try:
            n = scan_saz(p, hits, set())
        except Exception as e:
            print("  [err] %s: %s" % (p, e), file=sys.stderr)
            n = -1
        stats.append({"file": p, "type": "saz", "requests": n,
                      "event_hits": sum(1 for h in hits
                                        if h["capture"] == p)})
        print("%-6d reqs  %3d event-hits  %s" % (n, stats[-1]["event_hits"], p))

    har_files = set(glob.glob(os.path.join(DL, "*.har")))
    har_files |= set(glob.glob(os.path.join(DL, "com.penti.app", "**", "*.har"),
                               recursive=True))
    for p in sorted(har_files):
        n = scan_har(p, hits)
        stats.append({"file": p, "type": "har", "requests": n,
                      "event_hits": sum(1 for h in hits if h["capture"] == p)})
        print("%-6d reqs  %3d event-hits  %s" % (n, stats[-1]["event_hits"], p))

    # CHLS: binary grep for /event + signature markers (bounded)
    chls_files = set(glob.glob(os.path.join(DL, "*.chls")))
    chls_files |= set(glob.glob(os.path.join(DL, "com.penti.app", "**", "*.chls"),
                                recursive=True))
    for p in sorted(chls_files):
        try:
            with open(p, "rb") as f:
                blob = f.read()
        except Exception as e:
            print("  [bad chls] %s: %s" % (p, e), file=sys.stderr)
            continue
        n_ev = blob.count(b"/event ")
        n_sig = blob.count(b"signature=\"")
        stats.append({"file": p, "type": "chls", "requests": -1,
                      "event_hits": n_ev if (n_ev and n_sig) else 0})
        print("%-6s reqs  %3d raw /event, %3d raw signature  %s"
              % ("?", n_ev, n_sig, p))

    with open(OUT, "w") as f:
        json.dump({"hits": hits, "stats": stats}, f, indent=1)
    print("\nTOTAL event+signature hits: %d  -> %s" % (len(hits), OUT))
    for h in hits:
        print("  %s | %s | sdk=%s | bodylen=%d"
              % (os.path.basename(h["capture"]), h["request_line"][:80],
                 h.get("client_sdk", ""), h["body_len"]))


if __name__ == "__main__":
    main()

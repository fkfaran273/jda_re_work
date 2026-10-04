"""adjcap.py — mitmproxy addon: record EXACTLY what the app sends Adjust.

Run:  mitmdump -s adjcap.py -p 8080 --set ssl_insecure=true
Then point the device's proxy at the PC and launch the app.

Writes one JSON file per Adjust transaction under ./adjcap_out/ so the app's
real /session, /sdk_click and /attribution can be diffed byte-for-byte against
what our Python mint produces. This is the ground truth for "what is the app
doing that we are not".
"""
import json
import os
import time
import urllib.parse

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "adjcap_out")
os.makedirs(OUT, exist_ok=True)

INTEREST = ("app.adjust.com", "adjust.com")


def _flatten(pairs):
    """Keep duplicates and order — a param appearing twice may be the tell."""
    return [[k, v] for k, v in pairs]


def _dump(flow, tag):
    req = flow.request
    parsed = urllib.parse.urlsplit(req.pretty_url)
    rec = {
        "tag": tag,
        "ts": time.time(),
        "method": req.method,
        "url": req.pretty_url,
        "path": parsed.path,
        "host": parsed.hostname,
        "http_version": req.http_version,
        "headers": [[k, v] for k, v in req.headers.items(multi=True)],
        "body_len": len(req.raw_content or b""),
    }
    if req.method == "GET":
        rec["params"] = _flatten(urllib.parse.parse_qsl(parsed.query,
                                                         keep_blank_values=True))
    else:
        body = (req.raw_content or b"").decode("utf-8", "replace")
        rec["raw_body"] = body
        rec["params"] = _flatten(urllib.parse.parse_qsl(body,
                                                         keep_blank_values=True))
    fn = os.path.join(OUT, "%s_%s_%d.json"
                      % (tag, parsed.path.strip("/").replace("/", "_") or "root",
                         int(time.time() * 1000)))
    with open(fn, "w") as f:
        json.dump(rec, f, indent=1)
    print("[adjcap] %s %s params=%d -> %s"
          % (req.method, parsed.path, len(rec["params"]), os.path.basename(fn)))


def request(flow):
    host = flow.request.pretty_host or ""
    if not any(h in host for h in INTEREST):
        return
    path = urllib.parse.urlsplit(flow.request.pretty_url).path
    tag = path.strip("/").split("/")[0] or "root"
    _dump(flow, tag)


def response(flow):
    # flow.response has no .request in this mitmproxy version; the request is
    # always reachable as flow.request, and on the response hook it is populated.
    host = flow.request.pretty_host or ""
    if not any(h in host for h in INTEREST):
        return
    path = urllib.parse.urlsplit(flow.request.pretty_url).path
    tag = path.strip("/").split("/")[0] or "root"
    fn = os.path.join(OUT, "latest_%s_resp.txt" % tag)
    with open(fn, "w") as f:
        f.write("HTTP %s\n" % flow.response.status_code)
        for k, v in flow.response.headers.items(multi=True):
            f.write("%s: %s\n" % (k, v))
        f.write("\n")
        f.write((flow.response.raw_content or b"").decode("utf-8", "replace"))
    # this mitmproxy build exposes no .raw_content_length; measure the bytes.
    print("[adjcap] <- %s %s (%d bytes)"
          % (flow.response.status_code, path, len(flow.response.raw_content or b"")))

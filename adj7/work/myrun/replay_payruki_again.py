"""replay_payruki_again.py -- replay the stomach-jung-area fresh-paid
payrupik_new capture attribution row (43) with the EXACT raw URL and
Authorization from the capture; print the server verdicts.  Writes a
small report to a NEW file alongside (no originals touched).
"""
import gzip
import http.client
import json
import os
import re
import urllib.parse

RAW = r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payruki_again\raw"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun\payruki_again_reply.json"


def load_row(idx):
    head = open(os.path.join(RAW, "%02d_c.txt" % idx), "rb").read()
    request_head, _, _ = head.partition(b"\r\n\r\n")
    lines = request_head.decode().split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = {}
    for ln in lines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            headers[k] = v
    return method, target, headers


def get(path, headers):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    for k, v in headers.items():
        if k.lower() == "host":
            continue
        c.putheader(k, v)
    c.putheader("Host", "app.adjust.com")
    c.endheaders()
    r = c.getresponse()
    body = r.read()
    if body[:2] == bytes((0x1F, 0x8B)):
        body = gzip.decompress(body)
    c.close()
    return r.status, body.decode()


method, target, headers = load_row(43)
u = urllib.parse.urlsplit(target)
path = u.path + "?" + u.query
print("target:", u.path)
status, text = get(path, headers)
print("HTTP", status)
print(text[:500])
if "248wk8ym" in text:
    verdict = "NON-ORGANIC"
elif "g0bpyt5" in text:
    verdict = "ORGANIC"
elif status == 400:
    verdict = "THROTTLED/400"
else:
    verdict = "other"
print("VERDICT:", verdict)
json.dump({"http": status, "body": text, "verdict": verdict,
           "path": u.path}, open(OUT, "w"), indent=1)
print("wrote", OUT)

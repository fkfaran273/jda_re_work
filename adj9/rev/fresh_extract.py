#!/usr/bin/env python3
"""fresh_extract.py — pull the newest genuine /attribution GET (query + 192B blob)
from the live tap dump (split-tolerant over TLS record boundaries)."""
import re, base64, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"

raw = open(DUMP, "rb").read()
print("dump bytes:", len(raw))

# every attribution GET; take the last one
hits = []
for m in re.finditer(rb"GET (/attribution\S*) HTTP/1\.1", raw):
    hits.append(m.start())
print("attribution GET offsets:", hits)
if not hits:
    sys.exit("no attribution GET in dump")

off = hits[-1]
seg = raw[off:off + 8000]
mq = re.search(rb"GET (\S+) HTTP/1\.1", seg)
query = mq.group(1).decode()
print("query:", query[:250])

# b64 may be split by TLS-record chunks -> collapse everything between
# signature=" and the closing quote
m2 = re.search(rb'signature="([^"]{250,700})"', seg, re.S)
if not m2:
    sys.exit("no signature header found after offset %d" % off)
b64 = re.sub(rb"[^A-Za-z0-9+/=]", b"", m2.group(1))
print("b64 chars:", len(b64))
blob = base64.b64decode(b64)
print("blob %dB hdr=%s" % (len(blob), blob[:16].hex()))
if len(blob) != 192:
    print("WARNING: blob is not 192B — dump may be truncated mid-header")

out = {"query": query, "blob_hex": blob.hex(), "off": off}
json.dump(out, open(os.path.join(HERE, "fresh_genuine.json"), "w"))
print("saved fresh_genuine.json")

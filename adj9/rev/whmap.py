"""whmap.py - map the WHCAP EMIT stream: which EMIT (sink,pos) carries which
descriptor bytes, using the golden signing. The whcap_hits7.json has
~39673 EMIT dwords; desc_det/desc_all already extracted field descriptors.
Here: find the EMIT rows whose VALUE equals region dwords AND record their
(sink, pos, x19=writer-status, x21, x26, x28-walker) context. If region EMITs
come from the FIELD loop (walker x28 = desc index) vs the QUEUE program
(x28 = merge step), we learn HOW the region enters the blob.

Also correlate: the java_blob b64 in whcap = which nsign hex in wh4_records?
"""
import json
import os
import struct

DEV = "C:\\Users\\Apps\\Downloads\\com.penti.app\\adj9\\device\\"
d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
print("type:", type(d), "len:", len(d) if hasattr(d, "__len__") else "?")
if isinstance(d, dict):
    print("keys:", sorted(d.keys())[:20])
elif isinstance(d, list):
    print("item0 keys:", sorted(d[0].keys()) if isinstance(d[0], dict) else d[0])
print("done")

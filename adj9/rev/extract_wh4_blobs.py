"""extract_wh4_blobs.py - pull every 192-B blob from adj9_wh4.log + adj9_wh2.log.

Format (from the captures): 'nsign ts=<13-digit>\\nblob=<384 hex>' or similar.
Probe several patterns and report what was found.
"""
import base64
import json
import os
import re
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")


def read_log(name):
    p = os.path.join(DEV, name)
    if not os.path.exists(p):
        # try rev/
        p = os.path.join(HERE, name)
    return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""


out = {}
for logname in ("adj9_wh4.log", "adj9_wh2.log", "adj9_wh.log"):
    txt = read_log(logname)
    if not txt:
        continue
    print("%s: %d bytes" % (logname, len(txt)))

    # pattern 1: ts=13digits then blob=384hex nearby
    for m in re.finditer(r"ts=(\d{13}).{0,80}?blob=([0-9a-f]{384})", txt):
        out.setdefault(m.group(2), []).append((logname, int(m.group(1))))
    # pattern 2: nsign records with hex=384
    for m in re.finditer(r'"ts":\s*(\d{13})[^}]*?"hex":\s*"([0-9a-f]{384})"', txt):
        out.setdefault(m.group(2), []).append((logname, int(m.group(1))))
    # pattern 3: ADJ9ORA nsign blob line
    for m in re.finditer(r"nsign[^0-9a-f]([0-9a-f]{384})", txt):
        out.setdefault(m.group(1), [])

print("distinct blobs: %d" % len(out))
for hx, tss in out.items():
    print("  %s  %s" % (hx[:32], tss))

json.dump({hx: ts for hx, ts in out.items()},
          open(os.path.join(HERE, "wh_blobs.json"), "w"), indent=0)
print("saved wh_blobs.json")

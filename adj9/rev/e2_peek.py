import json
import base64
import os

p1 = os.path.join(os.environ["TEMP"], "mo1.json")
p2 = os.path.join(os.environ["TEMP"], "mo2.json")
print("mo1 keys:", end=" ")
raw = open(p1, "rb").read()
if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
    raw = raw.decode("utf-16").encode("utf-8")
d1 = json.loads(raw)
print(type(d1).__name__, list(d1.keys()) if isinstance(d1, dict) else len(d1))
if isinstance(d1, dict):
    for k, v in d1.items():
        print(" ", k, type(v).__name__, (len(v) if hasattr(v, "__len__") else v))

r"""crosscheck_extract_blobs.py — pull genuine Authorization blobs out of the
saved capture log (###ADJ9_BEGIN type=authorization_header blocks)."""
import json
import re

TXT = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\crosscheck_capture.log",
           "rb").read().decode("utf-8", "replace")

blobs = []
cur = None
for l in TXT.splitlines():
    if l.startswith("###ADJ9_BEGIN"):
        cur = {"hdr": l, "body": []}
    elif l.startswith("###ADJ9_END"):
        if cur is not None:
            joined = "\n".join(cur["body"])
            m = re.search(r'signature="([A-Za-z0-9+/=\r\n]+)"', joined)
            ts = re.search(r"ts=(\d+)", cur["hdr"])
            if m:
                blobs.append({"ts": int(ts.group(1)) if ts else None,
                              "blob": m.group(1).replace("\n", "").replace("\r", "")})
        cur = None
    elif cur is not None:
        cur["body"].append(l)

print("extracted %d blobs" % len(blobs))
for b in blobs:
    print(b["ts"], len(b["blob"]), b["blob"][:60])

json.dump({"auths": [b["blob"] for b in blobs],
           "ts": [b["ts"] for b in blobs],
           "auids": ["f2089155-1916-4052-8a95-1370799ec241"],
           "adids": ["6a8f535a13e23278c67aece378105c25"]},
          open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\crosscheck_ids.json", "w"),
          indent=1)
print("saved crosscheck_ids.json")

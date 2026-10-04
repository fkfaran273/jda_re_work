"""wh_log_evidence.py -- third-capture confirmation of the info claims law.

adj9/device/adj9_wh.log and adj9_wh2.log (12 Sep, app 3.13.9) recorded, per
signing, the sign_input map AND the resulting Authorization header.  The
base64 signature inside it is the 192-byte envelope; its decoded record gives
head/seed/cert/want for the block oracle.  Every info signing in both logs
must satisfy the law now installed in adj9_pure._GROUPS['info'].
"""
import base64
import os
import re
import struct
import sys

MRUN = r"C:\Users\Apps\Downloads\com.penti.app\manual_run"
sys.path.insert(0, MRUN)
import adj9_pure as P
import adj9_decode as D

pat = re.compile(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)")


def events(path):
    cur = None
    buf = []
    for line in open(path, encoding="utf-8", errors="replace"):
        m = pat.match(line)
        if m:
            cur, buf = (m.group(1), int(m.group(3))), []
            continue
        if line.startswith("###ADJ9_END"):
            if cur:
                yield (cur[1], cur[0], "\n".join(buf))
            cur = None
            continue
        if cur:
            buf.append(line.rstrip("\n"))


def main():
    total = okc = 0
    for path in (r"C:/Users/Apps/Downloads/com.penti.app/adj9/device/adj9_wh.log",
                 r"C:/Users/Apps/Downloads/com.penti.app/adj9/device/adj9_wh2.log"):
        evs = list(events(path))
        for i, (ts, typ, body) in enumerate(evs):
            if typ != "sign_input" or "activity_kind=info" not in body:
                continue
            sig = None
            for j in range(i + 1, min(i + 8, len(evs))):
                if evs[j][1] == "authorization_header":
                    m = re.search(r'signature="([^"]+)"', evs[j][2])
                    if m:
                        sig = base64.b64decode(m.group(1))
                    break
            mm = re.search(r"map_toString=\{(.*)\}", body, re.S)
            if not mm or sig is None or len(sig) != 192:
                continue
            val = {}
            for kv in mm.group(1).split(", "):
                k, _, v = kv.partition("=")
                val[k] = v
            rec = D.whiten_body_inverse(sig[16:160], sig[:16])
            if rec[0:3] != b"\x01\x00\x08":
                continue
            seed = struct.unpack(">I", rec[20:24])[0]
            padded, ulen = P.claims_padded(val, "info")
            got = P.record_block(rec[3:19], seed, padded[:ulen], rec[25:45])
            total += 1
            okc += got == rec[46:78]
        print("%s: %d/%d info block MATCH"
              % (os.path.basename(path), okc, total))
    print("third-capture evidence: %d/%d" % (okc, total))
    return 0 if okc == total and total else 1


if __name__ == "__main__":
    sys.exit(main())

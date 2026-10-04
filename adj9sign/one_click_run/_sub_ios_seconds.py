"""_sub_ios_seconds.py — recover the signing second of all 30 captured
requests by inverting the iOS MINSTD header law, and cross-check the record's
d0 head against region(S, head=(0x40,)).

Writes _sub_ios_seconds.json: per request {file, sid, signing_second,
offset_vs_begin, header16_hex, S, d0_head_ok}.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import zipfile
from datetime import datetime

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse
from _sub_ios_header import make_ios_header, load_capture

HERE = os.path.dirname(os.path.abspath(__file__))
SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"


def main():
    # 1. capture timestamps per sid
    cap = {c["sid"]: c for c in load_capture()}

    # 2. signed blobs per file
    z = zipfile.ZipFile(SAZ)
    rows = []
    for name in sorted(z.namelist()):
        if not re.fullmatch(r"raw/\d+_c\.txt", name):
            continue
        txt = z.read(name).decode("latin1")
        m = re.search(r'signature="([A-Za-z0-9+/=]+)"', txt)
        if not m:
            continue
        blob = base64.b64decode(m.group(1))
        sid = int(re.search(r"(\d+)_c", name).group(1))
        rec = whiten_inverse(blob[16:160], blob[:16])
        S = int.from_bytes(rec[20:24], "big")
        header = blob[:16]
        d0_ok = sg.head16_for(S, (0x40,)) == rec[3:19]
        c = cap[sid]
        center = int(c["begin_unix"] // 1)
        hits = [s for s in range(center - 900, center + 901)
                if make_ios_header(s) == header]
        assert len(hits) == 1, (sid, hits)
        second = hits[0]
        rows.append({
            "file": os.path.basename(name),
            "sid": sid,
            "path": txt.split("\r\n")[0].split(" ")[1].split("?")[0],
            "header16_hex": header.hex(),
            "signing_second": second,
            "begin_unix": c["begin_unix"],
            "offset_vs_begin": second - c["begin_unix"],
            "S": S,
            "d0_head_phase40_ok": bool(d0_ok),
            "byte112": rec[112],
            "device_field": rec[114:130].decode("latin1"),
        })

    ok_hdr = sum(1 for r in rows if make_ios_header(r["signing_second"])
                 .hex() == r["header16_hex"])
    ok_d0 = sum(1 for r in rows if r["d0_head_phase40_ok"])
    print("[seconds] %d requests" % len(rows))
    print("[seconds] header -> unique second recovered: %d/%d"
          % (len(rows), len(rows)))
    print("[seconds] header re-mint at second: %d/%d" % (ok_hdr, len(rows)))
    print("[seconds] d0 head == head16_for(S,(0x40,)): %d/%d"
          % (ok_d0, len(rows)))
    offs = sorted(set(r["offset_vs_begin"] for r in rows))
    print("[seconds] offsets vs floor(BeginRequest): %s" % offs[:20])
    secs = [r["signing_second"] for r in rows]
    print("[seconds] span: %d .. %d" % (min(secs), max(secs)))

    with open(os.path.join(HERE, "_sub_ios_seconds.json"), "w") as f:
        json.dump(rows, f, indent=1)
    print("[seconds] wrote _sub_ios_seconds.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

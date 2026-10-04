"""_sub_event_law_parse.py — stream-parse the on-device ADJ9 frida trace logs
(penti, android5.7.0) into per-signing records.

Each real signing appears as:
  type=nsign          : the 192-B signature blob (hex= in text)
  type=sign_input     : map_toString (full claims map) + key2_hex (same blob)
  type=authorization_header
  type=nsign_in       : arg3_hex (32-B) — oracle probe input
  type=mapget         : every Map.get during the trace: this=<id> key=<k> val=<v>

Output: _sub_event_signings.json  (list of signings with the mapget window
accumulated since the previous nsign, for claims-order reconstruction).
"""
from __future__ import annotations

import json
import os
import re
import sys

BASE = r"C:/Users/Apps/Downloads/com.penti.app/adj9/device"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "_sub_event_signings.json")

FILES = [
    "adj9_wh.log",
    "adj9_wh2.log",
    "adj9_mapget.mlog",
    "adj9_ns.mlog",
    "tail5.mlog",
]

HDR = re.compile(r"^###ADJ9_BEGIN type=([a-z_0-9]+)(?: utf8len=(\d+))?"
                 r"(?: ts=(\d+))?")
MG = re.compile(r"^this=(\d+) key=(.*) val=(.*)$")


def parse_map_order(s):
    """map_order payload: key \x01 value \x02 key \x01 value ..."""
    out = {}
    if not s:
        return out
    for pair in s.split("\x02"):
        if "\x01" in pair:
            k, v = pair.split("\x01", 1)
            out[k] = v
        elif pair.strip():
            out[pair] = ""
    return out


def parse_map_tostring(s):
    """Java LinkedHashMap toString: {k=v, k=v, ...} (fallback parser)."""
    out = {}
    if not (s.startswith("{") and s.endswith("}")):
        return out
    body = s[1:-1]
    if not body:
        return out
    prev_k = None
    for piece in body.split(", "):
        if "=" in piece:
            k, v = piece.split("=", 1)
            out[k] = v
            prev_k = k
        elif prev_k is not None:
            out[prev_k] += ", " + piece      # value contained ', '
    return out


def stream(path):
    """Yield (type, ts, text_lines) for every ###ADJ9 record."""
    cur_type = None
    cur_ts = None
    cur_text = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("###ADJ9_BEGIN "):
                m = HDR.match(line.rstrip("\n"))
                if m:
                    cur_type, _l, ts = m.groups()
                    cur_ts = int(ts) if ts else None
                    cur_text = []
                continue
            if line.startswith("###ADJ9_END"):
                if cur_type is not None:
                    yield cur_type, cur_ts, cur_text
                cur_type = None
                continue
            if cur_type is None:
                continue
            if line.startswith("text:"):
                cur_text.append(line[5:].rstrip("\n"))
            elif line.startswith("hex:"):
                pass
            elif line.strip():
                cur_text.append(line.rstrip("\n"))


def main():
    signings = []
    for fname in FILES:
        path = os.path.join(BASE, fname)
        if not os.path.exists(path):
            print("missing:", path)
            continue
        mg_buf = []            # mapgets since previous nsign
        last_nsign = None      # dict or None
        n_in = 0
        for rtype, ts, text in stream(path):
            if rtype == "mapget":
                if text:
                    m = MG.match(text[0].strip())
                    if m:
                        mg_buf.append([ts, int(m.group(1)), m.group(2),
                                       m.group(3)])
                continue
            if rtype == "nsign":
                blob_hex = None
                for ln in text:
                    if ln.strip().startswith("hex="):
                        blob_hex = ln.strip()[4:].strip().lower()
                if last_nsign is not None:
                    signings.append(last_nsign)
                last_nsign = {"file": fname, "nsign_ts": ts,
                              "blob_hex": blob_hex, "map": None,
                              "auth": None, "arg3": None,
                              "mapgets": mg_buf}
                mg_buf = []
                n_in += 1
                continue
            if rtype == "sign_input" and last_nsign is not None:
                mp, key2 = {}, None
                for ln in text:
                    lns = ln.strip()
                    if lns.startswith("map_toString="):
                        mp = parse_map_tostring(lns[13:])
                    elif lns.startswith("map_order="):
                        mp = parse_map_order(lns[10:])
                    elif lns.startswith("key2_hex="):
                        key2 = lns[9:].strip().lower()
                if key2 and last_nsign["blob_hex"] and key2 != \
                        last_nsign["blob_hex"]:
                    # belongs to a different (burst) signing — keep anyway
                    pass
                if mp:
                    last_nsign["map"] = mp
                last_nsign["key2"] = key2
                continue
            if rtype == "authorization_header" and last_nsign is not None \
                    and last_nsign["auth"] is None:
                last_nsign["auth"] = text[0] if text else None
                continue
            if rtype == "nsign_in" and last_nsign is not None \
                    and last_nsign["arg3"] is None:
                for ln in text:
                    lns = ln.strip()
                    if lns.startswith("arg3_hex="):
                        last_nsign["arg3"] = lns[9:].strip().lower()
                continue
        if last_nsign is not None:
            signings.append(last_nsign)
        print("%-24s signings=%3d mapgets_total=%d"
              % (fname, n_in, sum(len(s["mapgets"]) for s in signings
                                  if s["file"] == fname)))

    kinds = {}
    for s in signings:
        k = (s.get("map") or {}).get("activity_kind", "?")
        kinds[k] = kinds.get(k, 0) + 1
    print("kinds:", kinds)
    print("event signings:",
          sum(1 for s in signings
              if (s.get("map") or {}).get("activity_kind") == "event"))

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(signings, f)
    print("wrote", OUT)


if __name__ == "__main__":
    main()

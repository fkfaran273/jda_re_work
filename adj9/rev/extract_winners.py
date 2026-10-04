"""extract_winners.py — pull the genuine winning blobs + claims from
win_capture/module_win_capture.log and decode their regions."""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

from desc10_law import build_desc10, desc10_keys   # noqa: E402

LOG = os.path.join(HERE, "win_capture", "module_win_capture.log")


def parse_log():
    txt = open(LOG, encoding="utf-8", errors="replace").read()
    blocks = re.findall(r"###ADJ9_BEGIN type=(\w+).*?ts=(\d+)\ntext:(.*?)###ADJ9_END",
                        txt, re.S)
    out = []
    for kind, ts, text in blocks:
        out.append((kind, int(ts), text))
    return out


def parse_map_tostring(s):
    s = s.strip()
    assert s.startswith("{") and s.endswith("}")
    d = {}
    for part in s[1:-1].split(", "):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def main():
    blocks = parse_log()
    wins = []
    last_map = None
    for kind, ts, text in blocks:
        if kind == "sign_input":
            m = re.search(r"map_toString=\{(.*?)\}\n", text, re.S)
            if m:
                try:
                    last_map = parse_map_tostring("{" + m.group(1) + "}")
                except Exception as e:
                    print("map parse fail:", e)
        elif kind in ("nsign", "nsign_native"):
            m = re.search(r"out_hex=([0-9a-f]+)", text) or \
                re.search(r"hекс=([0-9a-f]+)", text) or \
                re.search(r"hex=([0-9a-f]{384})", text)
            if m is None:
                mm = re.search(r"(?:out_hex|hex)=([0-9a-f]+)", text)
                m = mm
            if m is None:
                continue
            hx = m.group(1)
            if len(hx) < 384:
                continue
            blob = bytes.fromhex(hx[:384])
            wins.append({"ts": ts, "second": ts // 1000, "blob": blob.hex(),
                         "map": last_map})
    print("nsign blobs:", len(wins))
    # dedupe by blob
    seen = {}
    for w in wins:
        seen[w["blob"]] = w
    uniq = list(seen.values())
    uniq.sort(key=lambda w: w["ts"])
    print("unique blobs:", len(uniq))
    for w in uniq:
        mp = w["map"] or {}
        print("ts=%d second=%d kind=%s blob=%s..."
              % (w["ts"], w["second"], mp.get("activity_kind"),
                 w["blob"][:16]))
    json.dump(uniq, open(os.path.join(HERE, "winners_extracted.json"), "w"),
              indent=1)
    print("saved winners_extracted.json")


if __name__ == "__main__":
    main()

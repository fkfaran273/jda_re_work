"""testbed.py — local adj9 mint testbed for the creditsea captures.

Mines the LSPosed ground-truth log (adj9_cap_fresh.log):
  - genuine 192-B blobs            (type=nsign)
  - per-signing claims maps        (type=sign_input, map_order k\\x01v \\x02-joined)
  - the HMAC digests               (type=t1_a_out)
decodes each blob (whiten_decoder), solves the head phase (block_pattern_analysis
solver), rebuilds the descriptor plane and drives fin_vm2.FinEx under a set of
claims-law hypotheses.  A hypothesis WINS when the minted blob is byte-exact.
"""
import base64
import hashlib
import itertools
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)

import whiten_decoder as WD          # noqa: E402
import F as Fmod                     # noqa: E402
from fin_vm2 import FinEx            # noqa: E402
from desc10_law import build_desc10  # noqa: E402

LOG = os.path.join(HERE, "adj9_cap_fresh.log")
SINK = 0x5500000000
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
D8_HEX = "bffffffffffffd1f0007000000000000"      # penti capture - to verify
D9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")  # creditsea cert

# the exact read order the native used (LSPosed mapget trace, session signing)
READ_ORDER = {
    'session': ['adj_verification', 'android_uuid', 'api_level', 'app_token',
                'app_version', 'country', 'created_at', 'device_name',
                'device_type', 'environment', 'gps_adid', 'gps_adid_src',
                'hardware_name', 'initiating_package_name', 'installed_at',
                'os_build', 'os_name', 'os_version', 'package_name',
                'session_count', 'store_name_from_system', 'tracking_enabled',
                'updated_at', 'activity_kind', 'client_sdk'],
    'click': ['adj_verification', 'android_uuid', 'api_level', 'app_token',
              'app_version', 'click_time', 'click_time_server', 'country',
              'created_at', 'device_name', 'device_type', 'environment',
              'google_play_instant', 'gps_adid', 'gps_adid_src',
              'hardware_name', 'install_begin_time', 'install_begin_time_server',
              'install_version', 'installed_at', 'os_build', 'os_name',
              'os_version', 'package_name', 'referrer', 'referrer_api',
              'session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at', 'activity_kind',
              'client_sdk'],
    'attribution': ['adj_verification', 'android_uuid', 'api_level',
                    'app_token', 'app_version', 'created_at', 'device_name',
                    'device_type', 'environment', 'gps_adid', 'gps_adid_src',
                    'initiated_by', 'os_name', 'os_version', 'package_name',
                    'tracking_enabled', 'activity_kind', 'client_sdk'],
}


# ---------------------------------------------------------------------------
# log mining
# ---------------------------------------------------------------------------
def mine_log(path=LOG):
    txt = open(path, encoding="utf-8", errors="replace").read()
    recs = []
    for chunk in txt.split("###ADJ9_BEGIN")[1:]:
        m = re.match(r"\s*type=(\w+) utf8len=\d+ ts=(\d+)", chunk)
        if not m:
            continue
        recs.append({"type": m.group(1), "ts": int(m.group(2)), "body": chunk})
    recs.sort(key=lambda r: r["ts"])

    blobs, digests, maps = [], [], []
    for r in recs:
        if r["type"] == "nsign":
            hm = re.search(r"\bhex=([0-9a-f]{384})", r["body"])
            if hm:
                blobs.append({"ts": r["ts"], "blob": bytes.fromhex(hm.group(1))})
        elif r["type"] == "t1_a_out":
            hm = re.search(r"\bhex=([0-9a-f]{64})", r["body"])
            if hm:
                digests.append({"ts": r["ts"], "digest": bytes.fromhex(hm.group(1))})
        elif r["type"] == "sign_input":
            mo = re.search(r"map_order=([^\n]*)", r["body"])
            mt = re.search(r"map_toString=(\{[^\n]*\})", r["body"])
            ms = re.search(r"map_size=(\d+)", r["body"])
            val = {}
            if mo:
                for part in mo.group(1).split("\x02"):
                    if "\x01" in part:
                        k, v = part.split("\x01", 1)
                        val[k] = v
            maps.append({"ts": r["ts"], "val": val, "map_size": int(ms.group(1)) if ms else -1})
    # pair: each blob with the sign_input whose ts is within [blob.ts, blob.ts+100ms]
    sigs = []
    for b in blobs:
        cand = [m for m in maps if 0 <= m["ts"] - b["ts"] <= 100]
        dig = [d for d in digests if 0 <= b["ts"] - d["ts"] <= 60_000]
        sigs.append({
            "second": b["ts"] // 1000,
            "blob": b["blob"],
            "val": cand[0]["val"] if cand else {},
            "digest": dig[-1]["digest"] if dig else None,
        })
    return sigs


def decode(blob):
    rec = WD.whiten_body_inverse(blob[16:160], blob[:16])
    d2w_le = int.from_bytes(rec[20:24], "little")
    return {
        "record": rec,
        "head": rec[3:19],
        "S": int.from_bytes(rec[20:24], "big"),
        "d2w_le": d2w_le,
        "block": rec[46:78],
    }


def solve_head_phase(d4w, head, max_len=7):
    src = Fmod._d0_source(d4w)
    hv = [int.from_bytes(head[2 * j:2 * j + 2], "big") for j in range(8)]
    for L in range(1, max_len + 1):
        for cand in itertools.product(range(0x20, 0x60), repeat=L):
            sels = tuple(list(cand) + [0x40 | (i & 7) for i in range(L, 72)])
            if all(Fmod._selector_halfword((sels[j] << 1) + 3, src) == hv[j]
                   for j in range(8)):
                return cand
    return None


def run_vm(second, descs, max_steps=60_000_000):
    ex = FinEx(int(second), descs)
    status = ex.run(max_steps=max_steps)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    m = bys.get(SINK)
    if m is None:
        return None, status
    blob = b"".join(struct.pack(">I", m.get(k, 0)) for k in range(48))
    return blob, status


def build_descs(second, claims_raw, d0, d4, d2):
    padded = claims_raw + b"\x00" * (-len(claims_raw) % 4)
    byidx = {
        0: (36, 0, d0), 9: (5, 0, D9),
        8: (4, 0, bytes.fromhex(D8_HEX)), 4: (8, 0, d4), 2: (1, 0, d2),
        7: (1, 0, struct.pack(">I", len(claims_raw))),
        10: (len(padded) // 4, 0, padded),
        5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
        1: (0, 0, b""), 3: (0, 0, b""),
    }
    return [byidx[i] for i in VA_ORDER]


def region_parts(dec, second):
    d4w = Fmod._d4_words(dec["S"])
    pfx = solve_head_phase(d4w, dec["head"])
    d0w = Fmod._d0_words(d4w, head=tuple(pfx)) if pfx else None
    d0 = b"".join(w.to_bytes(4, "big") for w in d0w)
    d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
    d2 = dec["d2w_le"].to_bytes(4, "big")
    return d0, d4, d2, pfx


# ---------------------------------------------------------------------------
# hypotheses: name -> claims bytes from the live map
# ---------------------------------------------------------------------------
def hypotheses(val):
    kind = val.get("activity_kind", "session")
    ro = [k for k in READ_ORDER.get(kind, sorted(val)) if k in val]
    # generic fallback: sorted-with-block2-last
    if not ro:
        ro = sorted(val)
    out = {}
    out["penti_law"] = build_desc10(val, kind).encode("latin1")
    out["ro_vals"] = "".join(val[k] for k in ro).encode("latin1")
    out["ro_vals_x2"] = out["ro_vals"] * 2
    out["ro_kv_eq"] = "".join(k + "=" + val[k] for k in ro).encode("latin1")
    out["ro_kv_amp"] = "".join(k + "=" + val[k] + "&" for k in ro).encode("latin1")
    out["ro_kv_1_2"] = "\x02".join(k + "\x01" + val[k] for k in ro).encode("latin1")
    out["ro_kv_concat"] = "".join(k + val[k] for k in ro).encode("latin1")
    out["ro_vals_plus_digest"] = out["ro_vals"] + val.get("_digest", b"").hex().encode()
    sv = sorted(val)
    out["sorted_vals_subset"] = "".join(val[k] for k in sv).encode("latin1")
    out["ro_vals_pinned"] = (
        "".join(val[k] for k in ro if k not in ("activity_kind", "client_sdk"))
        + "1500000"
        + "".join(val[k] for k in ("activity_kind", "client_sdk") if k in val)
    ).encode("latin1")
    return out


def main():
    sigs = mine_log()
    print("signings mined:", len(sigs))
    results = []
    for si, s in enumerate(sigs):
        kind = s["val"].get("activity_kind", "?")
        print(f"\n=== signing {si}: kind={kind} second={s['second']} "
              f"map_keys={len(s['val'])} digest={s['digest'].hex() if s['digest'] else None}")
        dec = decode(s["blob"])
        d0, d4, d2, pfx = region_parts(dec, s["second"])
        print(f"  S={dec['S']:#x} phase={[hex(x) for x in (pfx or ())]} "
              f"genuine_block={dec['block'].hex()}")
        if d0 is None:
            print("  head phase UNSOLVED"); continue
        for name, raw in hypotheses(s["val"]).items():
            blob, status = run_vm(s["second"], build_descs(s["second"], raw, d0, d4, d2))
            if blob is None:
                print(f"  {name:24s} len={len(raw):4d}  NO SINK ({status})")
                continue
            exact = blob == s["blob"]
            orec = WD.whiten_body_inverse(blob[16:160], blob[:16])
            blk_ok = orec[46:78] == dec["block"]
            nd = sum(1 for i in range(192) if blob[i] != s["blob"][i])
            results.append({"sig": si, "hyp": name, "len": len(raw),
                            "exact": exact, "block": blk_ok, "ndiff": nd})
            mark = "BYTE-EXACT ***" if exact else (f"block={'ok' if blk_ok else 'X'} ndiff={nd}")
            print(f"  {name:24s} len={len(raw):4d}  {status:8s} {mark}")
    json.dump(results, open(os.path.join(HERE, "testbed_results.json"), "w"), indent=1)
    wins = [r for r in results if r["exact"]]
    print("\nWINS:", [(w["sig"], w["hyp"]) for w in wins] or "none")


if __name__ == "__main__":
    main()

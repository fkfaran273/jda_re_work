"""diff_test.py — differential test: merged adj9_signer vs the original
adj9/rev stack. Mints a session and a click blob through BOTH with identical
inputs (claims, second, S, head phase) and asserts byte equality.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "adj9", "rev"))

import adj9_signer as S          # merged, self-contained
import mint_pipeline as M        # original
import F as FP                   # original region
import adj9_full_chain as AF     # fmt for realistic claims

WIN_HEAD = (0x2B, 0x48)
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

import json
base = json.load(open(os.path.join(ROOT, "adj9", "rev",
                                   "app_session_params_real.json"),
                      encoding="utf-8"))
base.pop("push_token", None)
GPS = "7cc81be0-60a0-4342-a878-eb5ee4f2634a"
AUID = "1b06322b-9070-4bdc-a231-2199bef3f3f5"


def build_params(kind):
    p = dict(base)
    p.update({"gps_adid": GPS, "android_uuid": AUID,
              "session_count": "1", "session_length": "0", "time_spent": "0",
              "subsession_count": "1"})
    if kind == "click":
        p.update({"source": "install_referrer", "referrer_api": "google",
                  "referrer": "adjust_reftag=cVxwJxtbQwuyM&utm_source=VKM",
                  "google_play_instant": "0",
                  "click_time": AF.fmt(1790625700, 0).decode(),
                  "click_time_server": AF.fmt(1790625698, 0).decode(),
                  "install_begin_time": AF.fmt(1790625706, 0).decode(),
                  "install_begin_time_server": AF.fmt(1790625704, 0).decode()})
    return p


def descs_for(stack_params, kind, sec, S):
    val = dict(stack_params)
    val.update({"activity_kind": kind, "client_sdk": "android5.7.0",
                "adj_signing_id": "1500000", "headers_id": "10",
                "native_version": "5.0.0",
                "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"})
    d0w, d2w, d4w = S.region(S, 0, 0, head=WIN_HEAD)  # placeholder, replaced
    return val


def mint_with(mod_region, mod_claims, mod_finex, params, kind, sec, Sv):
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": "android5.7.0",
                "adj_signing_id": "1500000", "headers_id": "10",
                "native_version": "5.0.0",
                "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"})
    d0w, d2w, d4w = mod_region(Sv, 0, 0, head=WIN_HEAD)
    padded, unpadded = mod_claims(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d2 = struct.pack(">I", d2w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]
    return mod_finex(descs, sec)


fails = 0
for kind, sec, Sv in (("session", 1790625704, 0xA6DA5D2B),
                      ("click", 1790625720, 0xE74F6D6D),
                      ("session", 1790341508, 0x11223344)):
    params = build_params(kind)
    blob_o, info_o = mint_with(FP.region, M.claims_for_law, M.finex_mint,
                               params, kind, sec, Sv)
    blob_s, info_s = mint_with(S.region, S.claims_for_law, S.finex_mint,
                               params, kind, sec, Sv)
    ok = blob_o == blob_s and info_o["status"] == info_s["status"]
    print("%-8s sec=%d S=%08x  orig=%s %dB  merged=%s %dB  -> %s"
          % (kind, sec, Sv, info_o["status"], len(blob_o),
             info_s["status"], len(blob_s), "MATCH" if ok else "MISMATCH"))
    if not ok:
        fails += 1
        for i in range(0, 192, 4):
            if blob_o[i:i+4] != blob_s[i:i+4]:
                print("  dword %d: %s vs %s"
                      % (i // 4, blob_o[i:i+4].hex(), blob_s[i:i+4].hex()))
                break
print("RESULT:", "ALL MATCH — merged signer is byte-identical" if not fails
      else "%d FAILURES" % fails)
sys.exit(1 if fails else 0)

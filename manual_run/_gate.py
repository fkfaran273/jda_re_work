"""Correctness gate + benchmark for adj9_signature.py.

Usage:
    python -u _gate.py mint  [out.json]   # mint known blobs (seed pinned)
    python -u _gate.py check [in.json]    # re-mint and demand 192/192 identical
    python -u _gate.py bench              # timing only, no files
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_signature as S

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 0xDEADBEEF
SECOND = 1759000000            # pinned so the header law is deterministic
T_CLICK = 1759000000
GAID = "e1f2a3b4c5d6e7f8"
UUID = "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"


def load_cfg():
    with open(os.path.join(HERE, "apps.json"), encoding="utf-8") as fh:
        cfg = dict(json.load(fh)["penti"])
    # Pin the signing-critical fields to the values _gold.json was minted
    # with, so the gate keeps testing the SIGNER even if apps.json or
    # HEAD_PHASE_BY_APP_TOKEN are edited underneath it.
    cfg.update({
        "package_name": "com.penti.app",
        "app_token": "jut9tib0eo",
        "cert_sha1": "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
        "sdk_version": "5.7.0",
        "client_sdk": "android5.7.0",
        "native_version": "5.0.0",
        "adj_signing_id": "1500000",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "head_phase": ["0x2b", "0x48"],
    })
    return cfg


def make(kind):
    cfg = load_cfg()
    S.configure_app(cfg)
    with open(os.path.join(HERE, "device_data.json"), encoding="utf-8") as fh:
        dev = json.load(fh)
    campaign = cfg
    if kind == "session":
        return S.build_session_request(GAID, UUID, dev, campaign, T_CLICK)
    return S.build_click_request(GAID, UUID, dev, campaign, T_CLICK,
                                  "https://play.google.com/store/apps/details"
                                  "?id=com.penti.app&referrer=utm_source%3Dgoogle")


def mint_one(kind):
    params = make(kind)
    blob, sec, info = S.sign_request(params, kind, second=SECOND, seed=SEED)
    assert len(blob) == 192, len(blob)
    return blob.hex(), sec, info


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "_gold.json")

    if mode == "bench":
        for kind in ("session", "click"):
            t = time.perf_counter()
            blob, sec, info = S.sign_request(make(kind), kind,
                                             second=SECOND, seed=SEED)
            dt = time.perf_counter() - t
            print("%-8s %7.3f s  steps=%-12d status=%-6s" %
                  (kind, dt, info["steps"], info["status"]))
        return

    got = {}
    t0 = time.perf_counter()
    for kind in ("session", "click"):
        h, sec, info = mint_one(kind)
        got[kind] = h
        print("minted %-8s %7.3f s steps=%d status=%s" %
              (kind, time.perf_counter() - t0, info["steps"], info["status"]))

    if mode == "mint":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(got, fh, indent=1)
        print("wrote", path)
        for k, v in got.items():
            print(k, v[:64], "...")
        return

    # check
    with open(path, encoding="utf-8") as fh:
        gold = json.load(fh)
    bad = 0
    for kind in ("session", "click"):
        g = gold[kind]
        o = got[kind]
        n = sum(1 for a, b in zip(g, o) if a == b)
        ok = (g == o)
        print("%-8s %3d/192 bytes match  %s" %
              (kind, n, "OK" if ok else "*** MISMATCH ***"))
        if not ok:
            bad += 1
            print("   gold:", g)
            print("   got :", o)
    print("GATE", "PASS" if not bad else "FAIL")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

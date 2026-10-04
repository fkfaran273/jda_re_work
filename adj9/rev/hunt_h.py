#!/usr/bin/env python3
"""hunt_h.py — two-pronged attack on descriptor #4 (H, 32 B, arg3 of nSign).

Prong 1: construction sweep — is H = hash/HMAC of the captured canonical env
         with a guessable key?  Data: device/triples.json (H + env per signing),
         device/triples_fresh.json (nSign 'in' H values), aligned session H.
Prong 2: locate H's computation in the app: scan extracted APK files for
         nSign / HmacSHA256 / Mac / javax.crypto, so we can dexdump the caller.
"""
import json, hashlib, hmac, os, glob, sys

ROOT = r"C:\Users\Apps\Downloads\com.penti.app"
DEV = os.path.join(ROOT, "adj9", "device")
sys.stdout.reconfigure(line_buffering=True)

rows = json.load(open(os.path.join(DEV, "triples.json")))
print(f"[triples.json] rows={len(rows)} env_lens={sorted(set(len(r['env'])//2 for r in rows))}")
e0 = bytes.fromhex(rows[0]["env"])
print("env[0] preview:", e0[:240])
print("env[0] tail  :", e0[-120:])

pairs = [(bytes.fromhex(r["H"]), bytes.fromhex(r["env"]), r) for r in rows]
# aligned session pair (env unknown -> only usable if we rebuild claims later)
ALIGNED_H = bytes.fromhex("46cb9a96471f255bb64bd0e8e82f6a1fda7398c86fcdb8c68cc7afe313833502")
# triples_fresh 'in' values = nSign arg3 (H) for session/click/info of that burst
tf = json.load(open(os.path.join(DEV, "triples_fresh.json")))
fresh_H = [bytes.fromhex(tf[i][2]) for i in range(0, len(tf), 3)]
print(f"[triples_fresh] {len(fresh_H)} H values (nSign 'in'):", [h.hex()[:12] for h in fresh_H])
# tail7 click H
pairs.append((bytes.fromhex("732c428984eefe01ec0cbcb3e616a53fbb3d0bd12f2ea1372decdee1589ba8a3"), None, {"idx": "tail7-click"}))
pairs.append((ALIGNED_H, None, {"idx": "aligned"}))

KEYS = [b"", b"Quoh8uafohgh7CahM2h", b"KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        b"jut9tib0eeps", b"adj9", b"1500000", b"5.0.0", b"android5.7.0",
        b"com.penti.app", b"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
        bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"),
        b"adj_verification", b"1500000adj9", b"adj9jut9tib0eeps",
        b"Quoh8uafohgh7CahM2hKlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        hashlib.sha256(b"Quoh8uafohgh7CahM2h").digest(),
        hashlib.sha256(b"jut9tib0eeps").digest()]

def variants(env, r):
    if env is None:
        return []
    api = (r.get("api") or "31").encode()
    return [env, api + env, env + api, api + b"|" + env, env[::-1]]

hits = 0; tests = 0
for H, env, r in pairs:
    for m in variants(env, r):
        for k in KEYS:
            cands = [
                ("hmac-sha256", hmac.new(k, m, hashlib.sha256).digest()),
                ("sha256(k+m)", hashlib.sha256(k + m).digest()),
                ("sha256(m+k)", hashlib.sha256(m + k).digest()),
                ("sha256(m)", hashlib.sha256(m).digest()),
            ]
            tests += len(cands)
            for name, dg in cands:
                if dg == H:
                    hits += 1
                    print(f"*** HIT {name} key={k[:24]!r} row={r.get('idx')}")
print(f"[sweep] {tests} constructions tested, hits={hits}")

# ---- prong 2: find the computation in the app ----
PATS = [b"nSign", b"HmacSHA256", b"HmacSHA1", b"HmacMD5", b"javax/crypto",
        b"Mac;->getInstance", b"adj_verification", b"Signature signature="]
cands = set(glob.glob(os.path.join(ROOT, "extracted", "**", "*.dex"), recursive=True))
cands |= set(glob.glob(os.path.join(ROOT, "extracted", "**", "*.so"), recursive=True))
print(f"[scan] {len(cands)} dex/so files under extracted/")
for f in sorted(cands):
    try:
        b = open(f, "rb").read()
    except OSError:
        continue
    found = []
    for p in PATS:
        i = b.find(p)
        if i >= 0:
            found.append((p.decode(), hex(i)))
    if found:
        print("  ", os.path.relpath(f, ROOT), found)

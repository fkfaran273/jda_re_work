"""_info_search.py -- search the info claims law with the block oracle.

Known from the native lib: the signer can only query keys from its pool string
(111 names, 0x14cad0 in penti_libsigner.so).  Of the info map's 22 non-envelope
keys, only 10 are in the pool.  The claims can therefore only contain values
of: subset of those 10 (map present, non-empty) + PIN + block2.

Search:
  1. one sorted group + PIN + block2          (2^10)
  2. no PIN                                    (2^10)
  3. PIN at every slot                         (small)
  4. two sorted groups (P, T) + PIN + block2   (3^10)
"""
import itertools, json, struct, sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\manual_run")
import adj9_pure as P

rows = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\manual_run\event_vectors.json"))
info = [r for r in rows if r["map"]["activity_kind"] == "info"]
import adj9_decode as D
for r in info:
    blob = bytes.fromhex(r["blob"])
    rec = D.whiten_body_inverse(blob[16:160], blob[:16])
    r["head"] = rec[3:19]
    r["cert"] = rec[25:45]
    r["block"] = rec[46:78]
    r["seed"] = struct.unpack(">I", rec[20:24])[0]

val = info[0]["map"]
POOL10 = sorted(["adj_verification", "android_uuid", "app_token", "created_at",
                 "environment", "gps_adid", "gps_adid_src", "push_token",
                 "source", "tracking_enabled"])
PIN = "1500000"
BLOCK2 = "infoandroid5.7.0105.0.0"     # activity_kind + client_sdk + headers_id + native_version

def block_ok(claims):
    if isinstance(claims, str):
        claims = claims.encode("latin1")
    return all(P.record_block(r["head"], r["seed"], claims, r["cert"]) == r["block"]
               for r in info)

def V(keys):
    return "".join(val[k] for k in keys)

n_hits = []
# 1. sorted subset + PIN + block2
for mask in range(1 << 10):
    ks = [POOL10[i] for i in range(10) if mask >> i & 1]
    claims = V(ks) + PIN + BLOCK2
    if block_ok(claims):
        n_hits.append(("sorted+PIN", ks))

# 2. no PIN
for mask in range(1 << 10):
    ks = [POOL10[i] for i in range(10) if mask >> i & 1]
    claims = V(ks) + BLOCK2
    if block_ok(claims):
        n_hits.append(("noPIN", ks))

# 3. PIN at every slot of every sorted subset
for mask in range(1 << 10):
    ks = [POOL10[i] for i in range(10) if mask >> i & 1]
    for pos in range(len(ks) + 2):
        claims = V(ks[:pos]) + PIN + V(ks[pos:]) + BLOCK2
        if block_ok(claims):
            n_hits.append(("PIN@%d" % pos, ks))

print("searches 1-3 done, hits:", len(n_hits))
for h in n_hits[:20]:
    print("  ", h[0], h[1])

# 4. two sorted groups (P, T): sorted(P)+PIN+sorted(T)+block2, P and T disjoint
if not n_hits:
    cnt = 0
    for states in itertools.product(range(3), repeat=10):
        pk = [POOL10[i] for i in range(10) if states[i] == 0]
        tk = [POOL10[i] for i in range(10) if states[i] == 1]
        claims = V(pk) + PIN + V(tk) + BLOCK2
        cnt += 1
        if block_ok(claims):
            n_hits.append(("P/T split", (pk, tk)))
            print("HIT P/T:", pk, tk)
            break
    print("search 4 done over %d states, hits: %d" % (cnt, len(n_hits)))

if not n_hits:
    # 5. 'algorithm' pinned value "adj9" at every slot of every sorted subset
    for mask in range(1 << 10):
        ks = [POOL10[i] for i in range(10) if mask >> i & 1]
        base = [V(ks[:p]) for p in range(len(ks) + 1)]
        for pos in range(len(ks) + 1):
            claims = V(ks[:pos]) + "adj9" + V(ks[pos:]) + PIN + BLOCK2
            if block_ok(claims):
                n_hits.append(("adj9@%d+PIN" % pos, ks))
    print("search 5 (algorithm pinned) done, hits:", len(n_hits))

print("DONE. hits:", len(n_hits))
for h in n_hits:
    print("FINAL:", h[0], h[1])

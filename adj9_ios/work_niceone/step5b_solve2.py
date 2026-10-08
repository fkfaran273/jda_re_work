"""step5b_solve2.py -- extended claims brute force: drop-subsets of suspects,
placements incl. inside the suffix."""
import sys, json, hashlib, struct, itertools

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))
PLAINS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_plains.json"))
SHA0 = hashlib.sha256(b"").digest()
Z20 = b"\x00" * 20
CLIENT_SDK = "ios5.6.2"
pool = A.CLAIMS["main"] + A.CLAIMS["rest"]
SPLIT = pool.index("session_count")


def sha_iv2(msg):
    st = list(A.IV2)
    m = (msg + bytes((128,)) + bytes((0,)) * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = A._sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return struct.pack(">8I", *st)


def block_of(head, nonce4, claims):
    return sha_iv2(Z20 + bytes((0, 8)) + head + nonce4[::-1] + SHA0 +
                   bytes((2,)) + claims)


def solve(idx, kind, suspects):
    r = RECS[idx]
    rec = bytes.fromhex(PLAINS[idx]["aes_hex"])
    head, nonce4, target = rec[3:19], rec[20:24], rec[46:78]
    params = r["params"]
    prof = [k for k in pool[:SPLIT] if params.get(k) not in (None, "") and k not in suspects]
    tail = [k for k in pool[SPLIT:] if params.get(k) not in (None, "") and k not in suspects]
    vals = [str(params[k]) for k in prof] + ["1400000"] + [str(params[k]) for k in tail]
    kind_s, sdk_s, h_s, nv_s = kind, CLIENT_SDK, "9", "3.67.0"
    svals = [str(params[k]) for k in suspects if params.get(k)]
    n = len(vals)
    # slots: 0..n between values; n+1..n+4 inside the suffix
    slots = list(range(n + 1)) + [n + 1, n + 2, n + 3, n + 4]
    found = []
    # drop-all
    if block_of(head, nonce4, ("".join(vals) + kind_s + sdk_s + h_s + nv_s).encode("latin1")) == target:
        found.append(("drop-all", None))
    for r3 in range(1, len(svals) + 1):
        for sub in itertools.combinations(range(len(svals)), r3):
            for perm in itertools.permutations(sub):
                for combo in itertools.combinations(slots, len(perm)):
                    parts = list(vals)
                    for pos, vi in zip(sorted(combo, reverse=True), perm):
                        parts.insert(pos, svals[vi])
                    s = "".join(parts) + kind_s + sdk_s + h_s + nv_s
                    if block_of(head, nonce4, s.encode("latin1")) == target:
                        found.append(([svals[vi] for vi in perm], combo))
                        return found, (vals, svals, n)
    return found, (vals, svals, n)


print("rec6 (event), suspects event_count/event_token/seq:")
f, info = solve(6, "event", ["event_count", "event_token", "seq"])
print("  ->", f if f else "NO HIT")

print("rec4 (session), suspects session_length/subsession_count/time_spent:")
f4, info4 = solve(4, "session", ["session_length", "subsession_count", "time_spent"])
print("  ->", f4 if f4 else "NO HIT")

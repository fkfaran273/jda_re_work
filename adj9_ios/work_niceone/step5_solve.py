"""step5_solve.py -- (a) head law hunt: adj9-iOS d0 generator over all phases;
(b) claims placement brute force for the failing records (rec4, rec6..17)."""
import sys, json, hashlib, struct, itertools

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios")
import adj9ios_pure as P

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))
PLAINS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_plains.json"))
SHA0 = hashlib.sha256(b"").digest()
Z20 = b"\x00" * 20
CLIENT_SDK = "ios5.6.2"

pool = A.CLAIMS["main"] + A.CLAIMS["rest"]
SPLIT = pool.index("session_count")


def claims_template(params, kind, drop=()):
    prof = [k for k in pool[:SPLIT] if params.get(k) not in (None, "") and k not in drop]
    tail = [k for k in pool[SPLIT:] if params.get(k) not in (None, "") and k not in drop]
    vals = [str(params[k]) for k in prof] + ["1400000"] + [str(params[k]) for k in tail]
    suffix = kind + CLIENT_SDK + "9" + "3.67.0"
    return vals, suffix


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


# ---------------- (a) head law: adj9-iOS d0 over all phases ----------------
print("== head law hunt (adj9-iOS d0 generator, all single-byte phases) ==")
head_hit = None
rec0 = bytes.fromhex(PLAINS[0]["aes_hex"])
n0 = rec0[20:24]
S0 = int.from_bytes(n0, "big")
for ph in range(256):
    try:
        h = P.head16_for(S0, head=(ph,))
    except Exception:
        break
    if h == rec0[3:19]:
        head_hit = ph
        print(f"  MATCH: phase 0x{ph:02x}")
        break
if head_hit is None:
    print("  no single-byte phase match on rec0")
    # try the pure cycle (no prefix override) and Android head_for as sanity
    print("  pure-cycle:", P.head16_for(S0).hex(), " target:", rec0[3:19].hex())

# ---------------- (b) claims placement brute force ----------------
def solve(idx, kind, suspects):
    """Brute force: place suspect values at any distinct positions of the
    confirmed template (or drop them)."""
    r = RECS[idx]
    rec = bytes.fromhex(PLAINS[idx]["aes_hex"])
    head, nonce4, target = rec[3:19], rec[20:24], rec[46:78]
    params = r["params"]
    vals, suffix = claims_template(params, kind, drop=suspects)
    svals = [str(params[k]) for k in suspects if params.get(k)]
    n = len(vals)
    slots = range(n + 1)
    found = []
    # 0) drop-all
    if block_of(head, nonce4, ("".join(vals) + suffix).encode("latin1")) == target:
        found.append(("drop-all", None))
    # 1) placements (ordered assignment of svals into slots)
    for perm in itertools.permutations(svals):
        for combo in itertools.combinations(slots, len(perm)):
            parts = list(vals)
            for pos, v in zip(sorted(combo, reverse=True), perm):
                parts.insert(pos, v)
            if block_of(head, nonce4, ("".join(parts) + suffix).encode("latin1")) == target:
                found.append((perm, combo))
    return found


print("\n== claims placement brute force ==")
sus_events = ["event_count", "event_token", "seq"]
f6 = solve(6, "event", sus_events)
print("rec6 (event):", f6 if f6 else "NO HIT")
sus4 = ["session_length", "subsession_count", "time_spent"]
f4 = solve(4, "session", sus4)
print("rec4 (session):", f4 if f4 else "NO HIT")

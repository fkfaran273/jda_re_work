"""step7_event_hunt.py -- comprehensive claims search for rec6 (event)."""
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


rec = bytes.fromhex(PLAINS[6]["aes_hex"])
head, nonce4, target = rec[3:19], rec[20:24], rec[46:78]
p = RECS[6]["params"]

fired_prof = [k for k in pool[:SPLIT] if p.get(k) not in (None, "")]
fired_tail = [k for k in pool[SPLIT:] if p.get(k) not in (None, "")]
fired = fired_prof + fired_tail
print("fired pool keys (%d):" % len(fired))


def claims_with(vals_override=None, drop=(), kind="event",
               extra_ins=None, suffix_override=None):
    ov = vals_override or {}
    vals = [str(ov.get(k, p[k])) for k in fired_prof if k not in drop] + \
           ["1400000"] + \
           [str(ov.get(k, p[k])) for k in fired_tail if k not in drop]
    base = "".join(vals)
    if extra_ins:
        base = extra_ins[0] + base  # placeholder, handled by caller
    if suffix_override is not None:
        return (base + suffix_override).encode("latin1")
    return (base + kind + CLIENT_SDK + "9" + "3.67.0").encode("latin1")


tried = 0
hit = None

# A: kind variants
for kind in ("event", "Event", "EVENT", "sdk_event", "info", ""):
    tried += 1
    if block_of(head, nonce4, claims_with(kind=kind)) == target:
        hit = ("kind", kind)

# B: leave-one/two/three-out drops
for r in (1, 2, 3):
    if hit:
        break
    for drop in itertools.combinations(fired, r):
        tried += 1
        if block_of(head, nonce4, claims_with(drop=drop)) == target:
            hit = ("drop", drop)
            break

# C: value drift on counters
if not hit:
    for seq in ("0", "1", "2", "3"):
        for ec in ("0", "1", "2", "3"):
            for sc in ("1", "2"):
                tried += 1
                ov = {"seq": seq, "event_count": ec, "session_count": sc}
                if block_of(head, nonce4, claims_with(vals_override=ov)) == target:
                    hit = ("drift", ov)
                    break
                if hit:
                    break
            if hit:
                break

# D: duplicate event_token insertion at every slot of the base
if not hit:
    et = p["event_token"]
    base0 = claims_with().decode("latin1")
    # remove event_token from base0 first (it fires once), then re-insert 2x
    b0 = base0.replace(et, "", 1)
    b1 = base0  # keeps pool event_token
    for pos in range(len(b0) + 1):
        tried += 1
        cand = b1[:pos] + et + b1[pos:]
        if block_of(head, nonce4, cand.encode("latin1")) == target:
            hit = ("dup_event_token@", pos)
            break

print(f"tried {tried} candidates -> hit: {hit}")

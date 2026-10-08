"""step6_solve3.py -- rec4 with kind=sdk_info; events with kind/value drift."""
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


def build(params, kind, overrides=None, drop=()):
    ov = overrides or {}
    prof = [k for k in pool[:SPLIT] if params.get(k) not in (None, "") and k not in drop]
    tail = [k for k in pool[SPLIT:] if params.get(k) not in (None, "") and k not in drop]
    vals = [str(ov.get(k, params[k])) for k in prof] + ["1400000"] + \
           [str(ov.get(k, params[k])) for k in tail]
    return "".join(vals) + kind + CLIENT_SDK + "9" + "3.67.0"


def ctx(idx):
    rec = bytes.fromhex(PLAINS[idx]["aes_hex"])
    return rec[3:19], rec[20:24], rec[46:78], RECS[idx]["params"]


# ---- rec4 as sdk_info ----
head, nonce4, target, p4 = ctx(4)
for kind in ("sdk_info", "session", "click", "info"):
    c = build(p4, kind)
    ok = block_of(head, nonce4, c.encode("latin1")) == target
    print(f"rec4 kind={kind!r}: {ok}")
    if ok:
        break

# ---- rec6 events: kind x value drift ----
head6, nonce46, target6, p6 = ctx(6)
kinds = ("event", "Event", "sdk_event", "event ")
drift = {
    "seq": ["1", "0", "2"],
    "event_count": ["1", "0", "2"],
    "session_count": ["1", "2"],
    "subsession_count": ["2", "1", "3"],
    "time_spent": ["110", "0"],
    "session_length": ["112", "0"],
}
keys = list(drift)
print("\nrec6: kind x small value-drift grid:")
hit = None
for kind in kinds:
    for combo in itertools.product(*(drift[k] for k in keys)):
        ov = dict(zip(keys, combo))
        if block_of(head6, nonce46, build(p6, kind, ov).encode("latin1")) == target6:
            hit = (kind, ov)
            print("  HIT:", hit)
            break
    if hit:
        break
if not hit:
    print("  no hit in drift grid")

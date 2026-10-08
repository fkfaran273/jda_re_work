"""step4_block.py -- head law + BLOCK law + claims law on the iOS adj8 records.

iOS record (128 B), from the dumps:
  01 00 08 | head(16) | 02 | nonce4(4) | 03 | ZEROS(20) | 04 | BLOCK(32)
  | 05 | SHA0(32) | 06 | 02 | 0f*15
BLOCK = sha256_iv2(ZEROS || 00 08 || head || rev4(nonce4) || SHA0 || 02 || claims)
claims = pool<session_count + "1400000" + pool>=session_count + kind +
         client_sdk("ios5.6.2") + "9" + "3.67.0"
"""
import sys, json, hashlib

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))
PLAINS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_plains.json"))
SECONDS = {0: 1778042980, 1: 1778042981, 2: 1778042985, 3: 1778043093,
           4: 1778043093, 5: 1778043101, 6: 1778043702, 7: 1778043726,
           8: 1778043824, 9: 1778043853, 10: 1778043961, 11: 1778043994,
           12: 1778044005, 13: 1778044450, 14: 1778044803, 15: 1778044820,
           16: 1778044903, 17: 1778044720}
# kind from the wire/endpoint
KIND = {0: "session", 1: "click", 2: "attribution", 3: "click", 4: "session",
        5: "click"}
for i in range(6, 18):
    KIND[i] = "event"

SHA0 = hashlib.sha256(b"").digest()
Z20 = b"\x00" * 20
CLIENT_SDK = "ios5.6.2"

pool = A.CLAIMS["main"] + A.CLAIMS["rest"]
SPLIT = pool.index("session_count")


def build_claims(params, kind):
    prof = [k for k in pool[:SPLIT] if params.get(k) not in (None, "")]
    tail = [k for k in pool[SPLIT:] if params.get(k) not in (None, "")]
    parts = [str(params[k]) for k in prof] + ["1400000"] + \
            [str(params[k]) for k in tail]
    return ("".join(parts) + kind + CLIENT_SDK + "9" + "3.67.0").encode("latin1")


def block_ios(head, nonce4, claims):
    msg = (Z20 + bytes((0, 8)) + head + nonce4[::-1] + SHA0 +
           bytes((2,)) + claims)
    st = list(A.IV2)
    m = (msg + bytes((128,)) + bytes((0,)) * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8)) if False else None
    import struct
    m = (msg + bytes((128,)) + bytes((0,)) * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = A._sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return struct.pack(">8I", *st)


import struct

print(f"{'rec':>4} {'kind':<12} {'head_ok':<8} {'layout_ok':<10} {'block_ok'}")
ok_h = ok_l = ok_b = 0
claims_lens = []
for pl, r in zip(PLAINS, RECS):
    i = pl["i"]
    rec = bytes.fromhex(pl["aes_hex"])
    head, nonce4 = rec[3:19], rec[20:24]
    head_ok = A.head_for(nonce4) == head
    ok_h += head_ok
    layout_ok = (rec[0:3] == b"\x01\x00\x08" and rec[19] == 2 and
                 rec[24] == 3 and rec[25:45] == Z20 and rec[45] == 4 and
                 rec[78] == 5 and rec[79:111] == SHA0 and rec[111] == 6 and
                 rec[112] == 2 and set(rec[113:]) <= {0x0f})
    ok_l += layout_ok
    claims = build_claims(r["params"], KIND[i])
    claims_lens.append(len(claims))
    blk = block_ios(head, nonce4, claims)
    block_ok = blk == rec[46:78]
    ok_b += block_ok
    print(f"{i:>4} {KIND[i]:<12} {str(head_ok):<8} {str(layout_ok):<10} {block_ok}"
          + ("" if block_ok else f"   got={rec[46:78].hex()} want={blk.hex()}"))

print(f"\nhead law: {ok_h}/18   layout: {ok_l}/18   BLOCK+claims law: {ok_b}/18")
print("claims lengths:", claims_lens)

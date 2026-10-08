"""step3_record.py -- the decrypted 128-B records: layout, head law, cert
field, BLOCK law vs the adj8-Android recipe, claims string hunt."""
import sys, json, hashlib, struct

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))
PLAINS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_plains.json"))
SECONDS = {0: 1778042980, 1: 1778042981, 2: 1778042985, 3: 1778043093,
           4: 1778043093, 5: 1778043101, 6: 1778043702, 7: 1778043726,
           8: 1778043824, 9: 1778043853, 10: 1778043961, 11: 1778043994,
           12: 1778044005, 13: 1778044450, 14: 1778044803, 15: 1778044820,
           16: 1778044903, 17: 1778044720}
KIND = {0: "session", 1: "click", 2: "attribution", 3: "click", 4: "session",
        5: "click", 6: "event", 7: "event", 8: "event", 9: "event",
        10: "event", 11: "event", 12: "event", 13: "event", 14: "event",
        15: "event", 16: "event", 17: "event"}

SHA0 = hashlib.sha256(b"").digest()

print("== record layout (adj8 Android offsets) ==")
print(f"{'rec':>4} {'head[3:19]==head_for(nonce4)':<30} {'nonce4':<10} "
      f"{'cert[25:45]':<44} {'r112':<5} {'r113':<5} {'tail[114:]'}")
out = []
for pl, r in zip(PLAINS, RECS):
    rec = bytes.fromhex(pl["spn_hex"])
    nonce4 = rec[20:24]
    head = rec[3:19]
    head_ok = A.head_for(nonce4) == head
    cert = rec[25:45]
    tags = dict(t19=rec[19], t24=rec[24], t45=rec[45], t78=rec[78],
                t111=rec[111], sha0=rec[79:111] == SHA0)
    out.append({"i": pl["i"], "record_hex": pl["spn_hex"],
                "head_ok": head_ok, "nonce4": nonce4.hex(),
                "cert": cert.hex(), "r112": rec[112], "r113": rec[113]})
    print(f"{pl['i']:>4} {str(head_ok):<30} {nonce4.hex():<10} {cert.hex()} "
          f"{rec[112]:#04x} {rec[113]:#04x} {rec[114:118].hex()}... "
          f"allzero={set(rec[114:]) <= {0x0f}} tags={tags}")

ok = sum(o["head_ok"] for o in out)
print(f"\nhead law (adj8 head_for(nonce4)): {ok}/18")
certs = set(o["cert"] for o in out)
print("distinct cert fields:", len(certs))
for c in certs:
    print("  ", c)

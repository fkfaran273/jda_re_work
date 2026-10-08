"""Find the event claims transformation against the KNOWN 13:00 event
(exact nSign map + device H + nonce12 + cert40)."""
import itertools
import json
import sys

ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
import adj7_pure as ap

T = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))["4"]
nmap = T["nmap"]
H = T["H"]
nonce12 = bytes.fromhex(T["nonce12"])
cert40 = T["cert40"].encode()

SPLIT = ap.CLAIM_POOL.index("session_count")
POOL = ap.CLAIM_POOL


def claims_of(m, use_id=True, block2=True):
    parts = [str(m[k]) for k in POOL[:SPLIT] if m.get(k) not in (None, "")]
    if use_id:
        parts.append(ap.ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in POOL[SPLIT:-2] if m.get(k) not in (None, "")]
    if block2:
        parts += [str(m.get("activity_kind", "")), str(m.get("client_sdk", ""))]
    return "".join(parts)


def hit(cl, tag, found):
    if ap.commitment_digest(cl.encode("latin1"), nonce12, cert40).hex().upper() == H:
        print("!!! MATCH: %s" % tag)
        print("    claims = %r" % cl)
        found.append((tag, cl))


found = []

# 0) sanity: 4 combos
for uid in (True, False):
    for b2 in (True, False):
        cl = claims_of(nmap, uid, b2)
        hit(cl, "base id=%s block2=%s" % (uid, b2), found)

# 1) exclude one pool key (keep id/block2 per combo)
for k in POOL[:SPLIT] + POOL[SPLIT:-2]:
    if nmap.get(k) in (None, ""):
        continue
    m2 = {x: v for x, v in nmap.items() if x != k}
    for uid in (True, False):
        for b2 in (True, False):
            hit(claims_of(m2, uid, b2), "drop %s id=%s b2=%s" % (k, uid, b2), found)

# 2) append one extra value at the end (after block2)
extra_vals = {}
for k, v in nmap.items():
    if k not in POOL:
        extra_vals["%s=%s" % (k, v)] = str(v)
extra_vals["endpoint"] = "https://app.adjust.com"
extra_vals["lang_en"] = "en"
extra_vals["empty"] = ""
for tag, v in extra_vals.items():
    for uid in (True, False):
        for b2 in (True, False):
            cl = claims_of(nmap, uid, b2) + v
            hit(cl, "append %s id=%s b2=%s" % (tag, uid, b2), found)

# 3) insert extra value BEFORE block2
for tag, v in extra_vals.items():
    if v == "":
        continue
    for uid in (True, False):
        cl = claims_of(nmap, uid, block2=False) + v \
            + str(nmap.get("activity_kind", "")) + str(nmap.get("client_sdk", ""))
        hit(cl, "preblock2 %s id=%s" % (tag, uid), found)

# 4) float-formatted numerics: session_length/time_spent/event_count/seq as x.0
import re as _re
for k in ("session_length", "time_spent", "event_count", "seq", "session_count",
          "subsession_count"):
    if k in nmap and _re.match(r"^\d+$", str(nmap[k])):
        m2 = dict(nmap)
        m2[k] = str(nmap[k]) + ".0"
        for uid in (True, False):
            for b2 in (True, False):
                hit(claims_of(m2, uid, b2), "%s=.0 id=%s b2=%s" % (k, uid, b2), found)

# 5) pairs of appends (before block2), from a shortlist
short = ["en", "https://app.adjust.com", nmap["sent_at"], nmap["wait_total"],
         nmap["wait_time"], "0.0", "1", "0"]
for a, b in itertools.product(short, repeat=2):
    cl = claims_of(nmap, True, False) + a + b \
        + str(nmap.get("activity_kind", "")) + str(nmap.get("client_sdk", ""))
    hit(cl, "preblock2 pair %r+%r" % (a, b), found)

print("done, matches:", len(found))
for tag, cl in found:
    print("  -", tag)

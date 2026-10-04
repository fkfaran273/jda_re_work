# nsign_cipher.py — full JCA event dump INSIDE one nSign window (oracle_run3 run)
# Goal: reconstruct the 176-byte body construction from logged cipher in/out.
import re, sys, base64

def parse_events(path):
    ev, cur = [], None
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\S+) ts=(\d+)", ln)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            ev.append(cur); continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"): cur = None; continue
            cur["body"].append(ln.rstrip("\n"))
    return ev

def txt(e): return "\n".join(e["body"])

def fld(e, name):
    m = re.search(r"^" + name + r"=(.*)$", txt(e), re.M)
    return m.group(1) if m else None

def hx(e, name):
    v = fld(e, name)
    return bytes.fromhex(v) if v else None

path = sys.argv[1] if len(sys.argv) > 1 else "C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run3.log"
ev = parse_events(path)
# find nsign_in with rich inner activity, then dump until 'nsign'
best, bestlen, i = None, 0, 0
while i < len(ev):
    if ev[i]["type"] == "nsign_in":
        j = i + 1
        while j < len(ev) and ev[j]["type"] != "nsign": j += 1
        if j < len(ev):
            inner = ev[i+1:j]
            if len(inner) > bestlen:
                bestlen, best = len(inner), (i, j)
        i = j
    else:
        i += 1

i, j = best
print("nSign window: events %d..%d  t=%d" % (i, j, ev[i]["ts"]))
blob = hx(ev[j], "hex")
print("nSign return (192B):", blob.hex() if blob else "?", "\n")
inner = ev[i+1:j]
for e in inner:
    t = e["type"]; T = txt(e)
    ts = e["ts"]
    if t == "jca_cipher_getInstance":
        print("[%d] CIPHER.getInstance  %s" % (ts, fld(e, "alg")))
    elif t == "jca_cipher_init":
        print("[%d] CIPHER.init  %s" % (ts, fld(e, "mode")))
    elif t == "jca_secretkeyspec_init":
        k = hx(e, "hex") or hx(e, "key")
        print("[%d]   SecretKeySpec key=%s (%d B) alg=%s" % (ts, (k.hex() if k else fld(e,"key")), len(k) if k else 0, fld(e, "alg")))
    elif t == "jca_cipher_doFinal":
        fin = hx(e, "hex_in") or b""
        out = hx(e, "hex") or hx(e, "out") or hx(e, "hex_out") or b""
        print("[%d]   doFinal in=%d B %s..." % (ts, len(fin), fin[:24].hex()))
        print("           out=%d B %s" % (len(out), out.hex() if out else T[:120]))
    elif t == "jca_md_getInstance":
        print("[%d] MD.getInstance %s" % (ts, fld(e, "alg")))
    elif t == "jca_md_update":
        u = hx(e, "hex")
        print("[%d]   md.update len=%d %s" % (ts, len(u) if u else 0, (u[:40].hex() + "...") if u else T[:100]))
    elif t == "jca_md_digest":
        o = fld(e, "hex")
        pre = hx(e, "hex_in")
        # 'text:' line has out= and hex= digest
        print("[%d]   md.digest %s %s" % (ts, ("in=" + pre.hex()[:40] + "...") if pre else "", o))
    elif t == "jca_md_digest_b":
        print("[%d]   md.digest_b %s" % (ts, T[:150]))
    elif t == "jca_mac_getInstance":
        print("[%d] MAC.getInstance %s" % (ts, fld(e, "alg")))
    elif t == "jca_mac_init":
        print("[%d]   mac.init %s" % (ts, fld(e, "key")))
    elif t == "jca_mac_doFinal":
        print("[%d]   mac.doFinal in=%s out=%s" % (ts, fld(e, "in"), fld(e, "hex")))
    elif t in ("jca_ks_getInstance", "jca_ks_load", "jca_ks_getKey", "jca_ks_keyinfo", "jca_ks_containsAlias"):
        print("[%d] KS %s  %s" % (ts, t, T[:100]))
    else:
        print("[%d] %s  %s" % (ts, t, T[:160]))

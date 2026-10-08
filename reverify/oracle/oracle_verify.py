"""Runtime oracle verification: parse ADJ7ORACLE lines (BUILD=adj7-rv2)
from the logcat/daemon log and verify, per captured signing:

  1. tag    HMAC law
  2. invert body -> record (nonce + cert40 + H recovered)
  3. header = bionic rand(second), second brute-forced from the map's
     created_at/sent_at
  4. H == custom-IV sha256(cert40-ASCII || nonce || sha0hex || claims)
     where claims = OUR 98-key pool order over THE ORACLE'S OWN MAP
     (non-pool keys skipped automatically)  -> RUNTIME pool proof
  5. full remint byte-exact vs the blob the device just produced

Also dumps the runtime map key set per signing (vs CLAIM_POOL membership).

Usage: python oracle_verify.py [logfile]   (default: rv_logcat2.txt)
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, ".."))
from verify_from_scratch import (CLAIM_POOL, build_claims, cbc_decrypt,
                                 make_header, sha256_custom_iv, REQ_RE,
                                 SHA0_HEX)
import hashlib
import hmac

DK37 = bytes.fromhex(
    "2a4cc07960d647623cc386dcefafbf25"
    "b669914d32cc8585a1ed7f920ef591eb")

LINE_RE = re.compile(r"ADJ7ORACLE: (.*)$")
TID_RE = re.compile(r"^\[ \S+\s+\d+:\s*(\d+):\s*(\d+)\s")   # [ ts uid: pid: tid


def parse_log(path):
    """Thread-aware: the SDK pipelines session+click signings CONCURRENTLY
    (different tids, interleaved lines) -- blocks split by tid."""
    blocks = []          # NSIGN blocks (MAP/KEY2/BLOB), if any
    signs = []           # SIGN blocks (ACT/GLOB/OUT)
    cur = {}             # tid -> NSIGN block being built
    scur = {}            # tid -> SIGN block being built
    seq = []             # (order, kind, tid) to emit in BEGIN order
    order = 0
    for raw in open(path, encoding="utf-8", errors="replace"):
        m = LINE_RE.search(raw)
        if not m:
            continue
        msg = m.group(1).rstrip()
        tm = TID_RE.match(raw)
        tid = tm.group(2) if tm else "-"
        # ---- SIGN blocks (Signer.sign: ACT/GLOB/OUT) ----
        if msg.startswith("SIGN BEGIN"):
            scur[tid] = {"pkg": msg.split("pkg=")[-1], "act": {},
                         "act_order": [], "glob": {}, "glob_order": [],
                         "out": {}, "_order": order}
            order += 1
        elif msg.startswith("ACT SIZE") and tid in scur:
            scur[tid]["act_size_decl"] = int(msg.split()[-1])
        elif msg.startswith("ACT ") and tid in scur:
            body = msg[4:]
            _i, rest = body.split(" ", 1)
            k, _, v = rest.partition("=")
            k = k.strip()
            if k not in scur[tid]["act"]:
                scur[tid]["act_order"].append(k)
            scur[tid]["act"][k] = v
        elif msg.startswith("GLOB SIZE") and tid in scur:
            scur[tid]["glob_size_decl"] = int(msg.split()[-1])
        elif msg.startswith("GLOB ") and tid in scur:
            body = msg[5:]
            _i, rest = body.split(" ", 1)
            k, _, v = rest.partition("=")
            k = k.strip()
            if k not in scur[tid]["glob"]:
                scur[tid]["glob_order"].append(k)
            scur[tid]["glob"][k] = v
        elif msg.startswith("OUT SIZE") and tid in scur:
            scur[tid]["out_size_decl"] = int(msg.split()[-1])
        elif msg.startswith("OUT ") and tid in scur:
            body = msg[4:]
            _i, rest = body.split(" ", 1)
            k, _, v = rest.partition("=")
            scur[tid]["out"][k.strip()] = v
        elif msg.startswith("SIGN END") and tid in scur:
            b = scur.pop(tid)
            b.pop("_order", None)
            b["_begin_order"] = len(signs)
            signs.append(b)
            continue
        # ---- NSIGN blocks (nSign: MAP/KEY2/BLOB) ----
        if msg.startswith("NSIGN BEGIN"):
            cur[tid] = {"pkg": msg.split("pkg=")[-1], "map": {},
                        "map_order": [], "key2": None, "level": None,
                        "blob_hex": ""}
        elif msg.startswith("MAP SIZE") and tid in cur:
            cur[tid]["map_size_decl"] = int(msg.split()[-1])
        elif msg.startswith("MAP ") and tid in cur:
            body = msg[4:]
            i, rest = body.split(" ", 1)
            k, _, v = rest.partition("=")
            k = k.strip()
            if k not in cur[tid]["map"]:
                cur[tid]["map_order"].append(k)
            cur[tid]["map"][k] = v
        elif msg.startswith("KEY2 ") and tid in cur:
            cur[tid]["key2"] = msg.split("hex=")[-1]
        elif msg.startswith("LEVEL ") and tid in cur:
            cur[tid]["level"] = msg.split()[-1]
        elif msg.startswith("BLOB ") and tid in cur:
            cur[tid]["blob_hex"] += msg.split(" ")[2]
        elif msg.startswith("NSIGN END") and tid in cur:
            b = cur.pop(tid)
            b["len"] = int(msg.split("len=")[-1])
            blocks.append(b)
    return blocks, signs


def seconds_from_map(m):
    import calendar
    out = set()
    for k in ("created_at", "sent_at", "click_time", "click_time_server"):
        v = m.get(k)
        if not v:
            continue
        mm = re.match(r"(.*?)Z([+-]\d{4})?$", v)
        if not mm:
            continue
        from datetime import datetime, timedelta
        naive = datetime.strptime(mm.group(1).split(".")[0],
                                  "%Y-%m-%dT%H:%M:%S")
        tz = mm.group(2) or "+0000"
        sgn = 1 if tz[0] == "+" else -1
        delta = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sgn
        for base in (naive - delta, naive):
            b = int(calendar.timegm(base.timetuple()))
            out.update([b - 2, b - 1, b, b + 1, b + 2])
    return sorted(out)


def verify_sign_block(b, idx):
    """Verify one Signer.sign capture: claims from ACT+GLOB (the exact maps
    the SDK handed the signer), blob from OUT['authorization']."""
    print("== SIGN#%d  pkg=%s  act=%d glob=%d" % (
        idx, b["pkg"], len(b["act"]), len(b["glob"])))
    oks = []
    auth = b["out"].get("authorization", "")
    msig = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    if not msig:
        print("    NO authorization in OUT: %s" % b["out"])
        return 0, 1
    blob = bytes.fromhex(msig.group(1))
    ap = dict(re.findall(r'(\w+)="([^"]*)"', auth))
    oks.append(("auth-params", ap.get("algorithm") == "adj7"
                and ap.get("adj_signing_id") == "1300000"
                and ap.get("headers_id") == "8"
                and ap.get("native_version") == "3.62.0"))
    oks.append(("tag", hmac.new(DK37, blob[16:272], hashlib.sha256).digest()
                == blob[272:304]))
    rec = cbc_decrypt(blob[16:272], blob[:16])
    mr = REQ_RE.search(rec.decode("latin1", "replace"))
    oks.append(("invert+record", mr is not None))
    if mr:
        nonce = int(mr.group("A")).to_bytes(8, "little") \
            + bytes.fromhex(mr.group("D"))
        C = mr.group("C")
        fields = dict(b["act"])
        fields.update(b["glob"])
        sec = next((s for s in seconds_from_map(fields)
                    if make_header(s) == blob[:16]), None)
        oks.append(("header(second=%s)" % sec, sec is not None))
        claims = build_claims(fields, "x", None)
        H_c = sha256_custom_iv(C.encode() + nonce + SHA0_HEX.encode()
                               + claims).hex().upper()
        oks.append(("H(cert-prefix)", H_c == mr.group("H")))
        if sec is not None and H_c == mr.group("H"):
            A2 = str(int.from_bytes(nonce[0:8], "little")).rjust(20)
            j = ('{ "a":  ' + A2 + ' ,"b": "' + H_c + '","c": "' + C
                 + '","d": "' + mr.group("D") + '","e": "' + SHA0_HEX
                 + '" }\x00')
            rec2 = j.encode() + b"\x10" * (256 - len(j))
            from verify_from_scratch import cbc_encrypt
            body2 = cbc_encrypt(rec2, blob[:16])
            blob2 = blob[:16] + body2 \
                + hmac.new(DK37, body2, hashlib.sha256).digest()
            oks.append(("remint-byte-exact", blob2 == blob))
    npass = nfail = 0
    for k, v in oks:
        print("    %-28s %s" % (k, "OK" if v else "** FAIL **"))
        npass += 1 if v else 0
        nfail += 0 if v else 1
    nonpool = sorted(set(fields) - set(CLAIM_POOL)) if mr else []
    print("    act+glob keys: %d  non-pool: %s" % (len(fields),
                                                   nonpool or "none"))
    print("    record c=%s  nonce=%s" % (mr.group("C") if mr else "-",
                                         nonce.hex() if mr else "-"))
    print()
    return npass, nfail


def verify(blocks, signs=None):
    npass = nfail = 0
    for bi, b in enumerate(blocks):
        print("== block %d  pkg=%s  map=%d keys  key2=%s"
              % (bi, b["pkg"], len(b["map"]),
                 (b["key2"] or "")[:16]))
        keys = set(b["map"])
        nonpool = sorted(keys - set(CLAIM_POOL))
        print("   non-pool keys in runtime map: %s" % (nonpool or "none"))
        blob = bytes.fromhex(b["blob_hex"])
        oks = []
        oks.append(("tag", hmac.new(DK37, blob[16:272],
                                    hashlib.sha256).digest()
                    == blob[272:304]))
        rec = cbc_decrypt(blob[16:272], blob[:16])
        mr = REQ_RE.search(rec.decode("latin1", "replace"))
        oks.append(("invert+record", mr is not None))
        if mr:
            nonce = int(mr.group("A")).to_bytes(8, "little") \
                + bytes.fromhex(mr.group("D"))
            C = mr.group("C")
            sec = next((s for s in seconds_from_map(b["map"])
                        if make_header(s) == blob[:16]), None)
            oks.append(("header(second=%s)" % sec, sec is not None))
            claims = build_claims(b["map"], "x", None)  # kind in map already
            H_c = sha256_custom_iv(C.encode() + nonce + SHA0_HEX.encode()
                                   + claims).hex().upper()
            oks.append(("H(cert-prefix)", H_c == mr.group("H")))
            if sec is not None and H_c == mr.group("H"):
                A2 = str(int.from_bytes(nonce[0:8], "little")).rjust(20)
                j = ('{ "a":  ' + A2 + ' ,"b": "' + H_c + '","c": "' + C
                     + '","d": "' + mr.group("D") + '","e": "' + SHA0_HEX
                     + '" }\x00')
                rec2 = j.encode() + b"\x10" * (256 - len(j))
                from verify_from_scratch import cbc_encrypt
                body2 = cbc_encrypt(rec2, blob[:16])
                blob2 = blob[:16] + body2 \
                    + hmac.new(DK37, body2, hashlib.sha256).digest()
                oks.append(("remint-byte-exact", blob2 == blob))
        for k, v in oks:
            print("    %-28s %s" % (k, "OK" if v else "** FAIL **"))
            npass += 1 if v else 0
            nfail += 0 if v else 1
        print("   runtime map keys (%d): %s" % (len(b["map"]),
                                                ", ".join(b["map_order"])))
        print()
    print("RUNTIME ORACLE: %d OK, %d FAIL across %d signings"
          % (npass, nfail, len(blocks)))
    return npass, nfail


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        BASE, "rv_logcat4.txt")
    blocks, signs = parse_log(path)
    print("parsed %d NSIGN blocks, %d SIGN blocks from %s"
          % (len(blocks), len(signs), path))
    npass = nfail = 0
    if signs:
        for i, s in enumerate(signs):
            p, f = verify_sign_block(s, i)
            npass += p
            nfail += f
    if blocks:
        for i, b in enumerate(blocks):
            print("== NSIGN block %d (raw): map=%d keys, blob=%d hex"
                  % (i, len(b["map"]), len(b["blob_hex"])))
        with open(os.path.join(BASE, "parsed_oracle_maps.json"), "w") as f:
            json.dump({"nsign": blocks, "sign": signs}, f, indent=1)
    print("RUNTIME ORACLE: %d OK, %d FAIL" % (npass, nfail))

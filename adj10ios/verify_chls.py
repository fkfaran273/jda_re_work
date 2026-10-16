# -*- coding: utf-8 -*-
"""verify_chls.py -- carve + verify the adj7-iOS blobs from a Charles .chls.

Charles stores requests as latin-1 text chunks with binary framing
(...sq\\x00~\\x00<idx> / t\\x00<len> / q\\x00~<key>).  For every
`Signature signature="<608 hex>"` occurrence:

  1. the endpoint is the last /session /sdk_click /attribution /event ...
     token in the 2.5 KB before the blob
  2. the wire map is the LAST `...&sent_at=...&...` chunk before the blob
     containing app_token= (query for GETs, body for POSTs)
  3. the logged response is the first JSON body chunk after the blob

Then the adj7ios law is verified per blob: tag / record / header seed
(unique second inside sent_at +- 180 s) / claims-H (kind probe) /
byte-exact mint.

    python verify_chls.py <file.chls>
"""
import json
import re
import sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7ios")
import adj7ios_pure as sg                                   # noqa: E402
from make_gold import to_epoch                              # noqa: E402

ENDPOINTS = ["sdk_click", "session", "attribution", "sdk_info", "event",
             "third_party_sharing"]
KIND_MAP = {"sdk_click": "click", "session": "session",
            "attribution": "attribution", "sdk_info": "info",
            "event": "event", "third_party_sharing": "third_party_sharing"}

URLCH = set("=%&_.-+~:?")
ASCII_OK = set("abcdefghijklmnopqrstuvwxyz"
               "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def _urlchar(ch):
    # ASCII only: str.isalnum() is True for latin-1 letters, which here are
    # payload bytes, not query characters.
    return ch in ASCII_OK or ch in URLCH


def carve_chunk(raw, pos):
    """The urlencoded buffer containing pos, minus Charles framing keys."""
    st = pos
    while st > 0 and _urlchar(raw[st - 1]):
        st -= 1
    en = pos
    while en < len(raw) and _urlchar(raw[en]):
        en += 1
    if en < len(raw) and raw[en] < " ":
        j, n = en, 0
        while n < 3 and j > 0 and "a" <= raw[j - 1] <= "z":
            j -= 1
            n += 1
        if n:
            en = j
    return raw[st:en]


def parse_params(q):
    import urllib.parse as up
    # a GET chunk may swallow the URL path prefix ("attribution?bundle_id=")
    q = re.sub(r"^[a-z_]+\?", "", q)
    return dict(up.parse_qsl(q, keep_blank_values=True))


def find_map(raw, pos):
    """Last body/query chunk before pos that carries app_token= + sent_at=."""
    best = None
    for m in re.finditer(r"app_token=", raw[:pos]):
        q = carve_chunk(raw, m.start())
        if "sent_at=" in q and q.count("&") >= 6:
            best = (m.start(), q)
    return best


def find_response(raw, pos):
    """First parseable JSON body chunk after pos."""
    for m in re.finditer(r"\{", raw[pos:pos + 4000]):
        s = pos + m.start()
        e = s
        depth = 0
        while e < len(raw) and e - s < 4000:
            if raw[e] == "{":
                depth += 1
            elif raw[e] == "}":
                depth -= 1
                if depth == 0:
                    break
            e += 1
        try:
            j = json.loads(raw[s:e + 1])
        except ValueError:
            continue
        if isinstance(j, dict) and ("app_token" in j or "attribution" in j
                                    or "ask_in" in j):
            return j, s
    return None, None


def main(path):
    raw = open(path, "rb").read().decode("latin-1")
    sdks = re.findall(r"[A-Za-z0-9.\-]{0,24}@ios[0-9.]+", raw)
    sdk = max(sdks, key=len) if sdks else ""
    out = []
    for i, m in enumerate(re.finditer(r'Signature signature="([0-9A-Fa-f]+)"',
                                      raw)):
        sig = m.group(1)
        if len(sig) != 608:
            continue
        back = raw[max(0, m.start() - 2500):m.start()]
        eps = [e for e in ENDPOINTS if ("/" + e) in back]
        endpoint = eps[-1] if eps else "?"
        mp = find_map(raw, m.start())
        if not mp:
            print("hit %d: no wire map found" % i)
            continue
        params = parse_params(mp[1])
        resp, _ = find_response(raw, m.end())
        out.append({"hit": i, "endpoint": endpoint, "params": params,
                    "sig": sig, "sdk": sdk, "response": resp,
                    "sent_at": params.get("sent_at")})

    print("%s: %d adj7 blobs, client-sdk %r\n" % (path, len(out), sdk))
    n_ok = 0
    for r in out:
        blob = bytes.fromhex(r["sig"])
        line = {"hit": r["hit"], "endpoint": r["endpoint"]}
        line["L1_tag"] = sg.verify_tag(blob)
        plain = sg.cbc_decrypt(blob[16:272], blob[:16])
        mm = re.match(sg.RECORD_RE, plain)
        line["L2_record"] = bool(mm) and plain.endswith(b"\x10" * 16) \
            and mm.group(3) == sg.CERT40_IOS
        if not mm:
            print(line, "RECORD FAIL")
            continue
        nonce12 = (int(mm.group(1).decode().strip()).to_bytes(8, "little")
                   + bytes.fromhex(mm.group(4).decode()))
        rec_h = mm.group(2).decode()
        sent = to_epoch(r["sent_at"])
        secs = [s for s in range(int(sent) - 180, int(sent) + 181)
                if sg.make_header(s) == blob[:16]]
        line["L3_secs"] = secs
        kinds = ([KIND_MAP[r["endpoint"]]]
                 if r["endpoint"] in KIND_MAP else
                 list(KIND_MAP.values()))
        hit = None
        for kind in kinds:
            claims = sg.build_claims(kind, r["params"], client_sdk=r["sdk"])
            if sg.commitment_digest(claims, nonce12).hex().upper() == rec_h:
                hit = (kind, claims)
                break
        line["L4_kind"] = hit[0] if hit else None
        line["L5_exact"] = bool(hit) and len(secs) == 1 and sg.sign(
            secs[0], nonce12, hit[1]).hex().upper() == r["sig"]
        n_ok += bool(line["L5_exact"])
        print("hit %d %-12s L1=%s L2=%s secs=%s kind=%s BYTE-EXACT=%s"
              % (line["hit"], line["endpoint"], line["L1_tag"],
                 line["L2_record"], line["L3_secs"], line["L4_kind"],
                 line["L5_exact"]))
        if r["response"]:
            a = r["response"].get("attribution")
            if a:
                print("     logged: tracker=%s network=%s campaign=%s "
                      "engage=%s installed=%s"
                      % (a.get("tracker_token"), a.get("network"),
                         a.get("campaign"), a.get("engagement_time"),
                         a.get("installed_at")))
            else:
                print("     logged:", json.dumps(r["response"])[:120])
    print("\n%d/%d byte-exact" % (n_ok, len(out)))
    with open(r"C:\Users\Apps\Downloads\com.penti.app\adj7ios"
              r"\lululemon_carved.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    return 0 if n_ok == len(out) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else
                          r"C:\Users\Apps\Downloads"
                          r"\lululemon_newapp_13may_ios11.chls"))

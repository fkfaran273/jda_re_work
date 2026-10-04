"""
validate_real.py — byte-for-byte validation of canonical_string_v5() and
build_authorization_header() against a REAL device-oracle capture.

The capture (adj9/device/capture_oracle_*.log) was produced by the LSPosed
module hooking d3.a / u2.a / o3.a / NativeLibHelper.a inside com.penti.app.
It contains, per signing event:
  - type=canonical            -> the exact string d3.a received (the HMAC input)
  - type=adj_verification     -> o3.a output
  - type=nsign                -> NativeLibHelper.a output blob (hex)
  - type=authorization_header -> the final u2.a output header

Usage: python validate_real.py <capture_oracle_log>
"""
from __future__ import annotations

import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from canonical import canonical_string_v5, build_authorization_header  # noqa: E402


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def parse_blocks(path):
    blocks, cur = [], None
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("###ADJ9_BEGIN"):
                meta = line[len("###ADJ9_BEGIN"):].strip()
                kv = dict(p.split("=", 1) for p in meta.split() if "=" in p)
                cur = {"type": kv.get("type"), "text_lines": [], "in_text": False}
            elif line.startswith("###ADJ9_END"):
                if cur is not None:
                    blocks.append(cur)
                cur = None
            elif cur is not None:
                if line.startswith("text: "):
                    cur["in_text"] = True
                    cur["text_lines"].append(line[len("text: "):])
                elif line.startswith("hex: "):
                    cur["in_text"] = False          # hex-dump line ends the text
                elif cur["in_text"]:
                    cur["text_lines"].append(line)  # multi-line text (sign_input)
    for b in blocks:
        b["text"] = "\n".join(b["text_lines"])
    return blocks


def parse_map(s):
    """Parse a Java Map.toString '{k=v, k=v}' into ordered (k,v) pairs,
    tolerant of nested {...} and quoted JSON values containing , and =."""
    s = s.strip()
    assert s.startswith("{") and s.endswith("}"), "not a map string"
    body = s[1:-1]
    fields, cur, depth, in_q = [], [], 0, False
    i = 0
    while i < len(body):
        c = body[i]
        if in_q:
            cur.append(c)
            if c == '"':
                in_q = False
        elif c == '"':
            in_q = True
            cur.append(c)
        elif c == "{":
            depth += 1
            cur.append(c)
        elif c == "}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0 and i + 1 < len(body) and body[i + 1] == " ":
            fields.append("".join(cur))
            cur = []
            i += 1
        else:
            cur.append(c)
        i += 1
    if cur:
        fields.append("".join(cur))
    pairs = []
    for f in fields:
        depth, in_q = 0, False
        for j, ch in enumerate(f):
            if in_q:
                if ch == '"':
                    in_q = False
            elif ch == '"':
                in_q = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            elif ch == "=" and depth == 0:
                pairs.append((f[:j], f[j + 1:]))
                break
    return pairs


def first_divergence(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            lo = max(0, i - 40)
            return (f"first diff at char {i}:\n  exp ...{a[lo:i+40]!r}\n"
                    f"  got ...{b[lo:i+40]!r}")
    if len(a) != len(b):
        return f"prefix equal, length differs exp={len(a)} got={len(b)}"
    return "identical"


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------
def validate_event(canon_str, adj_verif, nsign_hex, header, label):
    print(f"\n================ {label} ================")
    pairs = parse_map(canon_str)

    # split source / globals / adj_verification
    assert pairs[-1][0] == "adj_verification", f"last={pairs[-1][0]}"
    adj = pairs[-1][1]
    core = pairs[:-1]
    assert core[-2][0] == "activity_kind" and core[-1][0] == "client_sdk", \
        f"tail={core[-2][0]},{core[-1][0]}"
    globals_ = dict([core[-2], core[-1]])
    source = core[:-2]
    print(f"fields: total={len(pairs)} source={len(source)} "
          f"globals={list(globals_)} adj_verif={adj[:12]}...")
    assert adj == adj_verif, "adj_verification mismatch between canonical & o3.a"

    # (1) canonical-string model, feeding source in the DEVICE's observed order
    print("-- canonical_string_v5 byte-for-byte --")
    for cap in (16, 64):
        got = canonical_string_v5(dict(source), globals_, adj, source_capacity=cap)
        ok = got == canon_str
        print(f"  source_capacity={cap:>2}  feed=device-order : "
              f"{'MATCH' if ok else 'MISMATCH'}")
        if not ok:
            print("    " + first_divergence(canon_str, got).replace("\n", "\n    "))

    # (2) same but feeding source in ALPHABETICAL order -> probes whether
    #     within-bucket insertion order matters (i.e. are there collisions?)
    got_alpha = canonical_string_v5(dict(sorted(source)), globals_, adj,
                                    source_capacity=64)
    print(f"  source_capacity=64  feed=alphabetical: "
          f"{'MATCH' if got_alpha == canon_str else 'MISMATCH (collisions: insertion order matters)'}")
    if got_alpha != canon_str:
        print("    " + first_divergence(canon_str, got_alpha).replace("\n", "\n    "))

    # (3) header reconstruction: signature must equal base64(nsign blob)
    print("-- authorization_header reconstruction --")
    sig_b64 = base64.b64encode(bytes.fromhex(nsign_hex)).decode()
    # pull the metadata out of the captured header
    hdr_fields = {}
    for part in header[len("Signature "):].split(","):
        k, _, v = part.partition("=")
        hdr_fields[k.strip()] = v.strip().strip('"')
    got_hdr = build_authorization_header(
        sig_b64,
        hdr_fields["adj_signing_id"],
        hdr_fields["headers_id"],
        hdr_fields["algorithm"],
        hdr_fields["native_version"],
        hdr_fields["adj_verification"],
    )
    print(f"  signature == base64(nsign): "
          f"{'MATCH' if sig_b64 == hdr_fields['signature'] else 'MISMATCH'}")
    print(f"  full header reconstruction: "
          f"{'MATCH' if got_hdr == header else 'MISMATCH'}")
    if got_hdr != header:
        print("    exp:", header[:160])
        print("    got:", got_hdr[:160])
    print(f"  nsign blob length = {len(bytes.fromhex(nsign_hex))} bytes")


def main():
    path = sys.argv[1]
    blocks = parse_blocks(path)
    # group into events: a big canonical (len>100) anchors an event; the
    # following adj_verification / nsign / authorization_header belong to it.
    events, cur, pending_adj = [], None, None
    for b in blocks:
        t = b["type"]
        if t == "adj_verification":
            pending_adj = b["text"].strip()     # o3.a fires before the big canonical
            if cur is not None:
                cur["adj"] = pending_adj
        elif t == "canonical" and len(b["text"]) > 100:
            cur = {"canonical": b["text"], "adj": pending_adj}
            events.append(cur)
        elif cur is not None and t == "nsign":
            for ln in b["text_lines"]:
                if ln.startswith("hex="):
                    cur["nsign"] = ln[len("hex="):].strip()
        elif cur is not None and t == "authorization_header":
            cur["header"] = b["text"].strip()
            cur = None  # event complete

    print(f"parsed {len(events)} signing event(s) from {os.path.basename(path)}")
    for i, ev in enumerate(events, 1):
        if all(k in ev for k in ("canonical", "adj", "nsign", "header")):
            validate_event(ev["canonical"], ev["adj"], ev["nsign"], ev["header"],
                           f"EVENT {i}")
        else:
            print(f"EVENT {i}: incomplete {sorted(ev)}")


if __name__ == "__main__":
    main()

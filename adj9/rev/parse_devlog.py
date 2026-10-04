r"""parse_devlog.py — pull the genuine signing inputs out of the device oracle log.

devlog_tail.b64 = base64 of the last 400 KB of
/data/data/com.penti.app/files/adj9_capture.log (via su).

Prints the block-type histogram and, in order, the recent signing records
(nsign_in -> H/arg3, nsign -> blob, authorization_header -> final signature,
canonical/sign_input -> the HMAC input). The fresh install's signature is the
key artefact: with H + the canonical string we can mint a body carrying the
GENUINE H for the identical claim set and see whether the server books it.

Usage: python parse_devlog.py
"""
import base64
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
B64 = os.path.join(HERE, "devlog_tail.b64")


def main():
    raw = open(B64, "r", errors="replace").read()
    try:
        d = base64.b64decode(re.sub(r"\s+", "", raw))
    except Exception as e:
        print("b64 decode failed: %s" % e)
        return
    txt = d.decode("utf-8", "replace")
    print("decoded %d bytes" % len(d))
    print("types:", collections.Counter(re.findall(r"type=(\w+)", txt))
          .most_common(25))
    # block splitter: ###ADJ9_BEGIN type=... ... ###ADJ9_END
    blocks = re.findall(r"###ADJ9_BEGIN (.*?)###ADJ9_END", txt, re.DOTALL)
    print("blocks: %d" % len(blocks))
    keep = ("nsign", "nsign_in", "authorization_header", "canonical",
            "sign_input", "n_sign", "native_sign", "u2", "d3", "o3")
    seq = []
    for b in blocks:
        if not any(b.startswith(k) or ("type=%s" % k) in b[:60] for k in keep):
            continue
        head = b.split("\n", 1)[0][:120]
        ts = re.search(r"ts=(\d+)", b)
        txts = re.findall(r"^text: (.*)$", b, re.MULTILINE)
        hexs = re.findall(r"^hex: ([0-9a-fA-F]+)$", b, re.MULTILINE)
        seq.append((int(ts.group(1)) if ts else 0, head, txts[:1], hexs[:1]))
    print("\n--- %d interesting blocks (last 40) ---" % len(seq))
    for ts, head, t, h in seq[-40:]:
        print("ts=%s %s | %s | %s" % (ts, head[:80],
                                      (t[0][:90] if t else ""),
                                      (h[0][:60] if h else "")))
    # H values specifically
    hs = re.findall(r"arg3_hex=([0-9a-f]{64})", txt)
    print("\narg3_hex (H) occurrences: %d" % len(hs))
    for h in dict.fromkeys(hs):
        print("   ", h)
    sigs = re.findall(r'signature="([A-Za-z0-9+/=]{20,})"', txt)
    print("\nsignatures seen: %d" % len(sigs))
    for s in list(dict.fromkeys(sigs))[:8]:
        print("   ", s[:60])


if __name__ == "__main__":
    main()
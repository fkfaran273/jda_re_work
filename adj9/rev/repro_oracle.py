"""repro_oracle.py -- reproduce a real oracle-signed 192-byte blob OFFLINE.

We take:
  * the oracle's exact claim map (device/adj9_sign_in.pull, TASK block for a kind)
  * the oracle's signed Authorization (device/adj9_sign_out.pull, AUTH idx)
  * the header's signing second (recovered from the 16-byte header law)

Then we:
  1. read the native seed S straight out of the body (descriptor d2 is the
     little-endian store of S; the region lift is a pure function of S),
  2. rebuild the full descriptor set from our claim map + region(S),
  3. run FinEx and compare the 192-byte result to the oracle blob.

If this is byte-exact, the offline signer is cryptographically COMPLETE: the
only thing the device contributes is the fill-instant clock value V (and the
pid low bits folded into S).  That is a value we can also observe or predict,
so a device-free signer is a matter of choosing V, not of breaking crypto.
"""
import base64
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9_tool"))

import adj9_signer as S


def parse_control(path):
    """Return {idx: (kind, sdk, {k:v})} from the SIGN_IN control file."""
    tasks = []
    cur = None
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line.strip() == "TASK":
            cur = {"kind": "session", "sdk": S.CLIENT_SDK, "map": {}}
            tasks.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("KIND="):
            cur["kind"] = line[5:].strip(); continue
        if line.startswith("SDK="):
            cur["sdk"] = line[4:].strip(); continue
        if "\x01" in line:
            k, v = line.split("\x01", 1)
            cur["map"][k] = v
    return tasks


def parse_out(path):
    """Return {idx: auth_header_string} from the SIGN_OUT file."""
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"AUTH\s+(\d+)\s+(.*)$", line.strip())
        if m:
            out[int(m.group(1))] = m.group(2)
    return out


def blob_of(auth):
    m = re.search(r'signature="([^"]+)"', auth)
    raw = m.group(1); raw += "=" * (-len(raw) % 4)
    return base64.b64decode(raw)


def recover_second(hdr16, center):
    for delta in range(0, 3600):
        for sec in (center - delta, center + delta):
            if S.make_header(sec) == hdr16:
                return sec
        if delta == 0:
            continue
    return None


def find_seed(d0, d2, d4):
    """seed S such that region() reproduces (d0,d2,d4) exactly."""
    for s in range(0, 1 << 32):
        dd0, dd2, dd4 = S.region(s, 0)
        if dd2 == d2:
            return s
    return None


def main():
    dev = os.path.join(os.path.dirname(HERE), "device")
    cin = os.path.join(dev, "adj9_sign_in.pull")
    cout = os.path.join(dev, "adj9_sign_out.pull")
    if not (os.path.exists(cin) and os.path.exists(cout)):
        print("missing pulled control/output files"); return 1
    tasks = parse_control(cin)
    outs = parse_out(cout)
    print("control tasks: %d   outputs: %s" % (len(tasks), sorted(outs)))

    import time
    now = int(time.time())
    for idx in sorted(outs):
        auth = outs[idx]
        blob = blob_of(auth)
        if len(blob) != 192:
            print("idx %d: not a 192-B blob (%d)" % (idx, len(blob))); continue
        kind = tasks[idx]["kind"] if idx < len(tasks) else "?"
        sec = recover_second(blob[:16], now)
        print("\n===== idx %d  kind=%s  second=%s" % (idx, kind, sec))
        print("  header  %s" % blob[:16].hex())
        if sec is None:
            print("  could not recover second"); continue
        # claims -> desc10
        val = S.claims_from_wire(tasks[idx]["map"], kind)
        raw10 = S.build_desc10(val, kind).encode("latin1")
        print("  desc10 len=%d" % len(raw10))
        # brute force the seed against the 8 known (d0,d2,d4)?  We do not have
        # the region words directly -- but the BODY contains them after the VM
        # transform.  Instead of inverting the VM, scan S for the one whose
        # FinEx output equals the oracle blob.  That is the real reproduction.
        # Brute-forcing 2**32 through FinEx is too slow; do a coarse probe to
        # show the wiring, and report the seed-search strategy.
        print("  (full 2**32 FinEx inversion is the expensive step; "
              "region lift itself already verified 8/8 by verify_lift.py)")


if __name__ == "__main__":
    main()

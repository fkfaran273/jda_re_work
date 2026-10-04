"""Is the 192-byte envelope built from the digests nSign computes?
Pull every digest output in the nSign window and search for each (and every
>=6-byte substring) inside the captured 192-byte blobs."""
import os
import re
import glob

CAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cap")


def main():
    logs = sorted(glob.glob(os.path.join(CAP, "*.log")))
    blobs = []
    digests = []
    for lg in logs:
        lines = open(lg, encoding="utf-8", errors="replace").read().splitlines()
        inwin = False
        for ln in lines:
            if "nsign_in" in ln.lower() or ("nSign" in ln and "BEGIN" in ln):
                inwin = True
            if "nsign_out" in ln.lower() or ("nSign" in ln and "END" in ln.lower()):
                inwin = False
            m = re.search(r"hex=([0-9a-fA-F]{40,})\b", ln)
            if m and ("192" in ln or len(m.group(1)) // 2 == 192):
                blobs.append((os.path.basename(lg), m.group(1).lower()))
            if len(m.group(1)) // 2 in (16, 20, 32) if m else False:
                digests.append((os.path.basename(lg), m.group(1).lower(), inwin))
            elif m and len(m.group(1)) // 2 > 64:
                pass
    # separate: digests are the *short* ones (16/20/32B); blobs are 192B
    digests = []
    for lg in logs:
        for ln in open(lg, encoding="utf-8", errors="replace"):
            for m in re.finditer(r"hex=([0-9a-fA-F]+)", ln):
                h = m.group(1).lower()
                if len(h) // 2 in (16, 20, 32):
                    digests.append((os.path.basename(lg), h))

    blobs = sorted(set(blobs))
    digs = sorted(set(d for _, d in digests))
    print("192-byte blobs found: %d" % len(blobs))
    for f, b in blobs:
        print("  %s  %s..." % (f, b[:48]))
    print("distinct short digests (16/20/32B) in logs: %d" % len(digs))

    if not blobs:
        return
    print("\n=== direct containment ===")
    found = 0
    for f, b in blobs:
        bb = bytes.fromhex(b)
        for d in digs:
            db = bytes.fromhex(d)
            if db in bb:
                print("  HIT blob %s contains digest %s at offset %d" %
                      (f[:18], d, bb.index(db)))
                found += 1
    print("  total direct hits: %d" % found)

    print("\n=== substring (>=6 bytes) containment ===")
    hits = 0
    for f, b in blobs:
        bb = bytes.fromhex(b)
        for d in digs:
            db = bytes.fromhex(d)
            for i in range(0, len(db) - 6):
                sub = db[i:i + 6]
                if sub in bb:
                    print("  %s: 6B of %s @digest+%d found in blob @%d" %
                          (f[:18], d[:16], i, bb.index(sub)))
                    hits += 1
                    break
    print("  digests with a >=6B fragment present: %d" % hits)

    print("\n=== blob structure ===")
    for f, b in blobs:
        bb = bytes.fromhex(b)
        print("  %s len=%d distinct bytes=%d first16=%s last16=%s" %
              (f[:18], len(bb), len(set(bb)), bb[:16].hex(), bb[-16:].hex()))


if __name__ == "__main__":
    main()

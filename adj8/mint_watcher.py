"""mint_watcher.py — watch logcat for adj8mint_req chunks, reassemble the
canonical map, mint the adj8 blob offline, and push it to the device for the
oracle to substitute into the real request flow.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj8_pure as S

REAL = ("/data/app/~~30Ss2u9QWccmb8X2uH09NA==/"
        "com.grad.def-Zw4aOG74mRxAOJlVpHJHpQ==/base.apk")
apk = open(os.path.join(HERE, "apks", "graddef_base4.apk"), "rb").read()

SEEN_REQ = set()
PUSHED = set()


def adb(*args):
    return subprocess.run(["adb"] + list(args), capture_output=True, text=True,
                          errors="replace").stdout


def logcat_adj8():
    out = adb("logcat", "-d")
    lines = [l.split(" D ADJ9ORA : ", 1)[1].rstrip("\r\n")
             for l in out.splitlines() if " D ADJ9ORA : " in l]
    return lines


def reassemble(lines):
    """adj8mint_req#N :: chunk — group chunk indices per req occurrence."""
    reqs = []
    cur = None
    for l in lines:
        m = re.match(r"adj8mint_req#(\d+) :: (.*)$", l)
        if m:
            n = int(m.group(1))
            if n == 0:
                if cur is not None:
                    reqs.append(cur)
                cur = m.group(2)
            elif cur is not None:
                cur += m.group(2)
    if cur is not None:
        reqs.append(cur)
    return reqs


def parse_map(text):
    inner = text.strip()
    if inner.startswith("{"):
        inner = inner[1:]
    if inner.endswith("}"):
        inner = inner[:-1]
    out = {}
    for pair in inner.split(", "):
        if "=" in pair:
            a, b = pair.split("=", 1)
            out[a] = b
    return out


def mint_and_push(canonical, tag):
    m = parse_map(canonical)
    print("minting: %d fields | activity_kind=%s api=%s"
          % (len(m), m.get("activity_kind", "?"), m.get("api_level", "?")),
          flush=True)
    sec = int(time.time())
    # the device's map carries created_at/sent_at close to now; sign at now
    blob, auth, meta = S.mint_adj8(
        m.get("activity_kind", "session"), m, unix_sec=sec,
        return_meta=True, apk_path=REAL, apk_bytes=apk)
    print("  blob %d B tag_ok=%s header_ok=%s"
          % (len(blob), meta["tag_ok"], meta["header_ok"]), flush=True)
    hexblob = blob.hex()
    # write world-readable blob on the device
    subprocess.run(["adb", "shell", "rm", "-f",
                    "/data/local/tmp/adj8_mint_blob"], capture_output=True)
    subprocess.run(["adb", "shell", "rm", "-f",
                    "/data/local/tmp/adj8_mint_blob"], capture_output=True)
    for i in range(0, len(hexblob), 400):
        part = hexblob[i:i + 400]
        cmd = "printf %s" + part + " >> /data/local/tmp/adj8_mint_blob"
        subprocess.run(["adb", "shell", cmd], capture_output=True)
    subprocess.run(["adb", "shell", "chmod", "644",
                    "/data/local/tmp/adj8_mint_blob"], capture_output=True)
    print("  pushed blob (%d hex chars)" % len(hexblob), flush=True)
    json.dump({"canonical": canonical, "map": m, "auth": auth,
               "blob_hex": hexblob, "tag": tag},
              open(os.path.join(HERE, "mint_log", "mint_%s.json"
                                % time.strftime("%H%M%S")), "w"), indent=1)


def main():
    os.makedirs(os.path.join(HERE, "mint_log"), exist_ok=True)
    print("watching logcat for adj8mint_req (Ctrl+C to stop)...", flush=True)
    while True:
        lines = logcat_adj8()
        reqs = reassemble(lines)
        for canonical in reqs:
            key = canonical[:120]
            if key in SEEN_REQ:
                continue
            SEEN_REQ.add(key)
            print("\nNEW canonical (%d chars)" % len(canonical), flush=True)
            try:
                mint_and_push(canonical, key)
            except Exception as e:
                print("MINT FAILED:", e, flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()

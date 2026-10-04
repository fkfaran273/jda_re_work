"""replay31.py — decisive byte-exact replay of the device's three nSign
calls (arg4 = 31 = Build.VERSION.SDK_INT) with the REAL APK served to the
emulator through the fd-backed vfs (adj8_pure.Emu(apk_path=..., apk_bytes=...)).

The exact signed maps come from the jca_mac_update hex fragments (the SDK
HMAC'd the Java HashMap.toString() of the precise signed map before calling
nSign — these records are chunk-sequential and unclobbered, unlike the
signer_sign_entry mirror whose chunks interleave all three signings).

Per signing: same map, same H (arg2), same second (fixed_time), same APK
(apks/base.apk at the real install path).  SUCCESS = our blob == the
device's blob, byte for byte.
"""
import re
import sys
import time

sys.path.insert(0, ".")
import adj8_pure as S

REAL_PATH = ("/data/app/~~cgSd5YKkLX7RXvJWtSA_6Q=="
             "/xyz.be.customer-zt-y8mq-uV_paqBcpeNXcg==/base.apk")
LOG = "cap/device_capture_adj8.log"
APK_FILE = "apks/base.apk"

# ---- parse the oracle log ------------------------------------------------
lines = [l.split(" D ADJ9ORA : ", 1)[1].rstrip("\n")
         for l in open(LOG, encoding="utf-8", errors="replace")
         if " D ADJ9ORA : " in l]

# ---- the signed maps: jca_mac_update hex fragments (chunk-sequential) -----
groups = []
cur_chunks = None
for l in lines:
    m = re.match(r"jca_mac_update#(\d+) :: len=\d+\|hex=([0-9a-f]+)", l)
    if not m:
        m = re.match(r"jca_mac_update#(\d+) :: ([0-9a-f]{40,})", l)
    if not m:
        continue
    n, hx = int(m.group(1)), m.group(2)
    if n == 0:
        if cur_chunks is not None:
            groups.append(cur_chunks)
        cur_chunks = [hx]
    elif cur_chunks is not None:
        cur_chunks.append(hx)
if cur_chunks is not None:
    groups.append(cur_chunks)

signings = []
for chunks in groups:
    txt = bytes.fromhex("".join(chunks)).decode("utf-8")
    inner = txt.strip()
    assert inner.startswith("{") and inner.endswith("}"), inner[:60]
    m = {}
    for pair in inner[1:-1].split(", "):
        if "=" in pair:
            a, b = pair.split("=", 1)
            m[a] = b
    kind = m.get("activity_kind", "?")
    signings.append({"kind": kind, "map": m, "n": len(m),
                     "raw_len": len(txt)})
    print("mac_update map: kind=%s fields=%d toString_len=%d"
          % (kind, len(m), len(txt)))

# ---- H values (chronological mac_doFinal, deduped) -------------------------
H = []
for l in lines:
    m = re.match(r"jca_mac_doFinal#\d+ :: out=32\|hex=([0-9a-f]{64})", l)
    if m and m.group(1) not in H:
        H.append(m.group(1))

# ---- device blobs (chronological nsign_native, deduped) --------------------
blobs = []
for l in lines:
    if l.startswith("nsign_native#"):
        m = re.search(r"out_len=176\|out_hex=([0-9a-f]{352})", l)
        if m:
            b = bytes.fromhex(m.group(1))
            if b not in blobs:
                blobs.append(b)

# chronological pairing: session, click, attribution
kinds_order = ["session", "click", "attribution"]
secs = {"session": 1790969357, "click": 1790969357,
        "attribution": 1790969358}
H_expect = {
    "session": "5660cc1ef9e37bc82ccfc802b0b78f10abee591c58483c88713d41a17c221176",
    "click": "6bd8685bc57f32edaa82f6e712a6c922e9a51f43fdb68b9750f0a6d28e9673fe",
    "attribution": "8507d0be33e970ef542e910b204dba082660941d15aa5da6f73d9fd2c695f69e",
}

print("H (chronological):", [h[:12] for h in H])
print("blobs:", len(blobs), [b[:8].hex() for b in blobs])

# ---- load the real APK once, share across runs ------------------------------
t0 = time.perf_counter()
apk = open(APK_FILE, "rb").read()
print("APK loaded: %d bytes in %.1f s" % (len(apk), time.perf_counter() - t0))

results = []
for i, kind in enumerate(kinds_order):
    sig = next(s for s in signings if s["kind"] == kind)
    h = bytes.fromhex(H_expect[kind])
    assert h.hex() in H, "H mismatch for %s" % kind
    dev = blobs[i]
    assert S.make_header(secs[kind]) == dev[:16], "header/second mismatch"
    print()
    print("=== replay %s (sec=%d, H=%s..., map %d fields) ==="
          % (kind, secs[kind], h.hex()[:12], sig["n"]))
    emu = S.Emu(apk_path=REAL_PATH, apk_bytes=apk)
    emu.fixed_time = secs[kind]
    t1 = time.perf_counter()
    out = emu.run(payload=h, mapobj=sig["map"], arg4=31)
    dt = time.perf_counter() - t1
    if out is None:
        print("  mint FAILED (%.1f s): %s" % (dt, emu.error))
        results.append((kind, False, None))
        continue
    same = out == dev
    diff = next((j for j in range(176) if out[j] != dev[j]), None)
    print("  mint: %d bytes in %.1f s" % (len(out), dt))
    print("  identical=%s  first diff=%s" % (same, diff))
    print("  mine[16:48] %s" % out[16:48].hex())
    print("  dev [16:48] %s" % dev[16:48].hex())
    if not same and diff is not None:
        nd = sum(1 for j in range(176) if out[j] != dev[j])
        print("  differing bytes: %d/176 (header equal: %s, tag equal: %s)"
              % (nd, out[:16] == dev[:16], out[144:] == dev[144:]))
    print("  io_log (%d):" % len(emu.io_log))
    for e in emu.io_log[:36]:
        print("    %s" % (e,))
    if len(emu.io_log) > 36:
        print("    ... %d more" % (len(emu.io_log) - 36))
    if emu.error:
        print("  emu.error: %s" % emu.error)
    open("replay31_%s.hex" % kind, "w").write(out.hex() if out else "")
    results.append((kind, same, diff))

print()
print("VERDICT:", results)

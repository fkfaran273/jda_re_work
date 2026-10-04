"""full_replay.py - the decisive end-to-end replay: run the emulated signing
path (nSign 0xdb1cc -> VM -> sub_8d6f4 -> wire builder -> JNI return) with the
EXACT captured inputs of device signing #1..#3 (moto g42, hawao, Android 12,
build S2SE32.28-28-4) and diff the returned blob against the captured 192-B
blob word by word.

Captured input sources (all byte-exact):
  * adj9/device/java_dump/signings_extract.json - canonical claims bytes,
    32-B HMAC H, 192-B blob, header-inverted second (1790106110/176/196),
    ts (ms), env ints (sdk=31 widthPixels=1080 heightPixels=2237).
  * adj9/device/java_dump/adj9_capture_run1.log - the native map.get(key)
    traffic on the signing map (this=50234709), 63 calls: 3x environment,
    app_version, android_id=null, fire_adid=null, client_sdk, os_version,
    api_level, adj_verification, android_uuid, then TWO passes of the same
    27 keys.  These 29 keys are the exact map surface the wire sees.
  * nano_in=3565565088270 (nsign_in record) = CLOCK_MONOTONIC at nSign entry.
  * rev/cert_signer1.der - the real 745-B APK signing cert;
    SHA-1 = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd (descriptor #9).
  * Property strings: the capture is Java-side only, so the __system_property_get
    values are best-known stock hawao S2SE32.28-28-4 values (fingerprint
    "motorola/hawao_g/hawao:12/S2SE32.28-28-4/4140d-bd21d:user/release-keys"
    per stockrom.net's firmware listing; manufacturer/model confirmed by the
    device's own claims).  Serialno/build.user/build.host are unknowable -
    the sensitivity campaign (-v) shows which words they would reach.

Usage:
  python full_replay.py                     # signing 1, exact captured inputs
  python full_replay.py -n 2                # signing 2
  python full_replay.py -v '{"mono_nsec":565188270}'
  python full_replay.py --sens sens.jsonl   # one-at-a-time knob campaign
"""
import argparse
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import emu_8d6f4 as E

SIGNINGS = json.load(open(os.path.join(
    HERE, "..", "device", "java_dump", "signings_extract.json")))["signings"]

CERT = open(os.path.join(HERE, "cert_signer1.der"), "rb").read()
CERT_SHA1 = hashlib.sha1(CERT).digest()

# exact map.get surface captured on device during signing #1 (this=50234709);
# values identical for signings 1/2/3 (only the claims-string fields differ,
# and those are read through the same keys with the same values)
MAP_VALUES = {
    "environment": "production",
    "app_version": "3.13.9",
    "android_id": None,                       # map.get -> null on device
    "fire_adid": None,                        # map.get -> null on device
    "client_sdk": "android5.7.0",
    "os_version": "12",
    "api_level": "31",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "android_uuid": "8eaff6a2-7a27-424f-aa50-8bc8a293f823",
    "app_token": "jut9tib0eeps",
    "created_at": "2026-09-23T01:11:49.916Z+0530",
    "device_name": "moto g42",
    "device_type": "phone",
    "event_count": "5",
    "event_token": "29ah7d",
    "gps_adid": "950ed69a-1bec-4158-be55-d76a59dfdbce",
    "gps_adid_src": "service",
    "hardware_name": "S2SE32.28-28-4",
    "os_build": "S2SE32.28-28-4",
    "os_name": "android",
    "package_name": "com.penti.app",
    "partner_params": '{"productCode":"PHR9KOQU26SK-GAS","amount":"1",'
                      '"content_type":"product","content_id":"PHR9KOQU26SK-GAS",'
                      '"value":"1199.99","currency":"TRY"}',
    "seq": "2",
    "session_count": "1",
    "session_length": "6389",
    "subsession_count": "23",
    "time_spent": "5327",
    "tracking_enabled": "1",
    "activity_kind": "event",
    # --- fields fetched OUTSIDE the map (package/packageInfo/keystore) ---
    "versionName": "3.13.9",
    "SENSOR_SERVICE": "sensor",
    # publicSourceDir: /data/app/~~<24 rand>/com.penti.app-<24 rand>/base.apk;
    # the tail is known from the memscan record, the first token's middle is
    # elided in the capture ("~~YHMVfsPQ...") - X placeholders, correct length
    "publicSourceDir":
        "/data/app/~~YHMVfsPQXXXXXXXXXXXXXX==/com.penti.app"
        "-aP-iSz13tgXYY_5WRyY7ew==/base.apk",
    "default": None,     # any other map.get -> null (device-faithful)
}

# stock hawao (moto g42, XT2233) Android 12 S2SE32.28-28-4 property values.
# ???-marked values are unknowable from the Java-side capture (guessed stock
# defaults); the sensitivity campaign measures whether they can matter.
MOTO_G42_PROPS = {
    "ro.product.manufacturer": "motorola",
    "ro.product.model": "moto g42",
    "ro.product.device": "hawao",
    "ro.product.name": "hawao_g",
    "ro.product.brand": "motorola",
    "ro.product.board": "hawao",
    "ro.build.fingerprint":
        "motorola/hawao_g/hawao:12/S2SE32.28-28-4/4140d-bd21d:user/release-keys",
    "ro.bootimage.build.fingerprint":
        "motorola/hawao_g/hawao:12/S2SE32.28-28-4/4140d-bd21d:user/release-keys",
    "ro.build.version.release": "12",
    "ro.build.version.sdk": "31",
    "ro.build.display.id": "S2SE32.28-28-4",
    "ro.build.tags": "release-keys",
    "ro.build.type": "user",
    "ro.build.user": "og-wpt-dev",            # ???
    "ro.build.host": "ildbuildlr11",          # ???
    "ro.build.characteristics": "nosdcard",
    "ro.build.date.utc": "1653476385",
    "ro.hardware": "qcom",
    "ro.bootloader": "MBM-3.0-hawao_g-273037475-220525",
    "ro.bootmode": "unknown",
    "ro.boot.serialno": "ZY2W29T6V6",         # ??? per-device secret
    "ro.serialno": "ZY2W29T6V6",              # ??? per-device secret
    "ro.boot.serialno2": "ZY2W29T6V6",
    "ro.brand": "motorola",
    "ro.device": "hawao",
    "ro.system.build.type": "user",
    "ro.product.vendor.manufacturer": "motorola",
    "ro.product.vendor.model": "moto g42",
    "ro.product.cpu.abilist": "arm64-v8a,armeabi-v7a,armeabi",
    "ro.secure": "1",
    "ro.soc.manufacturer": "QTI",
    "ro.soc.model": "SM6225",                 # ???
    "ro.hardware.power": "hawao",
    "ro.hardware.egl": "qcom",
    "ro.kernel.qemu": "0",
}

# CLOCK_MONOTONIC at nSign entry, from the nsign_in capture record
NANO_IN = 3565565088270
MONO_SEC = NANO_IN // 1_000_000_000
MONO_NSEC = NANO_IN % 1_000_000_000


def build_cfg(n=0, mono_delta_ns=0, **over):
    """Exact captured-input cfg for device signing n (0-based)."""
    s = SIGNINGS[n]
    ts_ms = s["ts"]
    sec = ts_ms // 1000                    # == header-inverted second
    frac_ms = ts_ms % 1000
    # optional stack-trace model (anti-tamper probe)
    preset = over.pop("stack_frames_preset", None)
    if preset == "sig4":
        frames = [
            ["com.adjust.sdk.sig.NativeLibHelper", "nSign"],
            ["com.adjust.sdk.sig.NativeLibHelper", "a"],
            ["com.adjust.sdk.sig.u2", "a"],
            ["com.adjust.sdk.sig.Signer", "sign"],
        ]
    elif preset == "sig6":
        frames = [
            ["com.adjust.sdk.sig.NativeLibHelper", "nSign"],
            ["com.adjust.sdk.sig.NativeLibHelper", "a"],
            ["com.adjust.sdk.sig.u2", "a"],
            ["com.adjust.sdk.sig.Signer", "sign"],
            ["com.adjust.sdk.android-sdk-scheduler", "run"],
            ["java.lang.Thread", "run"],
        ]
    else:
        frames = []
    ncerts = over.pop("n_attestation_certs", 0)
    att = [bytes((i * 31 + j * 7 + 11) & 0xFF for j in range(1054))
           for i in range(ncerts)]
    cfg = {
        "width": 1080,
        "height": 2237,
        "props": dict(MOTO_G42_PROPS),
        "prop_default": "emu",
        "package": "com.penti.app",
        "strvals": dict(MAP_VALUES),
        "hmac": bytes.fromhex(s["H"]),
        "cert": CERT,
        "cert_sha1": CERT_SHA1,
        # CLOCK_REALTIME base: the signing's own wall clock at nSign entry
        "sec": sec,
        "nsec": frac_ms * 1_000_000,
        "time_sec": sec,                   # srand seed -> header law
        "usec": frac_ms * 1000,
        # CLOCK_MONOTONIC base (VM opcode 0x18aa0); delta since nSign entry
        # is unknown -> sweepable experiment input
        "mono_sec": MONO_SEC,
        "mono_nsec": MONO_NSEC + mono_delta_ns,
        "sdk_int": 31,
        "pid": 12345,
        "tid": 12346,
        "tls_base": 0x111100000,
        "stack_guard": 0x1122334455667788,
        "srand_seed": 1,
        "rand_impl": "random3",
        "urandom8": None,
        "stack_frames": frames,
        "attestation_certs": att,
        "x3_is_hmac": True,
    }
    cfg.update(over)
    return cfg


def run_one(cfg, verbose=True):
    e = E.Emu(cfg=cfg)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob")
    if verbose:
        print("stopped=%s wall=%.1fs calls=%d blob_len=%s" % (
            st, getattr(e, "wall", 0), len(e.calls),
            len(blob) if blob is not None else None))
    return e, blob


def word_map(b):
    """4-byte word list (raw byte groups, hex)."""
    return [b[i:i + 4].hex() for i in range(0, len(b) - 3, 4)]


def diff_blob(cap, emu):
    """Word-by-word diff map vs the captured 192-B blob."""
    capw, emuw = word_map(cap), word_map(emu)
    rows = []
    for i in range(max(len(capw), len(emuw))):
        cw = capw[i] if i < len(capw) else "--"
        ew = emuw[i] if i < len(emuw) else "--"
        kind = "HDR" if i < 4 else "body"
        rows.append({"word": i, "kind": kind, "cap": cw, "emu": ew,
                     "match": cw == ew})
    return rows


def report(n, e, blob, rows, out_lines=None):
    s = SIGNINGS[n]
    cap = bytes.fromhex(s["blob"])

    def w(x):
        print(x)
        if out_lines is not None:
            out_lines.append(x)

    w("=== signing %d (ts=%d sec=%d) ===" % (n + 1, s["ts"], s["ts"] // 1000))
    w("stopped=%s wall=%.1fs calls=%d" % (e.stopped, getattr(e, "wall", 0),
                                          len(e.calls)))
    w("blob: emu_len=%d cap_len=%d" % (len(blob) if blob else -1, len(cap)))
    if blob:
        w("emu  header: %s" % blob[:16].hex(" "))
        w("cap  header: %s" % cap[:16].hex(" "))
        hok = blob[:16] == cap[:16]
        w("header match: %s" % hok)
        # extend/trim emu to cap length for the word map
        nb = 16
        w("\nword map (4-B words; HDR = rand pair-XOR header):")
        nm = 0
        for r in rows:
            mark = "OK " if r["match"] else "DIFF"
            if r["match"]:
                nm += 1
            w("  [%02d] %s %-4s cap=%s emu=%s" % (
                r["word"], r["kind"], mark, r["cap"], r["emu"]))
        w("words matching: %d/%d (%d header + %d/%d body)" % (
            nm, len(rows), sum(1 for r in rows[:4] if r["match"]),
            sum(1 for r in rows[4:] if r["match"]), len(rows) - 4))
        # first differing byte
        fd = next((i for i in range(min(len(cap), len(blob)))
                   if cap[i] != blob[i]), None)
        w("first differing byte offset: %s" % fd)
    w("srand log: %s" % e.srand_log)
    w("rand draws: %s" % [v for _, v, _ in e.rand_calls])
    clocks = [c for c in e.calls
              if c[0] in ("clock_gettime", "gettimeofday", "time")]
    w("clock calls (%d): %s" % (len(clocks), clocks[:12]))


def sens_variants():
    """(name, override) list - focused knob campaign on the final harness."""
    D = build_cfg(0)
    V = []
    # the per-call whitening seed (get8random): device path vs fallback
    V.append(("urandom8=0011223344556677", {"urandom8": bytes.fromhex("0011223344556677")}))
    V.append(("urandom8=deadbeefcafebabe", {"urandom8": bytes.fromhex("deadbeefcafebabe")}))
    V.append(("urandom8 low bit +1", {"urandom8": bytes.fromhex("0011223344556678")}))
    V.append(("usec +1 (fallback seed)", {"usec": D["usec"] + 1}))
    V.append(("pid +1 (fallback seed)", {"pid": D["pid"] + 1}))
    V.append(("rt_sec +1 (fallback+clock)", {"sec": D["sec"] + 1}))
    V.append(("time_sec +1 (srand only)", {"time_sec": D["time_sec"] + 1}))
    V.append(("rt_nsec +1ms", {"nsec": D["nsec"] + 1_000_000}))
    # claims / map surface
    V.append(("map.environment=X", {"strvals": dict(D["strvals"],
                                                    environment="X")}))
    V.append(("map.app_version=X", {"strvals": dict(D["strvals"],
                                                    app_version="X")}))
    V.append(("map.created_at=X", {"strvals": dict(D["strvals"],
                                                   created_at="X")}))
    V.append(("map.partner_params=X", {"strvals": dict(D["strvals"],
                                                       partner_params="X")}))
    V.append(("map.android_id=set", {"strvals": dict(D["strvals"],
                                                     android_id="9a7c4e2b1d5f8036")}))
    V.append(("versionName=X", {"strvals": dict(D["strvals"],
                                                versionName="X")}))
    # material
    V.append(("hmac[0]^1", {"hmac": bytes([D["hmac"][0] ^ 1]) + D["hmac"][1:]}))
    V.append(("cert_sha1 vary", {"cert_sha1": bytes((i * 5 + 2) & 0xFF
                                                    for i in range(20))}))
    V.append(("sdk_int 31->32", {"sdk_int": 32}))
    V.append(("sec_level 1->0", {"sec_level": 0}))
    # negative controls (device inputs that should NOT reach the wire)
    V.append(("width +1", {"width": 1081}))
    V.append(("height +1", {"height": 2238}))
    V.append(("tls_base +0x1000", {"tls_base": D["tls_base"] + 0x1000}))
    V.append(("tid +1", {"tid": D["tid"] + 1}))
    V.append(("mono_nsec +1ms", {"mono_nsec": D["mono_nsec"] + 1_000_000}))
    V.append(("package=X", {"package": "com.other.app"}))
    V.append(("publicSourceDir=X", {"strvals": dict(D["strvals"],
                                                    publicSourceDir="X")}))
    V.append(("prop:ro.build.version.release", {"props": dict(
        D["props"], **{"ro.build.version.release": "12X"})}))
    V.append(("prop:ro.build.fingerprint", {"props": dict(
        D["props"], **{"ro.build.fingerprint": "X"})}))
    V.append(("prop:ro.boot.serialno", {"props": dict(
        D["props"], **{"ro.boot.serialno": "X123"})}))
    return V


def sens_shard(shard_idx, nshards, out_path, n=0):
    """Run a subset of the sensitivity variants; append to out_path (json)."""
    D = build_cfg(n)
    base_e, base_blob = run_one(D, verbose=True)
    results = [{"name": "BASELINE exact-captured", "stopped": base_e.stopped,
                "blob": base_blob.hex() if base_blob else None,
                "len": len(base_blob) if base_blob else 0}]
    b0 = base_blob or b""
    for k, (name, over) in enumerate(sens_variants()):
        if k % nshards != shard_idx:
            continue
        try:
            e, blob = run_one({**D, **over}, verbose=True)
        except Exception as ex:
            results.append({"name": name, "error": str(ex)})
            continue
        b1 = blob or b""
        flips = [i for i in range(max(len(b0), len(b1)))
                 if (b0[i:i + 1] or b"\x00") != (b1[i:i + 1] or b"\x00")]
        words = sorted(set(i // 4 for i in flips))
        results.append({"name": name, "stopped": e.stopped,
                        "blob": b1.hex() if b1 else None,
                        "len": len(b1), "base_len": len(b0),
                        "n_flip_bytes": len(flips),
                        "n_flip_words": len(words),
                        "first_words": words[:40],
                        "header_word_flip": any(i < 4 for i in words)})
        print("SENS %-32s len %d->%d flips: %4d bytes %3d words hdr=%s %s" % (
            name, len(b0), len(b1), len(flips), len(words),
            any(i < 4 for i in words), words[:14]), flush=True)
    json.dump(results, open(out_path, "w"), indent=1)
    print("shard %d -> %s" % (shard_idx, out_path))
    return results


def sens_campaign(out_path, n=0):
    return sens_shard(0, 1, out_path, n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=0, help="signing index (0-based)")
    ap.add_argument("-v", "--vary", type=str, default=None,
                    help="JSON cfg override")
    ap.add_argument("--mono-delta", type=int, default=0,
                    help="ns added to the CLOCK_MONOTONIC base")
    ap.add_argument("--sens", type=str, default=None,
                    help="run the sensitivity campaign, write JSONL here")
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--nshards", type=int, default=1)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.sens:
        sens_shard(args.shard, args.nshards,
                   args.sens.replace(".json", "_s%d.json" % args.shard),
                   n=args.n)
        return

    over = json.loads(args.vary) if args.vary else {}
    cfg = build_cfg(args.n, mono_delta_ns=args.mono_delta, **over)
    e, blob = run_one(cfg, verbose=not args.quiet)
    if blob:
        rows = diff_blob(bytes.fromhex(SIGNINGS[args.n]["blob"]), blob)
        report(args.n, e, blob, rows)
        json.dump(rows, open(os.path.join(HERE, "full_replay_rows.json"),
                             "w"), indent=1)
        open(os.path.join(HERE, "full_replay_blob.bin"), "wb").write(blob)
    else:
        print("NO BLOB; stopped=%s" % e.stopped)
        print("tail:", e.calls[-15:])
    # full call trace + ctx image for offline comparison
    json.dump({"calls": [list(c) for c in e.calls], "log": e.log},
              open(os.path.join(HERE, "full_replay_calls.json"), "w"),
              indent=1, default=str)
    try:
        open(os.path.join(HERE, "full_replay_ctx.bin"), "wb").write(
            e.ctx_bytes())
    except Exception as ex:
        print("ctx dump failed:", ex)


if __name__ == "__main__":
    main()

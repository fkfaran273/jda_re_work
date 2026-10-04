"""adj9_sign.py — adj9 SIGNATURE GENERATOR. params in -> Authorization header out.

Model (proven, adj9/rev/fin_result.md — 48/48 byte-exact reproduction):
    sig[0:16]   = Random3(second) draws 1..8, pairwise XOR, 4x BE u32   [header]
    sig[16:192] = VM program run over the input set                     [body]
        inputs: claims blob (#10) | H (8 dw) | core record #0 (36 dw)
                cert-SHA1 #9 | #8 #2 #7 #5 #6 #1 #3 | second only for header

H sources: captured (real, --H omit) | supplied hex (--H <64hex>) |
random (--H random — for server-tolerance testing; the model says the
server cannot verify H cryptographically: key2 is TEE-locked).

Examples
    python adj9_sign.py                                   # control: reproduce captured blob
    python adj9_sign.py --dynamic-saz                     # SAZ S1's params, live second
    python adj9_sign.py --dynamic-saz --H random --out s.json
    python adj9_sign.py --set created_at=2026-09-08T14:05:22.928Z+0530
"""
import argparse, base64, json, os, secrets, struct, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import Random3

D = json.load(open(os.path.join(HERE, "fin_descs.json")))
SEED_BASE = D["target"]["second"]
BLOB = bytes.fromhex(D["target"]["blob_hex"])
S0 = 0x5500000000                     # slot-0 stream = the output window

# SAZ S1 (OnePlus) -> equal-length replacements in the claims blob
SAZ_S1 = [
    (b"2026-09-12T21:15:11.678Z+0200", b"2026-09-08T14:05:22.928Z+0530"),
    (b"2026-09-08T12:20:49.782Z+0200", b"2026-09-08T14:00:02.774Z+0530"),
    (b"d773f47f-fc0e-4994-9cf7-7c3cf5bb636", b"117d0470-c64e-4530-af62-48049861d40"),
    (b"f476b3d4-e0b1-4707-bc43-6153d17f7f8", b"1a89cb29-3590-418c-ae2b-122bbd93e38"),
    (b"3.13.9", b"3.12.1"),
    (b"moto g42", b"DN2101  "),
    (b"12com.penti.app", b"11com.penti.app"),
    (b"2026-09-10T07:26:18.015Z+0200", b"2026-09-08T14:00:02.774Z+0530"),
]

CLAIM_KEYS = {"created_at": 36, "installed_at": 58, "android_uuid": 28,
              "gps_adid": 136, "app_version": 78, "device_name": 113,
              "os_version": 263}   # base blob offsets (informational)


def build_descs(h_bytes, sets, dynamic):
    repl = list(SAZ_S1) if dynamic else []
    for kv in sets:
        k, v = kv.split("=", 1)
        # replace the field whose name matches a known key else raw substring
        repl.append((k.encode(), v.encode()))
    descs = []
    for d in D["descs"]:
        data = bytes.fromhex(d["data_hex"])
        if d["len_dw"] == 90:
            out = bytearray(data)
            for old, new in repl:
                i = out.find(old)
                if i >= 0 and len(old) == len(new):
                    out[i:i + len(old)] = new
                elif i >= 0:
                    print("  ! skip length-changing swap %r (raw-concat blob)" % old)
            data = bytes(out)
        if d["len_dw"] == 8 and h_bytes is not None:
            data = h_bytes
        descs.append((d["len_dw"], 0, data))
    return descs


def generate(descs, second):
    ex = FinEx(second, descs)
    status = ex.run(max_steps=12_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    return status, b"".join(struct.pack(">I", out.get((S0, k), 0))
                            for k in range(48)), ex


def hdr_line(b64):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % b64)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dynamic-saz", action="store_true")
    ap.add_argument("--second", type=int)
    ap.add_argument("--H")
    ap.add_argument("--set", action="append", default=[])
    ap.add_argument("--out")
    a = ap.parse_args()

    h = None
    if a.H == "random":
        h = secrets.token_bytes(32)
    elif a.H:
        h = bytes.fromhex(a.H)
    # bare invocation = control: reproduce the captured signing (48/48 check);
    # anything dynamic (or an explicit --second) = generate
    control_wanted = not a.dynamic_saz and not a.set and a.H is None
    second = a.second or (SEED_BASE if control_wanted else int(time.time()))

    descs = build_descs(h, a.set, a.dynamic_saz)
    t0 = time.time()
    status, sig, ex = generate(descs, second)
    R = Random3(second)
    d = [R.next() for _ in range(8)]
    law = b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1]) for i in range(4))
    control = (not a.dynamic_saz and not a.set and a.H is None
               and second == SEED_BASE)
    print("=" * 72)
    print("adj9 SIGN GENERATOR")
    print("  mode    : %s" % ("CONTROL — reproduce captured signing"
                              if control else "GENERATE"))
    print("  second  : %d (%s)" % (second, time.strftime(
        "%Y-%m-%d %H:%M:%S UTC", time.gmtime(second))))
    print("  H       : %s" % ("captured (real)" if h is None else
                               ("random 32 B (test)" if a.H == "random"
                                else "supplied hex")))
    print("  claims  : %s" % ("SAZ-S1 dynamic" if a.dynamic_saz
                              else ("custom sets" if a.set else "captured")))
    print("  VM      : %s, %.1fs, %d emit steps" % (status, time.time() - t0,
                                                    ex.steps))
    print("  header  : %s  %s" % (sig[:16].hex(),
                                  "== Random3 law OK" if sig[:16] == law
                                  else "LAW MISMATCH!"))
    if control:
        print("  verify  : %s" % ("48/48 BYTE-EXACT == captured blob"
                                  if sig == BLOB else "MISMATCH"))
    b64 = base64.b64encode(sig).decode()
    print("-" * 72)
    print("Authorization: %s" % hdr_line(b64))
    print("-" * 72)
    if a.out:
        json.dump({"second": second, "H": (h or b"").hex() or None,
                   "signature_b64": b64, "signature_hex": sig.hex(),
                   "header_line": hdr_line(b64)}, open(a.out, "w"), indent=1)
        print("saved %s" % a.out)


if __name__ == "__main__":
    main()

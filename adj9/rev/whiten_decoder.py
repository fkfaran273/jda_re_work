"""whiten_decoder.py — INVERSE of the adj9 whitening cipher (pure Python).

Forward model (per 16-B chunk of the 144-B record, verified byte-exact against
the VM traces _inv2_row7_real.json.gz and _inv2_row7_rand.json.gz):

    WA0   = blob[0:16)               the header travels in the blob (IV)
    WA_k  = output of chunk k-1      CBC-style chain
    chunk = plaintext[16k:16k+16) ^ WA_k
    14 rounds r = 0..13:
        chunk[i] ^= 0x55 ^ KB[16r+i]         round-key sweep  (pc 0x111c68)
        chunk[i]  = T[chunk[i]] ^ 0x55       S-box            (pc 0x111f70)
        chunk    = pi1(chunk)                out[PI[i]] = in[i]
        if r < 13: chunk = F(chunk)          32-bit GF(2) linear map per
                                             4-B block (diag-2, 936/936)
    chunk[i] ^= 0x55 ^ KB[224+i]             final sweep
    body[16k:16k+16) = chunk                 == blob[16+16k : 32+16k)

The whitening covers blob[16:160) only (9 chunks = the 144-B record built at
VM MAIN [1134..1278); 2016 = 9*14*16 S-box events in the trace, and no
whitening events anywhere else on any stream).  blob[160:192) (words 40..47)
is a separate digest produced by other machinery and is NOT whitened by this
cipher.

Every step is a bijection, so the whole pipeline inverts with the extracted
constants alone -- no VM, no probing:

    T       256-byte S-box (a permutation)          T_INV[v] = x  iff  T[x] = v
    KB      240 B: 14 round keys (224 B) + final sweep (16 B), constant per VM
    pi1     fixed byte permutation, out[PI[i]] = in[i]
    F       32x32 GF(2) matrix, LINEAR (constant = 0), circulant; F_MINV is
            its exact inverse (F_inv(F(x)) == x; 936/936 block samples from
            both traces)

Decode: blob[16:160) --inverse-chain--> record (144 B).  The record layout
(vm_inverse.md / body_decoder.py):

    [0:3)     01 00 08
    [3:19)    head = d0[0..3] words rev16'd, LE-packed
    [19]      02
    [20:24)   d2 descriptor word, stored little-endian
              (BIG-endian read of these 4 bytes = the F.py native seed S)
    [24]      03
    [25:45)   d9 = APK cert SHA-1 (fad0f10d...)
    [45]      04
    [46:78)   32-B hash-like block
    [78]      05
    [79:111)  SHA256("")
    [111:114) 06 01 07
    [114:128) 00*14
    [128:130) tail2
    [130:144) 0e*14

Region reconstruction from a decoded record (validated convention, NOT the
one in body_decoder.region_from -- that one byteswaps the wrong way):

    d2_descriptor = LE32(record[20:24))
    F_seed        = BE32(record[20:24))  == byteswap(d2_descriptor)
    d4w           = F._d4_words(F_seed)
    d0w           = F._d0_words(d4w, head=phase)   phase from head match
    head          == rev16-LE-pack(d0w[0..3])

Validation (whiten_decoder.md):
  * forward(record) == blob[16:160) byte-exact, real AND rand traces
  * inverse(blob[16:160)) == record byte-exact
  * corpus rows 0,1,4,5,6,7 (pair_h3 blobs): decoded regions match
    all_signings.json d0/d2/d4 byte-exact
  * genuine winning blobs (win_capture): record decodes cleanly (all constant
    bytes + cert SHA-1 verified); their d0 head selector phase belongs to the
    winning device's own process state, so F.py region reconstruction (which
    only knows the test device's HEAD_FIRST/HEAD_RESIGN phases) does not
    reproduce those heads -- the decode itself is unaffected.

Usage:
    python whiten_decoder.py            # full validation + corpus + win decode
    python whiten_decoder.py --fast     # skip the (slow) trace round-trips
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# extracted constants (VM memory T[621..877), KB[877..1116), diag-1/diag-2)
# ---------------------------------------------------------------------------
T_HEX = "3629222ea73e3a906554327eab82fe239fd79c28af0c12a5f881f7fac9f12795e2a8c673636aa29961f0b0a4248d6440519276964dc350cf5247d5b7be72e7205cd6794f4e3b0ff5076e83e67cb67ad1068455b875a9e40e3f9eeb6c1f190d9a85baffae161866d010ac572a0569cafd04f615dac7c86da0e9e38f7445aaa687985946b90ac2114291f22b6831084c2635d41a89777fc5dd13bbed418b0b5e8eb5676f5f1c5371099786f937c4c0b12cb29d6238d8801bfc3903a1bf302ffb5def2d707b49f3e193bd88214a1ee8dedf256be0331d56a35b346002ecd39448cbb4adcd443c8cdbc1ce4bd2bc9b007d8ad9f4dc58eab3173d14cc785ae501ee43"
KB_HEX = "43fc368804c8ed1b17e5c8f603002f469e8f7ca2b2713e088c3f18324e1bc3046d6ce7273cf15f697e41c2ca2814b8d9610c29c68628429b5f420ffc440c99ada427a6a5cd83ac99e6973b069bd6d68aeae0c558399dd296338a883f22d344c7e4a5e9507c73109ccfb17ecf0132fd10ca650736a6ad80f5c0725d9fb7f44c0dde7183c8f757c6016db3ed9b39d445de9a69cd0b699118abfcb610611e170939e23bd37b4039402f78dff8e1145ee86a1942b77e2586fa808c65bfb4c727e3d882758e3497199b4eba9336fafb988bc5fdffaa1e8d2c05cb541cef2ac66e59a7208b07e8e2c7c9f30d01aa5ca3cc74cc"
PI = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
PI_INV = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
F_ROWS = [0x01018180, 0x02028381, 0x04040602, 0x08088c84, 0x10109888,
          0x20203010, 0x40406020, 0x8080c040, 0x01818001, 0x02838102,
          0x04060204, 0x088c8408, 0x10988810, 0x20301020, 0x40602040,
          0x80c04080, 0x81800101, 0x83810202, 0x06020404, 0x8c840808,
          0x98881010, 0x30102020, 0x60204040, 0xc0408080, 0x80010181,
          0x81020283, 0x02040406, 0x8408088c, 0x88101098, 0x10202030,
          0x20404060, 0x408080c0]
F_C = 0x00000000
F_MINV = [0x2161a1e0, 0x62a2e321, 0xc445c643, 0xa9eb2d67, 0x72b6fa2e,
          0xe46cf45c, 0xc8d8e8b8, 0x90b0d070, 0x61a1e021, 0xa2e32162,
          0x45c643c4, 0xeb2d67a9, 0xb6fa2e72, 0x6cf45ce4, 0xd8e8b8c8,
          0xb0d07090, 0xa1e02161, 0xe32162a2, 0xc643c445, 0x2d67a9eb,
          0xfa2e72b6, 0xf45ce46c, 0xe8b8c8d8, 0xd07090b0, 0xe02161a1,
          0x2162a2e3, 0x43c445c6, 0x67a9eb2d, 0x2e72b6fa, 0x5ce46cf4,
          0xb8c8d8e8, 0x7090b0d0]

T = bytes.fromhex(T_HEX)
KB = bytes.fromhex(KB_HEX)
T_INV = [0] * 256
for _x, _v in enumerate(T):
    T_INV[_v] = _x

D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")   # cert SHA-1
SHA0 = hashlib.sha256(b"").digest()

REC_N = 144


# ---------------------------------------------------------------------------
# the diag-2 GF(2) linear map F (32-bit little-endian words)
# ---------------------------------------------------------------------------
def F_word(x):
    y = 0
    for j in range(32):
        m = F_ROWS[j] & x
        b = 0
        while m:
            b ^= m & 1
            m >>= 1
        y |= b << j
    return y


def F_word_inv(y):
    x = 0
    for i in range(32):
        m = F_MINV[i] & y
        b = 0
        while m:
            b ^= m & 1
            m >>= 1
        x |= b << i
    return x


def _F(chunk):
    return b"".join(F_word(int.from_bytes(chunk[4 * b:4 * b + 4], "little"))
                    .to_bytes(4, "little") for b in range(4))


def _F_inv(chunk):
    return b"".join(F_word_inv(int.from_bytes(chunk[4 * b:4 * b + 4], "little"))
                    .to_bytes(4, "little") for b in range(4))


def _pi1(chunk):
    out = bytearray(16)
    for i in range(16):
        out[PI[i]] = chunk[i]
    return bytes(out)


def _pi1_inv(chunk):
    # undo out[PI[i]] = in[i]  ->  in[i] = out[PI[i]]
    return bytes(chunk[PI[i]] for i in range(16))


# ---------------------------------------------------------------------------
# forward (validation reference)
# ---------------------------------------------------------------------------
def whiten_chunk(chunk, WA, _kb=KB):
    """One forward chunk: 14 rounds + final sweep.  (chunk ^ WA is inside.)"""
    x = bytearray(a ^ b for a, b in zip(chunk, WA))
    for r in range(14):
        x = bytearray(v ^ 0x55 ^ _kb[16 * r + i] for i, v in enumerate(x))
        x = bytearray(T[v] ^ 0x55 for v in x)
        x = bytearray(_pi1(bytes(x)))
        if r < 13:
            x = bytearray(_F(bytes(x)))
    return bytes(v ^ 0x55 ^ _kb[224 + i] for i, v in enumerate(x))


def whiten_forward(record, header):
    """record: 144 B plaintext, header: 16 B IV -> whitened body (144 B)."""
    out = bytearray()
    wa = header
    for k in range(len(record) // 16):
        c = whiten_chunk(record[16 * k:16 * k + 16], wa)
        out += c
        wa = c
    return bytes(out)


# ---------------------------------------------------------------------------
# the inverse
# ---------------------------------------------------------------------------
def whiten_inverse(chunk, WA, KB_=None, T_inv=None, pi1_inv=None, F_inv=None):
    """Invert one whitened 16-B chunk given its WA (previous chunk final, or
    the header for chunk 0).  Returns the recovered 16-B plaintext chunk.

    KB_      : 240-B key table            (default: extracted KB)
    T_inv    : 256-entry inverse S-box    (default: extracted T_INV)
    pi1_inv  : inverse byte permutation   (default: extracted PI_INV);
               must satisfy pi1_inv(pi1(x)) == x
    F_inv    : callable 16 B -> 16 B inverting the diag-2 map (default _F_inv)
    """
    kb = KB if KB_ is None else KB_
    tinv = T_INV if T_inv is None else T_inv
    pinv = _pi1_inv if pi1_inv is None else pi1_inv
    finv = _F_inv if F_inv is None else F_inv
    x = bytes(v ^ 0x55 ^ kb[224 + i] for i, v in enumerate(chunk))  # final sweep
    for r in range(13, -1, -1):
        if r < 13:
            x = finv(x)                       # undo diag-2 affine
        x = pinv(x)                           # undo diag-1 permutation
        x = bytes(tinv[v ^ 0x55] for v in x)  # undo S-box
        x = bytes(v ^ 0x55 ^ kb[16 * r + i] for i, v in enumerate(x))
    return bytes(a ^ b for a, b in zip(x, WA))  # remove the WA XOR


def whiten_body_inverse(body, header, KB_=None, T_inv=None, pi1_inv=None,
                        F_inv=None):
    """body: 144 whitened bytes (blob[16:160)), header: blob[0:16).
    Returns the 144-B record."""
    out = bytearray()
    wa = header
    for k in range(len(body) // 16):
        p = whiten_inverse(body[16 * k:16 * k + 16], wa, KB_, T_inv,
                           pi1_inv, F_inv)
        out += p
        wa = body[16 * k:16 * k + 16]
    return bytes(out)


# ---------------------------------------------------------------------------
# record -> region (validated convention)
# ---------------------------------------------------------------------------
CONST_CHECKS = (
    ((0, 3), bytes.fromhex("010008")),
    ((19, 20), b"\x02"),
    ((24, 25), b"\x03"),
    ((45, 46), b"\x04"),
    ((78, 79), b"\x05"),
    ((79, 111), SHA0),
    ((111, 114), bytes.fromhex("060107")),
    ((114, 128), b"\x00" * 14),
    ((130, 144), b"\x0e" * 14),
)


def record_checks(record):
    ok = all(record[a:b] == want for (a, b), want in CONST_CHECKS)
    ok = ok and record[25:45] == D9
    return ok


def head_words(d0w):
    return b"".join(struct.pack("<I", ((w & 0xFFFF) << 16) | (w >> 16))
                    for w in d0w[:4])


def region_from_record(record):
    """record -> (d0 36 B, d2 4 B, d4 32 B) via the F.py laws, or None."""
    try:
        import F as Fmod
    except ImportError:
        sys.path.insert(0, HERE)
        try:
            import F as Fmod  # noqa: F811
        except ImportError:
            return None
    seed = int.from_bytes(record[20:24], "big")      # F.py native seed
    d2w = int.from_bytes(record[20:24], "little")    # d2 descriptor word
    head = record[3:19]
    d4w = Fmod._d4_words(seed)
    for name, phase in (("HEAD_FIRST", Fmod.HEAD_FIRST),
                        ("HEAD_RESIGN", Fmod.HEAD_RESIGN)):
        d0w = Fmod._d0_words(d4w, head=phase)
        if head_words(d0w) == head:
            d0 = b"".join(w.to_bytes(4, "big") for w in d0w)
            d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
            return {"d0": d0, "d2": d2w.to_bytes(4, "big"), "d4": d4,
                    "seed": seed, "d2w": d2w, "phase": name,
                    "d0w": d0w, "d4w": d4w}
    return None


def decode_blob(blob):
    """192-B adj9 signature blob -> dict(record, checks, region)."""
    blob = bytes(blob)
    if len(blob) != 192:
        raise ValueError("blob must be 192 bytes, got %d" % len(blob))
    header, body = blob[:16], blob[16:160]
    record = whiten_body_inverse(body, header)
    region = region_from_record(record)
    return {
        "header": header,
        "record": record,
        "consts_ok": record_checks(record),
        "head": record[3:19],
        "d2w": int.from_bytes(record[20:24], "little"),
        "F_seed": int.from_bytes(record[20:24], "big"),
        "block": record[46:78],
        "tail2": record[128:130],
        "region": region,
    }


# ---------------------------------------------------------------------------
# validation / demo main
# ---------------------------------------------------------------------------
def _load_traces():
    import gzip
    out = []
    for fn in ("_inv2_row7_real.json.gz", "_inv2_row7_rand.json.gz"):
        p = os.path.join(HERE, fn)
        if os.path.exists(p):
            out.append(json.load(gzip.open(p, "rt")))
    return out


def main():
    fast = "--fast" in sys.argv
    print("=== adj9 whitening decoder - validation ===")
    print("T permutation:", len(set(T)) == 256)
    print("KB[0:16]   :", KB[:16].hex())
    print("KB[224:240]:", KB[224:240].hex())
    print("pi1        :", PI)
    print("F linear, F_inv(F(x))==x:",
          all(F_word_inv(F_word(x)) == x
              for x in (0, 1, 0x80000001, 0xDEADBEEF, 0xFFFFFFFF)))
    print()

    # -- 1. trace round-trips (forward AND inverse, byte-exact) --------------
    if not fast:
        for A in _load_traces():
            blob = bytes.fromhex(A["blob"])
            rec = bytes.fromhex(A["record"])
            body = whiten_forward(rec, blob[:16])
            back = whiten_body_inverse(blob[16:160], blob[:16])
            print("trace row %-3s (%s) forward==blob[16:160): %-5s "
                  "inverse==record: %s"
                  % (A.get("row", "?"), A.get("status", "?"),
                     body == blob[16:160], back == rec))
        print()

    # -- 2. corpus decode (pair_h3 blobs, all_signings regions) --------------
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    als = json.load(open(os.path.join(HERE, "all_signings.json")))
    nok = 0
    print("--- corpus (pair_h3 blobs, all_signings regions) ---")
    for r in ph3:
        i = r["i"]
        blob = bytes.fromhex(r["blob"])
        dec = decode_blob(blob)
        reg = dec["region"]
        a = als[i]
        ok_c = dec["consts_ok"]
        if reg is None:
            print("row %d: consts=%s region=None (head %s)"
                  % (i, ok_c, dec["head"].hex()))
            continue
        ok = (reg["d0"].hex() == a["d0"] and reg["d2"].hex() == a["d2"]
              and reg["d4"].hex() == a["d4"])
        nok += ok
        print("row %d: consts=%s region_match=%s phase=%s seed=%08x d2=%08x"
              % (i, ok_c, ok, reg["phase"], reg["seed"], reg["d2w"]))
    print("corpus region matches: %d/%d" % (nok, len(ph3)))

    # -- 2b. cross-pairing: which all_signings row does each blob belong to --
    # (pair_h3's capture->sample assignment is a heuristic; rows 2/4 carry the
    # SAME capture and row 3's capture has no sample in all_signings)
    print()
    print("--- cross-pairing by decoded d2 word / full region ---")
    decs = {r["i"]: decode_blob(bytes.fromhex(r["blob"])) for r in ph3}
    for j in range(len(als)):
        a = als[j]
        d2hits = [i for i, d in decs.items()
                  if "%08x" % d["d2w"] == a["d2"]]
        full = [i for i, d in decs.items()
                if d["region"] and d["region"]["d0"].hex() == a["d0"]
                and d["region"]["d4"].hex() == a["d4"]]
        if d2hits or full:
            print("all_signings[%d] d2=%s : blob rows %s (full region %s)"
                  % (j, a["d2"], d2hits, full))
    orphan = {i: "%08x" % d["d2w"] for i, d in decs.items()
              if not any("%08x" % d["d2w"] == als[j]["d2"]
                         for j in range(len(als)))}
    print("decoded blobs with NO all_signings sample (pairing artifact):",
          orphan)
    print()

    # -- 3. genuine winning blobs --------------------------------------------
    wp = os.path.join(HERE, "win_capture", "winning_material.json")
    wr = os.path.join(HERE, "win_capture", "win_rows.json")
    if os.path.exists(wp):
        W = json.load(open(wp))
        rowsw = json.load(open(wr)).get("rows", []) if os.path.exists(wr) else []
        print("--- genuine winning blobs (%d) ---" % len(W["blobs"]))
        matched = 0
        for bi, bh in enumerate(W["blobs"]):
            dec = decode_blob(bytes.fromhex(bh))
            reg = dec["region"]
            tag = ""
            if reg is not None:
                for ri, rw in enumerate(rowsw):
                    dd = (rw.get("desc", {}).get("0") or {}).get("hex")
                    if dd and dd == reg["d0"].hex():
                        matched += 1
                        tag = ("  == win_rows[%d] (S=%d second=%d sign_id=%s)"
                               % (ri, rw.get("S", -1), rw.get("second", -1),
                                  rw.get("sign_id")))
            print("win blob %d: consts=%s d2w=%08x F_seed=%08x head=%s%s"
                  % (bi, dec["consts_ok"], dec["d2w"], dec["F_seed"],
                     dec["head"].hex(), tag))
        print("win blob <-> win_rows region matches: %d (of %d blobs, %d rows)"
              % (matched, len(W["blobs"]), len(rowsw)))


if __name__ == "__main__":
    main()

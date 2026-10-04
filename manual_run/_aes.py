"""_aes.py — hunt block32 as an AES output.

32 bytes fits: AES-256 ECB/CBC on 32-byte input, or a 32-byte slice of a
CTR keystream XORed with an intermediate.  Keys: every static round-key
group, adjacent pairs, the whole 240-byte KB, plus the other key-sized
tables in the signer.  Inputs: the known record fields and the claims.
"""
import hashlib
import re
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, ".")
import adj9_signature as SG

CAP = "../adj9/rev/creditsea/adj9_cap_declic.log"
text = open(CAP, "rb").read().decode("utf-8", "replace")
blob_hex = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", text)[0]
dec = SG.decode_blob(bytes.fromhex(blob_hex))
rec = dec["record"]
TARGET = rec[46:78]
seed = dec["F_seed"]
d4w = SG._d4_words(seed)
d0w = SG._d0_words(d4w, head=(43,))
claims = re.search(r"map_toString=\{([^}]*)\}", text).group(1).encode()
print("block32: %s" % TARGET.hex())

KB = SG.KB
groups = [bytes(KB[16 * i:16 * i + 16]) for i in range(15)]
keys = {}
for i, g in enumerate(groups):
    keys["g%d" % i] = g
    if i + 1 < 15:
        keys["g%d+g%d" % (i, i + 1)] = g + groups[i + 1]
keys["KB_all"] = bytes(KB)
keys["T_first16"] = SG.T[:16]
keys["Finv_first32"] = b"".join(w.to_bytes(4, "little") for w in SG.F_MINV[:8])
keys = {k: v for k, v in keys.items() if len(v) in (16, 24, 32)}

ZERO16 = bytes(16)
seed16 = seed.to_bytes(4, "big") * 4
inputs = {
    "S_be": seed.to_bytes(4, "big"),
    "S_le": seed.to_bytes(4, "little"),
    "d4": b"".join(w.to_bytes(4, "big") for w in d4w),
    "d0": b"".join(w.to_bytes(4, "big") for w in d0w),
    "cert": rec[25:45],
    "magic": rec[0:3],
    "head": rec[3:19],
    "rec_0_32": rec[0:32],
    "rec_0_46": rec[0:46],
    "rec_14_46": rec[14:46],
    "claims32": claims[:32],
    "claims_pad": claims[:32].ljust(32, bytes(1)),
    "zeros": bytes(32),
    "ones": b"\x0e" * 32,
}


def enc(alg, data):
    e = Cipher(alg[0], alg[1]).encryptor()
    return e.update(data) + e.finalize()


hits = []
for kname, key in keys.items():
    for iname, raw in inputs.items():
        pt = raw[:32].ljust(32, bytes(1))
        if enc((algorithms.AES(key), modes.ECB()), pt) == TARGET:
            hits.append("ECB key=%s data=%s" % (kname, iname))
        for ivname, iv in (("z", ZERO16), ("S", seed16)):
            if enc((algorithms.AES(key), modes.CBC(iv)), pt) == TARGET:
                hits.append("CBC-%s key=%s data=%s" % (ivname, kname, iname))
        for nname, nonce in (("z", ZERO16), ("S", seed16)):
            ks = enc((algorithms.AES(key), modes.CTR(nonce)), bytes(32))
            if bytes(a ^ b for a, b in zip(ks, pt)) == TARGET:
                hits.append("CTR key=%s nonce=%s data=%s" % (kname, nname, iname))
        for label, cand in (("sha(d+k)", hashlib.sha256(raw + key).digest()),
                            ("sha(k+d)", hashlib.sha256(key + raw).digest())):
            if cand == TARGET:
                hits.append("%s key=%s data=%s" % (label, kname, iname))

print("keys: %d  inputs: %d  modes: ECB/CBC(2)/CTR(2)/2x sha" %
      (len(keys), len(inputs)))
print("HITS:", hits if hits else "none")

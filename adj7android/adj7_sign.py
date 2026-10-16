# adj7 Android pure signer (3.62.0) — the complete law, stdlib-only.
#
# VERIFIED (2026-10-09): offline_verify.py reconstructs all 8 captured blobs
# (payruki/hanaf 5 + hunchdate/hunch 3) FULLY byte-exact:
#   header : bionic rand() TYPE_3 seeded by the sent_at epoch second,
#            310 warm-up draws discarded, then 8 draws pair-XORed into
#            4 big-endian dwords.
#   body   : CBC (IV = header) of the custom 15-round SPN over the
#            256-B record (spn.py: 4 seed pre-rounds + 0x75 tweak +
#            11 keyed rounds, keys = 184-B VM block ^0x55 lanes).
#   tag    : HMAC-SHA256(K, body).
#   record : '{ "a":<a rjust-22> ,"b": "<64hex>","c": "<cert40 ASCII-hex>",
#             ","d": "<hex nonce[0:4]>","e": "<sha256('') hex>" }' + NUL +
#             0x10*16.
#
# FRESH signing needs a + b, which the native derives inside its obfuscation
# VM from the entropy reads + the claims string (open law — use the emu
# signer sign_emu_cli.py for fresh mints; it runs the genuine native).
# REPLAY of a capture is fully offline: take a/b/d from its decrypted record.
import hmac, hashlib, struct, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spn import body_encrypt, body_decrypt, make_tag, chunk_encrypt, chunk_decrypt

class Random3Bionic:
    M = (1 << 31) - 1
    A = 16807
    Q = M // A
    R = M % A
    def __init__(self, seed):
        s = seed & 0xFFFFFFFF
        if s == 0:
            s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        self.r = [0] * 31
        self.r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi, lo = divmod(prev, self.Q)
            else:
                hi = -((-prev) // self.Q)
                lo = prev - hi * self.Q
            word = self.A * lo - self.R * hi
            if word < 0:
                word += self.M
            prev = word
            self.r[i] = word
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()
    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o

def make_header(second):
    g = Random3Bionic(int(second))
    d = [g.next() for _ in range(8)]
    words = [d[0] ^ d[1], d[2] ^ d[3], d[4] ^ d[5], d[6] ^ d[7]]
    return b"".join(struct.pack(">I", w) for w in words)

E_EMPTY = hashlib.sha256(b"").hexdigest().upper()

def build_record(a, b_hex, cert40_hex, d_hex):
    a_s = ("%22s" % a) if isinstance(a, int) else ("%22s" % str(a))
    return (('{ "a":' + a_s + ' ,"b": "' + b_hex.upper() +
             '","c": "' + cert40_hex.upper() + '","d": "' + d_hex.upper() +
             '","e": "' + E_EMPTY + '" }').encode() + b"\x00")

def pad_record(rec):
    n = 256 - len(rec)
    assert 0 < n <= 256, "record too long: %d" % len(rec)
    return rec + bytes([n]) * n

def sign_blob(second, a, b_hex, cert40_hex, nonce4_hex):
    """Full pure mint of a 304-B blob from explicit record fields."""
    header = make_header(second)
    record = pad_record(build_record(a, b_hex, cert40_hex, nonce4_hex))
    body = body_encrypt(record, header)
    return header + body + make_tag(body)

def auth_header(blob):
    return ('Signature signature="%s",adj_signing_id="1300000",'
            'algorithm="adj7",headers_id="8",native_version="3.62.0"'
            % blob.hex().upper())

if __name__ == "__main__":
    # self-test: reconstruct payruki sid 67 record fields -> byte-exact blob
    import json
    rows = [r for r in json.load(open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "cap", "payruki_signed.json"))) if "blob" in r]
    blob = bytes.fromhex(rows[2]["blob"])       # sid 67, second 1791358552
    rec = body_decrypt(blob[16:272], blob[:16])
    import re
    m = re.match(rb'\{ "a":\s*(\d+) ,"b": "([0-9A-F]+)","c": "([0-9A-F]+)",'
                 rb'"d": "([0-9A-F]+)",', rec)
    a = int(m.group(1))
    b = m.group(2).decode()
    c = m.group(3).decode()
    d = m.group(4).decode()
    got = sign_blob(1791358552, a, b, c, d)
    print("sid67 pure re-mint byte-exact:", got == blob)
    print(auth_header(got)[:100] + "...")

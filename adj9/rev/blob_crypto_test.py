"""Try the .rodata 32-byte constant pair against the captured 192-byte blobs.

.rodata:
  +0xc0 : 0123456789abcdeffedcba9876543210   (16B)
  +0xe0 : f0e1d2c39979825aa1ebd96edcbc1b8f   (16B)
  code at 0x12e5f4 stores both into a struct at +0x50 / +0x60, plus 0xca62c1d6 @+0x70
Tests: XOR keystream, AES-256 ECB/CBC (key=32B concat), AES-128 each half.
"""
from Crypto.Cipher import AES

BLOBS = {
    "cap1": "223b6f6e649348511dc9e61e70ab16a40023b27e101c68d2"
            "000000000000000000000000000000000000000000000000",
    "cap6a": "3d686b044f94aa857367a8d44bc83c416afd38926f45c3cd",
    "cap6b": "4dd3f0544ff1e7803cae627f44f7d778aeb35cb7f2b0ea08",
}
K1 = bytes.fromhex("0123456789abcdeffedcba9876543210")
K2 = bytes.fromhex("f0e1d2c39979825aa1ebd96edcbc1b8f")
K32 = K1 + K2

import glob
import os
import re

CAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cap")
real = {}
for lg in sorted(glob.glob(os.path.join(CAP, "*.log"))):
    for ln in open(lg, encoding="utf-8", errors="replace"):
        m = re.search(r"hex=([0-9a-fA-F]{384})\b", ln)
        if m:
            b = bytes.fromhex(m.group(1).lower())
            if len(b) == 192 and b[:2] not in (b"\x30\x82", b"\x30\x76"):
                real[os.path.basename(lg) + "#" + str(len(real))] = b.hex()
BLOBS = real if real else BLOBS


def show(name, out):
    printable = sum(1 for c in out if 32 <= c < 127)
    pad = out[-1] if out else 0
    okpad = 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad
    print("  %-26s print=%3d/192 last16=%s %s" %
          (name, printable, out[-16:].hex(), "PKCS7-OK" if okpad else ""))
    if printable > 120:
        print("      %r" % out)


def main():
    print("blobs: %d" % len(BLOBS))
    for name, h in BLOBS.items():
        b = bytes.fromhex(h)
        print("\n=== %s ===" % name)
        show("raw", b)
        # XOR with repeating 32-byte key
        ks = (K32 * (192 // 32 + 1))[:192]
        show("xor K32 repeating", bytes(x ^ y for x, y in zip(b, ks)))
        show("xor K1 repeating", bytes(x ^ y for x, y in zip(b, (K1 * 13)[:192])))
        show("xor K2 repeating", bytes(x ^ y for x, y in zip(b, (K2 * 13)[:192])))
        # AES
        try:
            show("aes256-ecb-dec K32", AES.new(K32, AES.MODE_ECB).decrypt(b))
        except Exception as e:
            print("  aes256ecb:", e)
        try:
            show("aes256-cbc K32 iv=0", AES.new(K32, AES.MODE_CBC, b"\x00" * 16).decrypt(b))
        except Exception as e:
            print("  aes256cbc:", e)
        try:
            show("aes256-cbc K32 iv=b[:16]", AES.new(K32, AES.MODE_CBC, b[:16]).decrypt(b[16:]))
        except Exception as e:
            print("  aes256cbc2:", e)
        for i, k in enumerate((K1, K2)):
            try:
                show("aes128-ecb-dec K%d" % (i + 1), AES.new(k, AES.MODE_ECB).decrypt(b))
            except Exception as e:
                print("  aes128:", e)
        # CTR with the two halves as nonce
        try:
            from Crypto.Util import Counter
            ctr = Counter.new(64, prefix=K1[:8], initial_value=int.from_bytes(K2[:8], "big"))
            show("aes256-ctr K32", AES.new(K32, AES.MODE_CTR, counter=ctr).decrypt(b))
        except Exception as e:
            print("  ctr:", e)


if __name__ == "__main__":
    main()

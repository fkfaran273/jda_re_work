"""Shared constants for the conststruct_ analysis."""
import hashlib

KB = bytes.fromhex(
    "43fc368804c8ed1b17e5c8f603002f469e8f7ca2b2713e088c3f18324e1bc304"
    "6d6ce7273cf15f697e41c2ca2814b8d9610c29c68628429b5f420ffc440c99ad"
    "a427a6a5cd83ac99e6973b069bd6d68aeae0c558399dd296338a883f22d344c7"
    "e4a5e9507c73109ccfb17ecf0132fd10ca650736a6ad80f5c0725d9fb7f44c0d"
    "de7183c8f757c6016db3ed9b39d445de9a69cd0b699118abfcb610611e170939"
    "e23bd37b4039402f78dff8e1145ee86a1942b77e2586fa808c65bfb4c727e3d8"
    "82758e3497199b4eba9336fafb988bc5fdffaa1e8d2c05cb541cef2ac66e59a7"
    "208b07e8e2c7c9f30d01aa5ca3cc74cc")
IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                    "7a30ed9323473054bbe3cd00f1355ea5")
K = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                  "0451723fbcfa92df62b55f6fec60f2de")
assert len(KB) == 240 and len(IV2) == 32 and len(K) == 32

# standard SHA-256 IV
SHA256_IV = bytes.fromhex(
    "6a09e667bb67ae853c6ef372a54ff53a"
    "510e527f9b05688c1f83d9ab5be0cd19")
SHA512_IV = bytes.fromhex(
    "6a09e667f3bcc908b2fb1366ea957d3e3adec17512775038"
    "19db70c2bd72ac3517cc3ec53f1ba46ce111275e3a70ba0f")


def blocks(b, n=16):
    return [b[i:i + n] for i in range(0, len(b), n)]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def rotl(b, n):
    n %= len(b) * 8
    x = int.from_bytes(b, "big")
    L = len(b) * 8
    return (((x << n) & ((1 << L) - 1)) | (x >> (L - n))).to_bytes(len(b), "big")


def popcount(b):
    return sum(bin(x).count("1") for x in b)


def shannon(data):
    from collections import Counter
    import math
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())

"""Decode libsigner.so's obfuscated .data string table.

Observed framing (derived from 5 known-good entries):
    [ ciphertext bytes ][ 1 xor-key byte ][ 0x00 terminator ]
i.e. every NUL-terminated run in .data is a candidate entry; the byte
immediately before the NUL is the per-entry XOR key.

Also provides a generic printable-ASCII scanner for .rodata.
"""
import string

PRINT = set(bytes(string.printable[:95], "ascii"))  # 0x20..0x7e


def decode_entry(tok: bytes):
    """tok = bytes BEFORE the terminating NUL (i.e. ciphertext+key)."""
    if len(tok) < 2:
        return None
    key = tok[-1]
    if key == 0:
        return None
    out = bytes(b ^ key for b in tok[:-1])
    if not out:
        return None
    if any(b not in PRINT for b in out):
        return None
    return out.decode("ascii")


def scan(data: bytes, base_va: int, minlen: int = 2):
    """yield (va, plaintext, ciphertext_len, key) for every NUL-terminated run."""
    res = []
    i = 0
    n = len(data)
    while i < n:
        j = data.find(b"\x00", i)
        if j < 0:
            break
        tok = data[i:j]
        if tok:
            s = decode_entry(tok)
            if s is not None and len(s) >= minlen:
                res.append((base_va + i, s, len(tok) - 1, tok[-1]))
        i = j + 1
    return res


def scan_plain(data: bytes, base_va: int, minlen: int = 4):
    res = []
    i = 0
    n = len(data)
    while i < n:
        j = data.find(b"\x00", i)
        if j < 0:
            j = n
        tok = data[i:j]
        if len(tok) >= minlen and all(b in PRINT for b in tok):
            res.append((base_va + i, tok.decode("ascii")))
        i = j + 1
    return res

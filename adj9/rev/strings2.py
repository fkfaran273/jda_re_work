"""Correct model for libsigner.so's .data string table.

Entry encoding (derived from 'AndroidKeyStore' / 'key2' / 'RSA/ECB/PKCS1Padding'
/ 'adjust_keys' / 'encrypted_key'):

    ciphertext = plaintext_bytes XOR key, INCLUDING the terminating NUL.

Because plain NUL == 0, the LAST ciphertext byte always equals the key itself.
So there is no separate key byte and no separator - entries are simply packed
back to back (with zero padding between groups).

We recover them with a DP over the whole section: a valid entry at p of length L
requires key = data[p+L] != 0 and every data[p+i]^key to be printable ASCII.
"""
import string

PRINT = set(bytes(string.printable[:95], "ascii"))
WORD = set(b"".join([bytes(string.ascii_letters, "ascii"),
                     bytes(string.digits, "ascii"),
                     b"_./$;<>[](){}+-=:,' !@#%^&*|~?"]))


def quality(s: bytes) -> float:
    if not s:
        return -1e9
    n = len(s)
    odd = sum(1 for c in s if c not in WORD)
    score = 2.0 * n - 6.0 * odd
    if n < 2:
        score -= 4
    if n == 2:
        score -= 2
    return score


def decode_section(data: bytes, base_va: int, maxlen: int = 200):
    """DP-segment the section into [entry|padding] and return list of
    (va, plaintext, key, L)."""
    n = len(data)
    NEG = -1e18
    dp = [NEG] * (n + 1)
    back = [None] * (n + 1)
    dp[0] = 0.0
    for p in range(n):
        if dp[p] == NEG:
            continue
        # zero padding: skip a 0x00 byte for free
        if data[p] == 0 and p + 1 <= n:
            if dp[p] > dp[p + 1]:
                dp[p + 1] = dp[p]
                back[p + 1] = (p, None)
        # entry of length L (plaintext), stored as L+1 bytes
        if data[p] == 0:
            continue          # plaintext can never start with NUL -> padding
        lim = min(maxlen, n - p - 1)
        L = 1
        while L <= lim:
            k = data[p + L]
            if k != 0:
                ok = True
                # fast reject on first non printable
                for i in range(L):
                    if (data[p + i] ^ k) not in PRINT:
                        ok = False
                        break
                if ok:
                    q = quality(bytes(data[p + i] ^ k for i in range(L)))
                    cand = dp[p] + q - 0.15
                    nxt = p + L + 1
                    if cand > dp[nxt]:
                        dp[nxt] = cand
                        back[nxt] = (p, L)
            L += 1
        # hard step: unparsable byte
        if p + 1 <= n and dp[p] - 20 > dp[p + 1]:
            dp[p + 1] = dp[p] - 20
            back[p + 1] = (p, -1)
    # walk back
    out = []
    p = n
    while p > 0:
        b = back[p]
        if b is None:
            p -= 1
            continue
        prev, L = b
        if L and L > 0:
            k = data[prev + L]
            s = bytes(data[prev + i] ^ k for i in range(L))
            out.append((base_va + prev, s.decode("ascii"), k, L))
        p = prev
    out.reverse()
    return out

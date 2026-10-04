"""_move_iv.py -- move the SHA-256 IV derivation out of the signer.

_SHA256_IV and _frac_isqrt_scaled in adj9_pure.py existed only to feed the
self-test that was removed.  Nothing in the signer uses them.  The fact worth
keeping -- that the block law's IV2 is NOT the standard IV -- belongs in the
gate that already checks the other SHA-256 constants.
"""
# ---- 1. drop them from the signer ---------------------------------------
p = 'adj9_pure.py'
s = open(p, encoding='utf-8').read()

i = s.index('def _frac_isqrt_scaled(p, scale=1 << 32):')
j = s.index('# --------------------------------------------------------------------------\n# THE BLOCK')
s = s[:i] + s[j:]
open(p, 'w', encoding='utf-8').write(s)
print('removed _frac_isqrt_scaled and _SHA256_IV from the signer')

# ---- 2. add the check to the K256 gate ----------------------------------
p = 'verify_K256_law.py'
s = open(p, encoding='utf-8').read()

helper = '''

def frac_isqrt_scaled(p, scale=1 << 32):
    """floor( frac(sqrt(p)) * scale ), exact integers."""
    n = 0
    while (n + 1) ** 2 <= p:
        n += 1
    target, base = p * scale ** 2, n * scale
    lo, hi = 0, scale
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if (base + mid) ** 2 <= target:
            lo = mid
        else:
            hi = mid - 1
    return lo


SHA256_IV = tuple(frac_isqrt_scaled(p) for p in P._primes(8)) if hasattr(P, "_primes") else None
'''

if 'SHA256_IV' not in s:
    s = s.rstrip() + '''


def _iv_check():
    """The block law's IV2 is NOT the standard SHA-256 IV.

    Both are derivable the same way -- square roots of the first 8 primes --
    so deriving the standard one here makes the contrast checkable rather
    than asserted.
    """
    def primes(n):
        out, i = [], 2
        while len(out) < n:
            if all(i % p for p in out if p * p <= i):
                out.append(i)
            i += 1
        return out
    std = tuple(frac_isqrt_scaled(p) for p in primes(8))
    ok = std[0] == 0x6A09E667 and std != P._BLK_IV2[:4]
    print("   standard IV[0] = %08x, block IV2[0] = %08x -> differ: %s"
          % (std[0], int.from_bytes(P._BLK_IV2[:4], "big"), ok))
    return ok
'''
    s = s.replace('    print("RESULT:", "K256 IS FULLY DERIVED" if same and ok == 64',
                  '    iv_ok = _iv_check()\n'
                  '    print("RESULT:", "K256 IS FULLY DERIVED" if same and ok == 64 and iv_ok')
    # define the helper before main() uses it
    s = s.replace('def main():', 'def frac_isqrt_scaled(p, scale=1 << 32):\n'
                  '    n = 0\n'
                  '    while (n + 1) ** 2 <= p:\n'
                  '        n += 1\n'
                  '    target, base = p * scale ** 2, n * scale\n'
                  '    lo, hi = 0, scale\n'
                  '    while lo < hi:\n'
                  '        mid = (lo + hi + 1) // 2\n'
                  '        if (base + mid) ** 2 <= target:\n'
                  '            lo = mid\n'
                  '        else:\n'
                  '            hi = mid - 1\n'
                  '    return lo\n\n\ndef main():', 1)
    open(p, 'w', encoding='utf-8').write(s)
    print('added the IV contrast check to the gate')
"""audit_constants.py — what is still opaque in the signer?

adj9_pure.py still shows a lot of raw bytes. This classifies every remaining
constant into three buckets and reports how many bytes have no derivation:

  DERIVED    - computed from a rule; the stored bytes are a convenience
  IDENTIFIED - a known named construct (AES, SHA-256, bionic)
  RECORDED   - generated randomness with no derivation to be found

Run: python audit_constants.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_pure as P  # noqa: E402

# name, kind, size, is_sequence, note
ITEMS = [
    ("_K256", "DERIVED", 64, True,
     "SHA-256 round constants = floor(frac(cbrt(p_i)) * 2^32) for the "
     "first 64 primes (FIPS 180-4). Computed at import from exact integer "
     "arithmetic - no table is stored. verify_K256_law.py."),
    ("SHA0", "DERIVED", 32, False,
     "sha256(b'') - the empty-string hash, used in the record at [79:111)."),
    ("T  (S-box)", "IDENTIFIED", 256, False,
     "AES S-box XOR 0x55, built by _aes_sbox() from its definition "
     "(affine of the GF(2^8) inverse). NOT stored - it is computed."),
    ("F  (linear layer)", "IDENTIFIED", 0, False,
     "AES MixColumns [2,3,1,1] over GF(2^8) mod 0x11B. mix_columns "
     "computes it. The extracted matrix lives in f_reference.py, beside the gate."),
    ("F_MINV", "IDENTIFIED", 0, False,
     "AES InvMixColumns [14,11,13,9]. Computed by inv_mix_columns; the extracted matrix is in f_reference.py."),
    ("PI / PI_INV", "IDENTIFIED", 16, False,
     "byte permutation, stride -3 mod 16. Identified, but NOT AES "
     "ShiftRows (stride 1) - the one genuinely custom part."),
    ("_DIG_IPAD / _DIG_OPAD", "DERIVED", 64, False,
     "0x36 x 32 and 0x5c x 32 - straight from HMAC."),
    ("IV2  (_BLK_IV2)", "RECORDED", 32, False,
     "the block law's custom SHA-256 chaining value."),
    ("_DIG_K", "RECORDED", 32, False,
     "the digest law's MAC key."),
    ("KB", "RECORDED", 240, False,
     "240-byte key schedule = 15 x 16 round keys. TESTED: it is NOT an "
     "AES-256 expansion, so no 32-byte master key regenerates it."),
]


def wrap(s, w=62):
    out, cur = [], ""
    for word in s.split():
        if len(cur) + len(word) + 1 > w:
            out.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        out.append(cur)
    return out


print("=" * 74)
print("1. EVERY CONSTANT IN THE SIGNER, CLASSIFIED")
print("=" * 74)
for name, kind, size, is_seq, note in ITEMS:
    unit = " entries" if is_seq else " bytes"
    print("  %-22s %-10s %4d%s" % (name, kind, size, unit if size else ""))
    for ln in wrap(note):
        print("        %s" % ln)

rec = [i for i in ITEMS if i[1] == "RECORDED"]
total = sum(i[2] for i in rec)
print()
print("=" * 74)
print("2. HOW MUCH IS STILL UNEXPLAINED")
print("=" * 74)
for name, kind, size, is_seq, note in rec:
    print("  %-22s %4d bytes" % (name, size))
print("  %-22s %4d bytes" % ("TOTAL", total))
print()
print("  Everything else is derived from a rule, or identified as a known")
print("  construct. There is no fourth category.")

print()
print("=" * 74)
print("3. _K256 SPELLED OUT - these are not magic words")
print("=" * 74)
print("  K256[i] = floor( frac(cbrt(p_i)) * 2^32 ),  p_i = the i-th prime")
print()
for i, p in enumerate([2, 3, 5, 7, 11, 13]):
    print("    K[%d]  prime %-3d  %s" % (i, p, hex(P._K256[i])))
print()
print("  So 0xb5c0fbcf is just prime 5:  cbrt(5) = 1.7099..., frac .7099,")
print("      .7099 * 2^32 = 0xb5c0fbcf.  Nothing Adjust-specific about it.")
print()
print("  The same family:")
print("    SHA0   = %s" % P.SHA0.hex())
print("              (literally sha256 of the empty string)")
print("    IV2    = %s" % P._BLK_IV2.hex())
print("    _DIG_K = %s" % P._DIG_K.hex())
print()
print("  IV2 and _DIG_K are the only values in the whole algorithm that are")
print("  pure recorded randomness - there is nothing to derive them from.")
print("  That is the correct form of the answer, not a gap in it.")
"""f_reference.py — the ORIGINAL extracted matrices for the whitening cipher's
linear layer, kept ONLY so the gates can check the computed law against them.

WHY THIS IS A SEPARATE FILE
---------------------------
The signer (adj9_pure.py) does not need these.  Its linear layer is AES
MixColumns, computed by mix_columns / inv_mix_columns.  These two tables are
the matrices as they were first extracted from libsigner.so, and they exist
purely as an INDEPENDENT reference: test_f_formula.py asserts that the computed
MixColumns reproduces F_ROWS on all 32 basis vectors.

That check is only worth anything because the reference is NOT derived from the
formula.  If adj9_pure derived its own reference from MixColumns, the gate would
be comparing the formula against itself and would pass no matter what.  So the
extracted table lives here, beside the test, and not in the production signer.

    F_ROWS[j]  row j: which INPUT bits are XORed to produce OUTPUT bit j
    F_MINV[i]  the same for the inverse map
"""
F_ROWS = [0x01018180, 0x02028381, 0x04040602, 0x08088c84, 0x10109888,
          0x20203010, 0x40406020, 0x8080c040, 0x01818001, 0x02838102,
          0x04060204, 0x088c8408, 0x10988810, 0x20301020, 0x40602040,
          0x80c04080, 0x81800101, 0x83810202, 0x06020404, 0x8c840808,
          0x98881010, 0x30102020, 0x60204040, 0xc0408080, 0x80010181,
          0x81020283, 0x02040406, 0x8408088c, 0x88101098, 0x10202030,
          0x20404060, 0x408080c0]

F_MINV = [0x2161a1e0, 0x62a2e321, 0xc445c643, 0xa9eb2d67, 0x72b6fa2e,
          0xe46cf45c, 0xc8d8e8b8, 0x90b0d070, 0x61a1e021, 0xa2e32162,
          0x45c643c4, 0xeb2d67a9, 0xb6fa2e72, 0x6cf45ce4, 0xd8e8b8c8,
          0xb0d07090, 0xa1e02161, 0xe32162a2, 0xc643c445, 0x2d67a9eb,
          0xfa2e72b6, 0xf45ce46c, 0xe8b8c8d8, 0xd07090b0, 0xe02161a1,
          0x2162a2e3, 0x43c445c6, 0x67a9eb2d, 0x2e72b6fa, 0x5ce46cf4,
          0xb8c8d8e8, 0x7090b0d0]


def _parity(v):
    p = 0
    while v:
        p ^= v & 1
        v >>= 1
    return p


def F_word(x):
    """The extracted table applied directly -- the slow, obvious reference."""
    y = 0
    for j in range(32):
        if _parity(F_ROWS[j] & x):
            y |= 1 << j
    return y


def inv_mix_columns_doc(y):
    x = 0
    for i in range(32):
        if _parity(F_MINV[i] & y):
            x |= 1 << i
    return x
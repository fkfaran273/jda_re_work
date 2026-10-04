"""region_synth.py - generate a structurally lawful #0/#2/#4 (v2).

All laws verified against 11+ genuine captures. Key constraint (slice 140):
#4 has a GRADUAL popcount density profile: ~2,~4,~7,~9,~11,~13,~15,~16
This is what the server can verify — our synth must match it exactly.
"""
import secrets
import struct


def _random_popcount(target):
    """Generate a 32-bit word with exactly `target` bits set (direct)."""
    positions = list(range(32))
    secrets.SystemRandom().shuffle(positions)
    v = 0
    for p in positions[:target]:
        v |= (1 << p)
    return v



def _w():
    return secrets.randbits(32)


def synth_region():
    """Generate #0 (36 words), #2 (1 word), #4 (8 words) with all measured laws."""
    W0, T0, T1 = _w(), _w(), _w()
    R = secrets.randbits(16)
    Xlo = (T0 ^ T1) & 0xFFFF
    T3 = T1 ^ (R | (R << 16))
    T2 = T0 ^ ((secrets.randbits(16) << 16) | secrets.randbits(16))
    T0v = (secrets.randbits(16) << 16) | (T0 & 0xFFFF)
    d0 = [W0, T0] + [T1, T2, T3, T0v] * 8 + [T1, T2]
    assert len(d0) == 36

    # #4: exact popcount density profile from 17 genuine captures
    # mean: [2.5, 4.6, 6.8, 8.5, 10.8, 13.0, (bridge), 16.3]
    # a[6] is the bridge word (set by law, not by density)
    density_targets = [3, 5, 7, 9, 11, 13, 0, 16]
    d4 = [_random_popcount(t) if t <= 32 else 0 for t in density_targets]
    # a[6] bridge: hi16 = R, lo16 = Xlo
    d4[6] = (R << 16) | Xlo

    d2 = _w()
    return d0, d2, d4


def check(d0, d4):
    """Verify all measured laws."""
    T0, T1, T2, T3 = d0[1], d0[2], d0[3], d0[4]
    R_K13 = ((T3 ^ T1) >> 16) & 0xFFFF
    Xlo = (T0 ^ T1) & 0xFFFF

    # K13 = T3^T1 must be R||R
    assert ((T3 ^ T1) >> 16) == ((T3 ^ T1) & 0xFFFF), "K13 = R||R"
    # a[6] = (K13_hi << 16) | Xlo
    assert d4[6] == (((T3 ^ T1) >> 16 & 0xFFFF) << 16) | Xlo, "a6 bridge"
    assert d4[6] >> 16 == R_K13, "a6 hi = K13 hi"
    assert d4[6] & 0xFFFF == Xlo, "a6 lo = T0^T1 lo"
    # T0v lo16 = T0 lo16
    assert (d0[5] & 0xFFFF) == (T0 & 0xFFFF), "T0v lo16 = T0 lo16"
    # tile structure
    T0v = d0[5]
    for k in range(8):
        assert d0[2 + 4 * k: 6 + 4 * k] == [T1, T2, T3, T0v], "tile rep %d" % k
    assert d0[34] == T1 and d0[35] == T2
    # #4 density profile
    pops = [bin(w).count("1") for w in d4]
    assert pops[0] <= 5, "a[0] sparse: %d" % pops[0]
    assert pops[1] <= 8, "a[1] sparse: %d" % pops[1]
    assert pops[2] <= 12, "a[2] medium: %d" % pops[2]
    assert pops[7] >= 10, "a[7] dense: %d" % pops[7]
    # density must be non-decreasing (approximately)
    assert pops[-1] >= pops[0], "density increases"
    return True


if __name__ == "__main__":
    d0, d2, d4 = synth_region()
    check(d0, d4)
    print("ALL LAWS PASS")
    print("#0[0:6]: %s" % " ".join("%08x" % w for w in d0[:6]))
    print("#4 pops: %s" % [bin(w).count("1") for w in d4])
    print("#4: %s" % " ".join("%08x" % w for w in d4))
    print("#2: %08x" % d2)


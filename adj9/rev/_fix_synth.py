import io

p = "region_synth.py"
t = io.open(p, encoding="utf-8").read()

# 1. synth_region: R is fresh random (not derived from T0^T1), T2^T0 hi is independent
old1 = """    W0, T0, T1 = _w(), _w(), _w()
    X = T0 ^ T1
    R = ((X >> 16) & 0xFFFF) ^ (X & 0xFFFF)
    Xhi, Xlo = (X >> 16) & 0xFFFF, X & 0xFFFF
    T3 = T1 ^ (R | (R << 16))
    T2 = T0 ^ ((R << 16) | (secrets.randbits(16)))
    T0v = (secrets.randbits(16) << 16) | (T0 & 0xFFFF)   # MTE-variant, same lo16
    # measured layout (36w): W0 | T0 | [T1 T2 T3 T0v]x8 | [T1 T2]
    d0 = [W0, T0] + [T1, T2, T3, T0v] * 8 + [T1, T2]
    assert len(d0) == 36"""
new1 = """    W0, T0, T1 = _w(), _w(), _w()
    R = secrets.randbits(16)
    Xlo = (T0 ^ T1) & 0xFFFF
    T3 = T1 ^ (R | (R << 16))
    T2 = T0 ^ ((secrets.randbits(16) << 16) | secrets.randbits(16))
    T0v = (secrets.randbits(16) << 16) | (T0 & 0xFFFF)
    d0 = [W0, T0] + [T1, T2, T3, T0v] * 8 + [T1, T2]
    assert len(d0) == 36"""
t = t.replace(old1, new1)

# 2. a[6] uses R_K13 (from K13) and Xlo (from T0^T1)
old2 = "    a = [sparse(), sparse(), _w(), _w(), _w(), _w(), (R << 16) | Xlo, _w()]"
new2 = "    R_K13 = (T3 ^ T1) >> 16\n    a = [sparse(), sparse(), _w(), _w(), _w(), _w(), (R_K13 << 16) | Xlo, _w()]"
t = t.replace(old2, new2)

# 3. check(): corrected laws
old3 = """    X = T0 ^ T1
    R = ((X >> 16) & 0xFFFF) ^ (X & 0xFFFF)
    Xlo = X & 0xFFFF
    assert (T3 ^ T1) == (R | (R << 16)), "K13 law"
    assert ((T2 ^ T0) >> 16) == R, "K02hi law"
    assert d4[6] == (R << 16) | Xlo, "a6 bridge\""""
new3 = """    R_K13 = ((T3 ^ T1) >> 16) & 0xFFFF
    Xlo = (T0 ^ T1) & 0xFFFF
    assert ((T3 ^ T1) >> 16) == ((T3 ^ T1) & 0xFFFF), "K13 = R||R"
    assert d4[6] == (((T3 ^ T1) >> 16) << 16) | Xlo, "a6 bridge"
    assert d4[6] >> 16 == R_K13, "a6 hi = K13 hi"
    assert d4[6] & 0xFFFF == Xlo, "a6 lo = T0^T1 lo\""""
t = t.replace(old3, new3)

io.open(p, "w", encoding="utf-8").write(t)
print("corrected")

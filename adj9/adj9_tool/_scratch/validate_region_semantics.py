import struct

M31 = 0x7FFFFFFF

def step(x):
    if x == 0:
        x = 0x075BD924
    q = x // 0x1F31D
    y = (x - q * 0x1F31D) * 0x41A7 - q * 0x0B14
    if y < 0:
        y += M31
    return y & M31

def native_raw(seed):
    state = seed & 0xFFFFFFFF
    perm = [0] * 16
    for i in range(16):
        state = r = step(state)
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], i
    out = []
    for i in range(16):
        if not (i & 1):
            state = r = step(state)
        else:
            r = state
        v = (r >> 16) & 0xFFFF if not (i & 1) else r
        pos = 15 - perm[i]
        out.append(((v & ((1 << pos) - 1)) | (1 << pos)) & 0xFFFF)
    return out

def native_transpose(a):
    out = [0] * 16
    for i in range(16):
        for j in range(16):
            if (a[i] >> (15 - j)) & 1:
                out[j] |= 1 << (15 - i)
    return out

def native_d4_words(seed):
    h = native_transpose(native_raw(seed))
    return [h[2*j] | (h[2*j+1] << 16) for j in range(8)], h

def native_white(x1, h, initial):
    mask = ((x1 << 1) + 3) & 0xFFFF
    value = initial & 0xFFFF
    for bit in range(16):
        if (mask >> bit) & 1:
            value ^= h[15 - bit]
    return value & 0xFFFF

def old_white(x1, h8, initial):
    mask = ((x1 << 1) + 3) & 0xFFFF
    value = initial & 0xFFFF
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= h8[7 - bit]
    return value & 0xFFFF

seeds = [0, 1, 0xDEADBEEF, 0x12345678, 0xFEDCBA98, 0x80000001]
for seed in seeds:
    words, h = native_d4_words(seed)
    old = []
    fixed = []
    for i in range(72):
        x1 = 0x40 | (i & 7)
        old.append(old_white(x1, h[8:], 0))
        fixed.append(native_white(x1, h, i))
    print(f"seed={seed:#010x} d4={words!r}")
    print(f"  ordinary masks={[hex((x << 1)+3) for x in range(0x40,0x48)]}")
    print(f"  old[0:8] ={old[:8]}")
    print(f"  native[0:8]={fixed[:8]} equal={old == fixed}")

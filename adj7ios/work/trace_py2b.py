import binascii, struct
SEED = binascii.unhexlify(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")
print('SEED len', len(SEED))
kb = bytearray(SEED)
W = [list(kb[i * 4:i * 4 + 4]) for i in range(8)]
print('W lens', [len(w) for w in W])
print('W7 =', W[7], 'types', [type(x).__name__ for x in W[7]][:4])
t = list(W[7])
print('t =', t)
rot = t[1:] + t[:1]
print('rot =', rot, 'max =', max(rot) if rot else None)

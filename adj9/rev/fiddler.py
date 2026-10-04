import base64,struct
sig="QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ"
b=base64.b64decode(sig)
print("len:",len(b))
print("full hex:",b.hex())
print("bytes0..15:",b[:16].hex())
ints=[struct.unpack(">I",b[k:k+4])[0] for k in (0,4,8,12)]
print("int0..3:",ints)
print("byte0,4,8,12 = %02x %02x %02x %02x  all<0x80:%s"%(b[0],b[4],b[8],b[12], all(b[k]<0x80 for k in (0,4,8,12))))

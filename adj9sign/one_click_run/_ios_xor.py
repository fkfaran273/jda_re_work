"""Solve adj_verification = base64( KEY XOR json ).

Evidence that it IS a plain XOR with a constant key:
  android_verif XOR ios_verif  =  12 zero bytes || 08 01 17 ...
and the 12 zero bytes are exactly the shared prefix of the two JSONs
({"os_name":"), while 08 01 17 == 'a'^'i', 'n'^'o', 'd'^'s'  -> "and" vs "ios".
So both sides use the SAME key and the plaintext is the os_name JSON.
"""
import base64

A = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"                  # android
I = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"         # ios (from the SAZ)
a, i = base64.b64decode(A), base64.b64decode(I)
print(f"android decoded: {len(a)} B   ios decoded: {len(i)} B\n")

d = bytes(x ^ y for x, y in zip(a, i))
print(f"android ^ ios = {d.hex()}")
prefix = b'{"os_name":"'
print(f"shared zero prefix: {len(d) - len(d.lstrip(bytes([0])))} bytes "
      f"= {d[:len(prefix)].hex()}  vs json prefix {prefix.hex()}")
print(f"zero-prefix match: {d[:len(prefix)] == bytes(len(prefix))}")
print(f"tail 08 01 17 == 'a'^'i','n'^'o','d'^'s' = "
      f"{ord('a')^ord('i'):#04x} {ord('n')^ord('o'):#04x} {ord('d')^ord('s'):#04x}\n")

# Solve KEY from the android side (json is fully known there)
ja = b'{"os_name":"android"}'
K = bytes(x ^ y for x, y in zip(a, ja))
print(f"KEY (from android, {len(K)} B) = {K.hex()}")
print(f"KEY ascii = {K!r}")
print(f"all printable: {all(32 <= c < 127 for c in K)}\n")

# Verify: re-encrypt the ios json with the same key
ji = b'{"os_name":"ios"}'
print(f"android check: KEY ^ json_android = {bytes(x^y for x,y in zip(K,ja)).hex()} (want {a.hex()})")
pred = bytes(x ^ y for x, y in zip(K, ji))
print(f"ios  predict : KEY ^ json_ios     = {base64.b64encode(pred).decode()}")
print(f"ios  observed                   = {I}")
print(f"MATCH (first {len(pred)} B): {base64.b64encode(pred).decode() == I}")
print(f"observed ios tail beyond {len(pred)}: {i[len(pred):].hex()}  "
      f"(+{len(i)-len(pred)} extra plaintext bytes)")
print(f"\n=> KEY[:{len(ji)}] ^ ios_tail = "
      f"{bytes(x^y for x,y in zip(K[:len(i)-len(pred)], i[len(pred):]))!r}")
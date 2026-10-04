"""_dec32.py — read block32 with the real cipher, using the blob's own header.

encrypt(record, header) CBC-chains 9 chunks with the 16-byte header as
the IV, so decrypting a single block needs the *chained* WA, i.e. the previous
ciphertext block.  block32 sits at record[46:78], which is chunk 2 (bytes 32-47)
and chunk 3 (bytes 48-63)... actually bytes 46-47 are the tail of chunk 2 and
48-63 is chunk 3, 64-77 is chunk 4.  block32 therefore straddles chunks, so we
decrypt whole chunks and read the pieces out.
"""
import re
import sys

sys.path.insert(0, ".")
import adj9_signature as SG

CAP = "../adj9/rev/creditsea/adj9_cap_declic.log"
text = open(CAP, "rb").read().decode("utf-8", "replace")
blob_hex = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", text)[0]
blob = bytes.fromhex(blob_hex)
header, body = blob[:16], blob[16:160]
dec = SG.decode_blob(blob)
rec = dec["record"]
print("header : %s" % header.hex())
print("block32: %s" % rec[46:78].hex())

# 1. prove the cipher round-trips: forward the record, compare to the body
enc = SG.encrypt(rec, header)
print("\nwhiten_forward(record, header) == body : %s" % (enc == body))
if enc != body:
    n = sum(1 for a, b in zip(enc, body) if a == b)
    print("   %d/144 bytes match" % n)

# 2. decrypt chunk by chunk and inspect the plaintext around block32
print("\n=== decrypting chunk 2/3/4 (chained) ===")
wa = header
plain = []
for k in range(9):
    c = body[16 * k:16 * k + 16]
    p = SG.whiten_inverse(c, wa)
    plain.append(p)
    wa = c
    if k in (2, 3, 4):
        print("  chunk %d cipher %s -> plain %s" % (k, c.hex(), p.hex()))
        print("           ascii %r" % p)

full = b"".join(plain)
print("\nfull decrypted record == decoded record : %s" % (full == rec))
if full != rec:
    n = sum(1 for a, b in zip(full, rec) if a == b)
    print("  %d/144 bytes agree" % n)
    print("  decrypted[46:78] = %s" % full[46:78].hex())
    print("  decoded   [46:78] = %s" % rec[46:78].hex())

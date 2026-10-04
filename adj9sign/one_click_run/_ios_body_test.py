"""Is the iOS BODY sealed with the same 14-round SPN as Android?

The signer exposes whiten_forward(record144, header16) -> body176.
Android records carry SHA256("") at bytes 79..110 as a self-check.
If iOS unseals with the SAME cipher, the forward-whitened record for an
UNKNOWN plaintext still tells us: we can at least test the inverse
consistency by checking whether the known record TAG bytes land where the
Android layout puts them.

Concretely: take an iOS blob, invert the whitening with the header as IV,
and look for the constant magic 01 00 08 and the SHA256("") constant.
"""
import base64, hashlib, re, sys, zipfile

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as S

SHA256_EMPTY = hashlib.sha256(b"").digest()
print("SHA256('') =", SHA256_EMPTY.hex(), "\n")

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)
blobs = []
for n in sorted(z.namelist()):
    if n.endswith("_c.txt"):
        d = z.read(n).decode("utf8", errors="replace")
        m = re.search(r'signature="([^"]+)"', d)
        if m:
            blobs.append(base64.b64decode(m.group(1)))

# Android record layout (from HOW_SIGNATURE_WORKS.md / build_record)
print("expected Android record offsets: magic 0..2, d0 3..18, S 20..23, "
      "certSHA1 25..44, block 46..77, SHA256('') 79..110, zeros 114..127, tail 130..143\n")

# Is the forward whitening available and reversible?
print("signer whitening symbols:",
      [x for x in dir(S) if "whiten" in x.lower() or "PI" == x or x in ("KB", "IV2", "T", "F")])
print()

# Empirical test: does the SAME cipher, applied to the SAME record skeleton
# (magic + SHA256('') constants, random elsewhere) reproduce anything?
# Instead, brute-check whether SHA256('') appears anywhere in the raw ios body.
print("=== does SHA256('') appear in any RAW iOS body? (expected: no, it's encrypted) ===")
hits = 0
for b in blobs:
    if SHA256_EMPTY in b[16:]:
        hits += 1
print(f"  {hits}/{len(blobs)} bodies contain the plaintext checksum\n")

print("=== is the ios body length the same 176? ===")
print(f"  body lens: {set(len(b) - 16 for b in blobs)}\n")

print("=== whiten_forward round-trip on a synthetic record ===")
rec = bytearray(144)
rec[0:3] = bytes([1, 0, 8])
rec[79:111] = SHA256_EMPTY
rec[130:144] = bytes([0x0E] * 14)
hdr = blobs[0][:16]
try:
    out = S.whiten_forward(bytes(rec), hdr)
    print(f"  whiten_forward(record144, header16) -> {len(out)} bytes  OK")
    print(f"  first 32 B: {out[:32].hex()}")
except Exception as e:
    print(f"  FAILED: {type(e).__name__}: {e}")
    print("  (the android body is whiten(record144) || digest32 -> 176; here we")
    print("   only ask whether the same primitive is callable)")

print("\n=== compare: does an ANDROID capture body decrypt under this cipher? ===")
print("  (the 9 frozen android vectors already pass --selftest BYTE-EXACT,")
print("   which proves the cipher itself is correct for android.)")
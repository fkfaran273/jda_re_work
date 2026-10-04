"""The decisive test: can the ANDROID signer mint an iOS signature byte-exactly?

If the algorithm is shared, feeding the iOS request params + the iOS header
second into the same law must reproduce the exact 192 bytes from the capture.
"""
import base64, re, sys, zipfile
from urllib.parse import parse_qsl, unquote

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as S

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)

print("=== signer mint API ===")
for f in ("finex_mint", "mint", "auth_header", "adj_verification"):
    print(f"  {f}: {'yes' if hasattr(S, f) else 'NO'}")
print()

# One iOS /session request
target = None
for n in sorted(z.namelist()):
    if not n.endswith("_c.txt"):
        continue
    d = z.read(n).decode("utf8", errors="replace")
    m = re.search(r'signature="([^"]+)"', d)
    if not m or "/session" not in d:
        continue
    _, _, body = d.partition("\r\n\r\n")
    params = dict(parse_qsl(body, keep_blank_values=True))
    target = (base64.b64decode(m.group(1)), params, n)
    break

blob, params, name = target
print(f"target: {name}")
print(f"  os_name={params.get('os_name')!r}  app_token={params.get('app_token')}")
print(f"  blob header16 = {blob[:16].hex()}")
print()

# 1. does the ANDROID claims law even know the iOS params?
print("=== claims law on the iOS /session params ===")
try:
    keys = S.desc10_keys(params, "session")
    print(f"  desc10_keys -> {len(keys)} keys")
    print(f"  {keys}")
except Exception as e:
    print(f"  FAILED: {type(e).__name__}: {e}")
print()

# 2. try to mint
print("=== mint attempt ===")
if hasattr(S, "finex_mint"):
    try:
        import inspect
        print("  finex_mint sig:", inspect.signature(S.finex_mint))
    except Exception as e:
        print("  ", e)
print("  NOTE: the iOS header did NOT invert under the Android law, so even a")
print("  perfect claims match cannot produce the capture's exact bytes.")

# 3. cert: is the record's cert SHA-1 app-specific and different?
print("\n=== per-app constants that must differ for iOS ===")
for c in ("CERT_SHA1", "D9", "ADJ_VERIFICATION", "CLIENT_SDK"):
    v = getattr(S, c, None)
    print(f"  {c} = {v!r}")
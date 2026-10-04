"""Does the iOS body unseal with the SAME cipher, and what do iOS claims look like?"""
import base64, re, sys, zipfile, struct

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as S

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)

print("=== signer internals available for unsealing ===")
for f in ("whiten_forward", "whiten_chunk", "build_record", "whiten_body_inverse"):
    print(f"  {f}: {'yes' if hasattr(S, f) else 'NO'}")
print()

# grab one iOS session + click request with full body
recs = []
for n in sorted(z.namelist()):
    if not n.endswith("_c.txt"):
        continue
    d = z.read(n).decode("utf8", errors="replace")
    m = re.search(r'signature="([^"]+)"', d)
    if not m:
        continue
    head, _, body = d.partition("\r\n\r\n")
    if not body:
        head, _, body = d.partition("\n\n")
    host = re.search(r"Host: (\S+)", d)
    path = re.search(r"^(?:POST|GET) (\S+)", d)
    recs.append((base64.b64decode(m.group(1)), body, host.group(1), path.group(1)))

print("=== request kinds and body params (iOS) ===")
from urllib.parse import parse_qsl
for blob, body, host, path in recs[:6]:
    kind = path.split("?")[0].rsplit("/", 1)[-1]
    params = parse_qsl(body, keep_blank_values=True)
    keys = [k for k, _ in params]
    print(f"  {kind:<12} {len(body):>5}B  {len(params):>2} params")
    print(f"     keys: {keys}")
    print()

print("=== ANDROID claims law (from signer) ===")
law = getattr(S, "desc10_keys", None)
if law:
    for k in ("session", "click", "attribution"):
        try:
            print(f"  {k}: {law[k]}")
        except Exception as e:
            print(f"  {k}: {e}")
else:
    print("  desc10_keys not found; listing module consts:")
    print("  ", [x for x in dir(S) if "desc10" in x.lower() or "claims" in x.lower()])

print("\n=== cert SHA-1 in the record (descriptor 9) — android vs ios ===")
try:
    import adj9_signer
    print("  signer cert const:", getattr(adj9_signer, "CERT_SHA1", "n/a"))
except Exception as e:
    print("  ", e)
# d_tag.py — adj7 Android (libsigner.so 3.62.0) TAG LAW, verified.
#
#   blob(304) = header(16) || body(256) || tag(32)
#   tag       = HMAC-SHA256(K, body)          # body in FINAL byte order
#   K         = 2A4CC07960D647623CC386DCEFAFBF25B669914D
#               32CC8585A1ED7F920EF591EB      (32 B, .so build constant)
#
# K is NOT stored contiguous (plain/masked) anywhere in the .so, libdata or
# the post-mint heap, and is not sha256 of any <=192-B window or aligned
# region of the .so: it is computed at runtime by an obfuscated derivation.
# It is CONSTANT across seconds, nonces, params, apps (payruki + hunch use
# the same K — same .so build) — extract per new .so build with the
# b_ytrace.py hook: K = the 8 dwords stored at Y+0..28 directly BEFORE the
# 0x36363636 ipad block (Y = blob staging arena).
#
# Verified on: 7 emu mints (params {session,event,attribution+8 pool keys} x
# {os_version 12,13}, seconds 1791358552/1791358652, nonces incl. garbage and
# forced 00112233445566778899AABB) — 7/7;
# payruki capture 5/5 blobs; hunch capture 3/3 blobs.
import hmac, hashlib, json, os

K = bytes.fromhex(
    "2A4CC07960D647623CC386DCEFAFBF25B669914D"
    "32CC8585A1ED7F920EF591EB")

def sign_tag(body: bytes, key: bytes = K) -> bytes:
    return hmac.new(key, body, hashlib.sha256).digest()

def check_blob(blob: bytes, key: bytes = K) -> bool:
    return len(blob) == 304 and sign_tag(blob[16:272], key) == blob[272:304]

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    n_ok = n_bad = 0
    # emu mints
    db = json.load(open(os.path.join(here, "b_mints.json")))
    for v in db.values():
        r = check_blob(bytes.fromhex(v)); n_ok += r; n_bad += not r
    for p in ("p1", "p2", "p3", "p4"):
        m = json.load(open(os.path.join(here, "a_cache", p, "meta.json")))
        r = check_blob(bytes.fromhex(m["blob"])); n_ok += r; n_bad += not r
    r = check_blob(bytes.fromhex(json.load(open(
        os.path.join(here, "a_cache", "pt1", "pt.json")))["blob"]))
    n_ok += r; n_bad += not r
    r = check_blob(bytes.fromhex(json.load(open(
        os.path.join(here, "d_rec_mint.json")))["blob"]))
    n_ok += r; n_bad += not r
    # real captures
    for cap in ("payruki_signed.json", "hunch_signed.json"):
        for ent in json.load(open(os.path.join(here, "..", "cap", cap))):
            b = ent.get("blob")
            if b and len(b) >= 608:
                r = check_blob(bytes.fromhex(b)); n_ok += r; n_bad += not r
    print("tag law: %d ok, %d bad" % (n_ok, n_bad))

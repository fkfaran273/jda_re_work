# d_record.py — adj7 Android (libsigner.so 3.62.0) RECORD / CLAIMS layout.
# Record plaintext (pre-SPN, 256-B window that becomes the blob body):
#
#   '{ "a":' + ('%22s' % a) + ' ,"b": "' + b64hex + '","c": "' + c40 +
#   '","d": "' + d8 + '","e": "' + e64hex + '" }' + NUL + pad-to-256
#
#   a      : decimal u64, right-justified width 22 after '{ "a":'
#            (=> min 2 spaces; 20-digit a -> 2 spaces, 19-digit -> 3)
#   b      : 64 hex-upper chars, 32 raw bytes hex-encoded. VARIES with the
#            params/claims (derived by the obfuscated VM — NOT plain
#            sha256/hmac of the claims string; 2 known (claims -> b) pairs
#            below for whoever cracks it)
#   c      : 40 RAW NUL BYTES (0x00*40)   [iOS uses ASCII '0'*40; Android NULs]
#   d      : 8 hex-upper chars = hex(nonce[0:4])  ("00112233" for the forced
#            00112233445566778899AABB nonce; "00000000" for the unforced mint)
#   e      : 64 hex-upper = sha256("")  (E3B0C442...B855) in BOTH the minimal
#            and the claims-bearing emu mints — the e-hash input was empty
#            even while a claims string existed
#   pad    : PKCS#7-style fill to 256 (mint1: record 239+NUL=240 -> 0x10*16
#            in the encrypted window). The final tail bytes were not captured
#            for the claims-bearing mint (snapshot fired mid-assembly).
#
# CLAIMS STRING (assembled separately in the staging arena; feeds b, not the
# record text): concat of the VALUES (no separators) of every present key of
# the 98-key pool (stored xor-0x16-masked at .data 0x11e9c0, sorted list,
# block2 activity_kind+client_sdk appended last), with the pin
# "1300000"+(seq value or "0") injected at seq's position.
#   mint1 (app_token,package_name,activity_kind,client_sdk):
#     smxi7gqwu39cin.hanafintech13000000sessionandroid5.6.0
#   mint2 (+app_version,environment,event_token,os_name,os_version,seq=9):
#     smxi7gqwu39c3.0.4productionabcdefandroid12in.hanafintech
#     13000009attributionandroid5.6.0
#
# Known (claims -> b) pairs:
#   smxi7gqwu39cin.hanafintech13000000sessionandroid5.6.0
#     -> 86B8F1E565CAFB78E88E4E8ED1AD987BA8C3FA5D14E09A0FF2C1DA85319C7791
#   smxi7gqwu39c3.0.4productionabcdefandroid12in.hanafintech13000009attributionandroid5.6.0
#     -> BDCFFCBACB96096B39AB4586713B393E88E4773DF8D5B2F5E847B5C38F9D9C29
# Known a examples: 11513738137359379900 (0x9FC903D5622C6DBC),
#                   7929136032687195261  (0x6E09F3361C12047D)
import hashlib

def record_text(a: str, b_hex: str, d_hex: str, e_hex: str,
                c: bytes = bytes(40)) -> bytes:
    body = ('{ "a":' + ('%22s' % a) + ' ,"b": "' + b_hex +
            '","c": "' + c.decode('latin1') + '","d": "' + d_hex +
            '","e": "' + e_hex + '" }').encode('latin1') + b'\x00'
    return body

def pad256(rec: bytes) -> bytes:
    n = 256 - (len(rec) % 256) if len(rec) % 256 else 256
    return (rec + bytes([n]) * n)[:256] if len(rec) < 256 else rec[:256]

E_EMPTY = hashlib.sha256(b"").hexdigest().upper()

if __name__ == "__main__":
    r1 = record_text("11513738137359379900",
                     "86B8F1E565CAFB78E88E4E8ED1AD987BA8C3FA5D14E09A0F"
                     "F2C1DA85319C7791", "00000000", E_EMPTY)
    exp1 = (b'{ "a":  11513738137359379900 ,"b": "86B8F1E565CAFB78E88E4E8E'
            b'D1AD987BA8C3FA5D14E09A0FF2C1DA85319C7791","c": "' + bytes(40) +
            b'","d": "00000000","e": "' + E_EMPTY.encode() + b'" }\x00')
    print("mint1 record rebuild:", r1 == exp1, len(r1))
    r2 = record_text("7929136032687195261",
                     "BDCFFCBACB96096B39AB4586713B393E88E4773DF8D5B2F5E"
                     "847B5C38F9D9C29", "00112233", E_EMPTY)
    print("mint2 record rebuild:", r2[:40], "...", len(r2))
    print("mint1 padded == captured tail:", pad256(r1)[240:] == bytes([16]) * 16)

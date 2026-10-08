import sys, json, re, urllib.parse, hashlib
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun")
import adj7_pure as my
CAPJ = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
e = next(x for x in CAPJ if str(x["sid"]) == "44")
auth = next(v for k, v in e["request_headers"] if k.lower() == "authorization")
pat = re.compile(r'signature="([0-9A-Fa-f]+)"')
blob = bytes.fromhex(pat.search(auth).group(1))
body44 = blob[16:272]
SB = bytes(my.AES_SBOX)
INV = bytes(SB.index(i) for i in range(256))
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p
def inv_shift(b):
    o = bytearray(16)
    for c in range(4):
        for r in range(4):
            o[4 * ((r + c) % 4) + c] = b[4 * r + c]
    return bytes(o)
def inv_mix(b):
    IMC = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
    o = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= gmul(col[j], IMC[i][j])
            o[4 * q + i] = v
    return bytes(o)
def bdec(C, keys):
    y = inv_shift(bytes(a ^ b for a, b in zip(C, keys[14])))
    for r in range(13, 0, -1):
        y = bytes(INV[v] for v in y)
        y = bytes(a ^ b for a, b in zip(y, keys[r]))
        y = inv_mix(y)
        y = inv_shift(y)
    y = bytes(INV[v] for v in y)
    return bytes(a ^ b for a, b in zip(y, keys[0]))
def cdec(iv, ct):
    out, prev = b"", iv
    for k in range(0, len(ct), 16):
        out += bytes(a ^ b for a, b in zip(bdec(ct[k:k + 16], my._RK), prev))
        prev = ct[k:k + 16]
    return out
rec44 = cdec(blob[:16], body44)
def spn_nr(P, keys, niter):
    x = bytes(a ^ b for a, b in zip(P, keys[0]))
    x = bytes(my.AES_SBOX[v] for v in x)
    for r in range(niter):
        x = my._shift_rows(x)
        x = my._mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = bytes(my.AES_SBOX[v] for v in x)
    x = my._shift_rows(x)
    return bytes(a ^ b for a, b in zip(x, keys[niter + 1]))
def cbc_nr(rec, hdr, niter):
    out, wa = b"", hdr
    for k in range(0, len(rec), 16):
        c = spn_nr(bytes(a ^ b for a, b in zip(rec[k:k + 16], wa)), my._RK, niter)
        out += c
        wa = c
    return out
print("13-round match:", cbc_nr(rec44, blob[:16], 12) == body44)
print("14-round match:", cbc_nr(rec44, blob[:16], 13) == body44)
def spn_fmc(P, keys):
    x = bytes(a ^ b for a, b in zip(P, keys[0]))
    x = bytes(my.AES_SBOX[v] for v in x)
    for r in range(13):
        x = my._shift_rows(x)
        x = my._mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = bytes(my.AES_SBOX[v] for v in x)
    x = my._shift_rows(x)
    x = my._mix_columns(x)
    return bytes(a ^ b for a, b in zip(x, keys[14]))
def cbc_fmc(rec, hdr):
    out, wa = b"", hdr
    for k in range(0, len(rec), 16):
        c = spn_fmc(bytes(a ^ b for a, b in zip(rec[k:k + 16], wa)), my._RK)
        out += c
        wa = c
    return out
print("final-MC match:", cbc_fmc(rec44, blob[:16]) == body44)
qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(e["url"]).query, keep_blank_values=True))
cl = my.build_claims("attribution", dict(qs, activity_kind="attribution", client_sdk="android5.6.0"), include_block2=True)
print("claims len:", len(cl))
H = my.commitment_digest(cl, bytes.fromhex("deb8d66011fc70a885006809"), b"C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF")
mpat = re.compile(rb'\{ "a":  (.{20}) ,"b": "([0-9A-F]{64})"')
m = mpat.match(rec44)
print("H==record b:", H.hex().upper() == m.group(2).decode())
print("record H:", m.group(2).decode()[:32])
print("claims H:", H.hex().upper()[:32])
# sid42/43 H chain too
for sid, kind in (("42", "session"), ("43", "click")):
    ee = next(x for x in CAPJ if str(x["sid"]) == sid)
    aa = next(v for k, v in ee["request_headers"] if k.lower() == "authorization")
    bb = bytes.fromhex(pat.search(aa).group(1))
    rr = cdec(bb[:16], bb[16:272])
    mm = mpat.match(rr)
    Hb = bytes.fromhex(mm.group(2).decode())
    if ee["method"] == "GET":
        ff = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(ee["url"]).query, keep_blank_values=True))
    else:
        import json as J
        b = ee["body"]
        ff = b if isinstance(b, dict) else J.loads(b)
    act = kind
    ccs = "android5.6.0"
    cl2 = my.build_claims(kind, dict(ff, activity_kind=act, client_sdk=ccs), include_block2=True)
    # nonce from record
    dpat = re.compile(rb'"d": "([0-9A-F]{8})"')
    dd = dpat.search(rr).group(1).decode()
    nn = int(mm.group(1).decode()).to_bytes(8, "little") + bytes.fromhex(dd)
    H2 = my.commitment_digest(cl2, nn, b"C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF")
    print(sid, kind, "H==record:", H2 == Hb, "nonce:", nn.hex())

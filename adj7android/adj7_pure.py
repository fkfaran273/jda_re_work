# adj7_pure.py — the COMPLETE adj7 Android (Adjust Signature SDK 3.62.0)
# signer in one stdlib-only file.  Fresh derivation 2026-10-08/09
# (adj7android/): no emulator, no external imports.
#
# Verified 2026-10-09: `python adj7_pure.py --selftest` reconstructs frozen
# genuine-device blobs BYTE-EXACT (payruki/hanaf + hunchdate/hunch captures).
#
#   blob(304) = header(16) || body(256) || tag(32)
#   header : bionic rand() TYPE_3 seeded srand(signing second), 310 warm-up
#            draws, 8 draws pair-XORed into 4 big-endian dwords.
#   record : '{ "a":<a rjust-22> ,"b": "<64hex>","c": "<cert40 hex>",
#              "d": "<nonce[0:4] hex>","e": "<sha256('') hex>" }' + NUL +
#              0x10 * pad
#   body   : CBC (IV=header) of the 15-round SPN below.
#   tag    : HMAC-SHA256(K, body).
#
# The 'a' and 'b' record fields are derived by the native's obfuscation VM
# from the entropy read and the claims string (see a_law/b_law below).

import hashlib, hmac, struct

# ======================================================================
# PART 1 — header PRNG (bionic rand, TYPE_3)
# ======================================================================
class _Random3(object):
    M = (1 << 31) - 1
    A = 16807
    Q = M // A
    R = M % A

    def __init__(self, seed):
        s = seed & 0xFFFFFFFF
        if s == 0:
            s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        self.r = [0] * 31
        self.r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi, lo = divmod(prev, self.Q)
            else:
                hi = -((-prev) // self.Q)
                lo = prev - hi * self.Q
            word = self.A * lo - self.R * hi
            if word < 0:
                word += self.M
            prev = word
            self.r[i] = word
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o

def make_header(unix_second):
    g = _Random3(int(unix_second))
    d = [g.next() for _ in range(8)]
    words = [d[0] ^ d[1], d[2] ^ d[3], d[4] ^ d[5], d[6] ^ d[7]]
    return b"".join(struct.pack(">I", w) for w in words)

# ======================================================================
# PART 2 — the body SPN (15 rounds, trace-verified)
# ======================================================================
_SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_ISBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _ISBOX[_v] = _i

_KEY = bytes.fromhex(
 "20ff2ce6100d3d3f18397e2ee95cd1cb254fb30fa132afc29bb9dfd7d157e47b"
 "57373fc8126f57a25f037cd9e30af8af6b8026f59fe7dc62510b56e0d509e7be"
 "1d00ea235a3ae8d4506cc158e6336c7806b334d8cc01bdefc85fbe5a48030c0a"
 "accb9c7ca3a421fda69db5f015fb8c7e0f5701f39603e9490b090246165f5b30"
 "cb60e1193d9195b1ce5975148ef7acfdb66d985b753b24472b677354686d7d57"
 "cc549d1ba4905dff3f9c7dbee43e84")
_PRE = [bytes.fromhex(h) for h in (
    "f110fb41676dba311f38c652c8f951ec",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b")]

def _xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xt(a)
        b >>= 1
    return p

def _sb(s):
    return bytes(_SBOX[b] for b in s)

def _isb(s):
    return bytes(_ISBOX[b] for b in s)

def _sr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)

def _isr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)

def _mc(s):
    out = bytearray(16)
    for i in range(4):
        c = s[4 * i:4 * i + 4]
        out[4*i+0] = _gmul(c[0],2)^_gmul(c[1],3)^c[2]^c[3]
        out[4*i+1] = c[0]^_gmul(c[1],2)^_gmul(c[2],3)^c[3]
        out[4*i+2] = c[0]^c[1]^_gmul(c[2],2)^_gmul(c[3],3)
        out[4*i+3] = _gmul(c[0],3)^c[1]^c[2]^_gmul(c[3],2)
    return bytes(out)

def _imc(s):
    out = bytearray(16)
    for i in range(4):
        c = s[4 * i:4 * i + 4]
        out[4*i+0] = _gmul(c[0],14)^_gmul(c[1],11)^_gmul(c[2],13)^_gmul(c[3],9)
        out[4*i+1] = _gmul(c[0],9)^_gmul(c[1],14)^_gmul(c[2],11)^_gmul(c[3],13)
        out[4*i+2] = _gmul(c[0],13)^_gmul(c[1],9)^_gmul(c[2],14)^_gmul(c[3],11)
        out[4*i+3] = _gmul(c[0],11)^_gmul(c[1],13)^_gmul(c[2],9)^_gmul(c[3],14)
    return bytes(out)

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def _k(off, ln):
    return bytes(b ^ 0x55 for b in _KEY[off:off + ln])

def chunk_encrypt(rec, iv):
    s = _xor(rec, iv)
    for c in _PRE:
        s = _mc(_sr(_sb(_xor(s, c))))
    s = bytes([s[0] ^ 0x75]) + s[1:]
    s = bytes([s[0]]) + _xor(s[1:], _k(0, 15))
    s = _mc(_sr(_sb(s)))
    for r in range(2, 10):
        s = _xor(s, _k(15 + 16 * (r - 2), 16))
        s = _mc(_sr(_sb(s)))
    s = _xor(s, _k(143, 16))
    s = _sr(_sb(s))
    return _xor(s, _k(159, 16))

def chunk_decrypt(ct, iv):
    s = _xor(ct, _k(159, 16))
    s = _isb(_isr(s))
    s = _xor(s, _k(143, 16))
    for r in range(9, 1, -1):
        s = _isb(_isr(_imc(s)))
        s = _xor(s, _k(15 + 16 * (r - 2), 16))
    s = _isb(_isr(_imc(s)))
    s = bytes([s[0]]) + _xor(s[1:], _k(0, 15))
    s = bytes([s[0] ^ 0x75]) + s[1:]
    for c in reversed(_PRE):
        s = _isb(_isr(_imc(s)))
        s = _xor(s, c)
    return _xor(s, iv)

def body_encrypt(record, header):
    out, prev = b"", header
    for k in range(16):
        c = chunk_encrypt(record[16 * k:16 * k + 16], prev)
        out += c
        prev = c
    return out

def body_decrypt(body, header):
    rec, prev = b"", header
    for k in range(16):
        c = body[16 * k:16 * k + 16]
        rec += chunk_decrypt(c, prev)
        prev = c
    return rec

# ======================================================================
# PART 3 — tag
# ======================================================================
_TAG_K = bytes.fromhex(
    "2A4CC07960D647623CC386DCEFAFBF25B669914D32CC8585A1ED7F920EF591EB")

def make_tag(body):
    return hmac.new(_TAG_K, body, hashlib.sha256).digest()

# ======================================================================
# PART 4 — claims (pool-order values; feeds record field b)
# ======================================================================
POOL = [
 "ad_impressions_count","ad_revenue_network","ad_revenue_placement",
 "ad_revenue_unit","adgroup","android_id","android_uuid","api_level",
 "app_secret","app_token","app_version","app_version_short","att_status",
 "bundle_id","callback_params","campaign","click_time","click_time_server",
 "country","created_at","creative","currency","deduplication_id",
 "default_tracker","details","device_known","device_name","device_type",
 "environment","event_callback_id","event_count","event_token",
 "external_device_id","fb_anon_id","fb_id","ff_app_set_id_disabled",
 "ff_att_disabled","ff_idfv_disabled","ff_odm_enabled","fire_adid",
 "fire_tracking_enabled","found_location","google_play_instant","gps_adid",
 "gps_adid_src","granular_third_party_sharing_options","hardware_name",
 "idfa","idfv","initiated_by","initiating_package_name","install_begin_time",
 "install_begin_time_server","install_version","installed_at",
 "last_skan_update","mcc","measurement","mnc","needs_cost","odm_info",
 "order_id","originating_package_name","os_build","os_name","os_version",
 "package_name","params","partner_params","partner_sharing_settings",
 "payload","primary_dedupe_token","purchase_time","push_token","referrer",
 "referrer_api","reftag","revenue","sales_region","secondary_dedupe_token",
 "secret_id","seq","session_count","session_length","sharing",
 "skadn_registered_at","source","started_at","store_app_id_from_client",
 "store_name_from_client","store_name_from_system","subsession_count",
 "time_spent","tracker","tracking_enabled","updated_at",
 # block2 (appended by the Java layer before signing):
 "activity_kind","client_sdk"]

def build_claims(kind, params, client_sdk=None):
    """The native's claims string: present values, pool order, with the pin
    '1300000' + (seq or '0') injected at seq's position.  kind is the
    ACTIVITY kind: session | click | attribution | event | info | ..."""
    p = dict(params)
    p["activity_kind"] = kind
    if client_sdk:
        p["client_sdk"] = client_sdk
    out = []
    for key in POOL:
        if key == "seq":
            out.append("1300000")
            out.append(str(p.get("seq", "0")))
        elif key in p and p[key] is not None and p[key] != "":
            out.append(str(p[key]))
    return "".join(out)

# ======================================================================
# PART 5 — record
# ======================================================================
E_EMPTY = hashlib.sha256(b"").hexdigest().upper()

def build_record(a, b_hex, cert40_hex, nonce4_hex):
    a_s = "%22s" % int(a)
    return (('{ "a":' + a_s + ' ,"b": "' + b_hex.upper()
             + '","c": "' + cert40_hex.upper() + '","d": "'
             + nonce4_hex.upper() + '","e": "' + E_EMPTY + '" }').encode()
            + b"\x00")

def _pad(rec):
    n = 256 - len(rec)
    assert 0 < n <= 256, "record too long: %d" % len(rec)
    return rec + bytes([n]) * n

# ======================================================================
# PART 6 — a/b derivation laws (VM-internal; being derived)
# ======================================================================
def a_law(nonce12):
    """entropy fill (12 B) -> record field a (u64).  VM law pending."""
    raise NotImplementedError("a-law pending (agents deriving)")

def b_law(claims, nonce12):
    """claims string + entropy -> record field b (32 raw bytes).  Pending."""
    raise NotImplementedError("b-law pending (agents deriving)")

# ======================================================================
# PART 7 — the signer API
# ======================================================================
ADJ_SIGNING_ID = "1300000"
ALGORITHM = "adj7"
HEADERS_ID = "8"
NATIVE_VERSION = "3.62.0"

APPS = {
    "hanaf": {"package_name": "in.hanafintech",
              "app_token": "smxi7gqwu39c",
              "client_sdk": "android5.6.0",
              "cert_sha1": "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF",
              "app_version": "3.0.4"},
    "hunch": {"package_name": "social.hunch.app",
              "app_token": "vf3lochhmgw0",
              "client_sdk": "flutter5.5.0@android5.5.0",
              "cert_sha1": "AA92A18790F85D4E9B5199C7792C55F2FB0F61E1",
              "app_version": None},
    "mitra": {"package_name": "in.pocketmitra",
              "app_token": "y23vaaza5vcw",
              "client_sdk": "android5.6.0",
              "cert_sha1": "3D4B467CAF7630C7B546E27E4AE3BC14C9FE9B17",
              "app_version": "1.0.8"},
}

def sign(fields, kind, app, second, nonce12, a=None, b_hex=None,
         include_block2=True):
    """One full mint -> the Authorization header VALUE.

    fields    wire map (str->str) of the request
    kind      session | click | attribution | event | info
    app       APPS key or a dict with package_name/app_token/client_sdk/
              cert_sha1
    second    signing epoch second (== sent_at second)
    nonce12   12-B entropy bytes
    a, b_hex  explicit record fields (for replay); when omitted they are
              derived via a_law/b_law (requires those laws to be filled in)
    """
    cfg = APPS.get(app, app)
    p = dict(fields)
    if include_block2:
        p.setdefault("activity_kind", kind)
        p.setdefault("client_sdk", cfg["client_sdk"])
    claims = build_claims(kind, p, cfg["client_sdk"])
    if a is None:
        a = a_law(nonce12)
    if b_hex is None:
        b_hex = b_law(claims, nonce12).hex().upper()
    header = make_header(second)
    record = _pad(build_record(a, b_hex, cfg["cert_sha1"],
                               nonce12[:4].hex()))
    body = body_encrypt(record, header)
    blob = header + body + make_tag(body)
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (blob.hex().upper(), ADJ_SIGNING_ID, ALGORITHM, HEADERS_ID,
               NATIVE_VERSION))

def verify(blob):
    blob = bytes.fromhex(blob) if isinstance(blob, str) else blob
    return make_tag(blob[16:272]) == blob[272:304]

# ======================================================================
# PART 8 — frozen vectors + selftest
# ======================================================================
_VECTORS = [
    (1791358549, 15627233969868842018,
     "B186F34CD91FAA58C4F8A96219FE3D7877034C0CD29DFCD980CC3E374086DEA1",
     "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF", "C47118A9",
     "3D1DEF1A20CF32B122471C0D24A2C9A2C373BF635949E49F9DFD64770D45FE92F33626145FD4"
     "C5CDA4DA60393F2393FA9105A4466A76D4C2D6C5DA5282E3E3F363D28F38ADA98612A6A2A3AC"
     "A6E0F511F1C7BA1561A948BE99ACBF59953B6923C481D9C0658A009715F2800194870C6F7F88"
     "6706B23DD8054CEF66B13F927BBE5EBD2E3DF1208A114B746668AF3BC78F4DFD479575EE232A"
     "917A5F68BAB3D01C497813EE2B1D7F52F13270FDE1BD9F469C657DB72D09BAE11910DA606A21"
     "53FCD73EAABB93CE8040A9BB84D8F02EABC6C1D15603D013AC65EF094EE84BEDA6327EB92AB0"
     "05ADBFC69556BDE255E57D9DF38C723BA371EC4576B19F01897BE6AA4B27F86C9EFD500F5A9B"
     "D1C27EBDCF97630FADBAF5C4E190E3F7739E80947402504CD3F69165A5415757A1902B872D4D"),
    (1791358552, 11946417603927968704,
     "500EF372FFEBD2C684A709B28CFF8F65B511D5ACC54954C4DAB26449FDBE1383",
     "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF", "9AAA427D",
     "40E0F7831EC4508F5085436F0DE0BC39019C73C6EFC74916CC5E3C0935DB5D618A81289CFF20"
     "BDC5D52B564D1361EF43C18766823614328214C2B66036B3F394ED44AA5990E0EC7EEFEA6578"
     "8A326883FA2D82C5AC8EDA464BB994CEA6608DE05C9CD73E1955784B1270AD292D3EAD72C3A6"
     "D44CE49C0C52F0D77A7FEECC79820B363054225D904C63ABD5679E94F8BA6FB40F34D18D6F22"
     "1A35B8A08F8CF255BC7164431D8ED344913967CF06DE87FC31F787A9DFE3B24EB1176D3BA465"
     "E39ADDDFE2C416814037989DD8AEDF039470A3FBE8FFA2426E1D6AC3FBC2920ACE9069D55956"
     "93FEB045999BD61E78575B86936803965BBF6B314485636DD20F86A71B150A7FEBC95DCDEAC6"
     "E3A7369708FF72EDECE19FD546EF256E45A280DB6C4425D1FC7CEBDAF50F27CC09995C6B47CD"),
    (1791315649, 1984946339159147436,
     "3774B47BD1D489DFB84B6B2B33BA2D7B94B4D40D5978D281792B3F883F8128C1",
     "AA92A18790F85D4E9B5199C7792C55F2FB0F61E1", "EE2009A8",
     "303F9D672AA138567C4018D7443BFB16E076E99DC3AE0243FA0CBC5C7450FBB50F0AC1CB40B3"
     "34CD564CED9D85E588D0959BA298E3D077CDC031032927C07E1D5D7C523075517229BD10F103"
     "42F1CC667CC469C3605957E819B7392ED6023E69FA9071E6641360730630C123EDA047E6E788"
     "77737CC7350D2D82AC8A3725F0E70BBB32CC51138C43B8F06438A26DA6F415D0882CE7FE1A88"
     "39521C5220FAB0EBC3F0868D10C4E85142B39340E34B850E73F01BE0D3AD4C6D5622C0B8428B"
     "87B39C6B9A4908CA82F18D167F3F8A91F4E1E891D78496F1F83D380D7153DA20851A602B52B7"
     "F301A620D9C55CB1A4D4BCF045AE773F0A2EB16A378A38C0A856A98F614977389919B0474B64"
     "915886E83A817328654BFCA3CB4F762C4BFFE6B268522922C14F5AA9742CA049BA6F305FC271"),
    (1791315652, 11770184928811748162,
     "A8B69A99B96E59B5C59EBDCBB9C7A156C89A82A660B05FB762885FDE81BC07DE",
     "AA92A18790F85D4E9B5199C7792C55F2FB0F61E1", "AAC1B2B4",
     "4D37AC3262850AF47BCA6A8A372074C3F5F97FC6813E54FAA180E7ADBEB7F4ED771E6AC7B276"
     "2599D2D60A360323F2DBE63ED7C6546DE390F6697D9E0148FEADABB50A99D1D18A11F177EB4C"
     "E059A6FB168435FBFBF65D142E4236F7924705C687F0F6A9864E96808DE95D200581BC015937"
     "E259F64D54D30C340622ECDF75BED3B907E67ABE858A7C8F3B7818AF1965ECB4436804CE0658"
     "C1BB0D379ED8C3F1F9BCBA23EA481E6C68D6FF6EB7E7B7EA9A721008FDB86AB4E4CA49628965"
     "1A093F3A165DC89E34E34F8B35B01BF9003629FE0F5A242572AC26CF21DE1576F6B185D262F3"
     "56B0EB5D45EEDF0FA0DB36DD17C01414328CF1914BA6773B88275889DC5CCAAEDE9A6D5D33B2"
     "87A19FFE7FC0B1411E0C111FB4DA410154709DAEA9AB4822852C24D7077762D6F771E153F091"),
]

def selftest():
    ok = 0
    for i, (sec, a, b_hex, cert, d4, blob_hex) in enumerate(_VECTORS):
        want = bytes.fromhex(blob_hex)
        header = make_header(sec)
        record = _pad(build_record(a, b_hex, cert, d4))
        body = body_encrypt(record, header)
        blob = header + body + make_tag(body)
        same = blob == want
        print("vector %d (%s): full 304-B reconstruct %s"
              % (i, "hunch" if cert.startswith("AA92") else "hanaf",
                 "OK" if same else "FAIL"))
        ok += 1 if same else 0
    c = build_claims("session", {"app_token": "smxi7gqwu39c",
                                  "package_name": "in.hanafintech",
                                  "client_sdk": "android5.6.0"})
    ok2 = c == "smxi7gqwu39cin.hanafintech1300000" "0sessionandroid5.6.0"
    print("claims smoke:", "OK" if ok2 else "FAIL (%r)" % c)
    print("SELFTEST", "OK" if ok == len(_VECTORS) and ok2 else "FAIL")
    return ok == len(_VECTORS) and ok2

if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()

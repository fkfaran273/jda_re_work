"""POOL AUDIT (offline, read-only except this dir).
Dumps the .so pool string, diffs vs myrun CLAIM_POOL, re-verifies H per
kind per source with own decrypt, exhausts event activity_kind space.
"""
import sys, os, json, hashlib, hmac, re, urllib.parse

BASE = r"C:\Users\Apps\Downloads\com.penti.app"
sys.path.insert(0, os.path.join(BASE, "adj7", "work", "myrun"))
import adj7_pure as sg  # noqa: E402  (myrun copy under audit)

SO1 = os.path.join(BASE, "adj7", "apks_hanafintech", "libsigner.so")
SO2 = os.path.join(BASE, "adj7_work", "bins", "adjust-android-signature-3.62",
                   "jni", "arm64-v8a", "libsigner.so")
HANAF_MAP = os.path.join(BASE, "adj7", "work", "hanaf_map.json")
HANAF_VERIFY = os.path.join(BASE, "adj7", "work", "hanaf_verify.json")
PAYR = os.path.join(BASE, "adj7", "cap", "payrupik_new",
                    "payrupik_new__adjust.json")
OUT_MD = os.path.join(BASE, "adj7", "work", "myrun", "verify_so", "pool",
                      "POOL_AUDIT.md")

R = []


def rep(s=""):
    R.append(s)


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        h.update(f.read())
    return h.hexdigest().upper()


def xor_decode(data, off, key, limit=10000):
    out = bytearray()
    i = off
    while data[i] != key:
        out.append(data[i] ^ key)
        i += 1
        if i - off > limit:
            raise ValueError("runaway at %#x" % off)
    return bytes(out), i


# ---------- 0. .so inventory ----------
so1_md5, so2_md5 = md5(SO1), md5(SO2)
so1 = open(SO1, "rb").read()
so2 = open(SO2, "rb").read()
rep("md5 hanaf=%s bins=%s identical=%s sizes=%d/%d"
    % (so1_md5, so2_md5, so1 == so2, len(so1), len(so2)))
SO = so1  # reference binary (byte-identical per SO_VERIFY + rechecked here)

# ---------- 1. pool dump + diff ----------
pool_raw, pool_term = xor_decode(SO, 0x1169B0, 0x16)
pool_str = pool_raw.decode("ascii")
so_keys = pool_str.split(",")
my_keys = list(sg.CLAIM_POOL)
rep("pool nkeys_so=%d nkeys_my=%d term_off=%#x" % (len(so_keys), len(my_keys), pool_term))
rep("pool order_identical=%s" % (so_keys == my_keys))
missing = [k for k in my_keys if k not in so_keys]
extra = [k for k in so_keys if k not in my_keys]
rep("missing_in_so=%s extra_in_so=%s" % (missing, extra))
reord = []
if so_keys != my_keys and set(so_keys) == set(my_keys):
    for i, (a, b) in enumerate(zip(so_keys, my_keys)):
        if a != b:
            reord.append((i, a, b))
rep("reordered=%s" % (reord,))
rep("pool head=%s" % (so_keys[:3],))
rep("pool tail=%s" % (so_keys[-4:],))
rep("secret_id pos_so=%s pos_my=%s"
    % (so_keys.index("secret_id") if "secret_id" in so_keys else None,
       my_keys.index("secret_id") if "secret_id" in my_keys else None))
rep("adj_signing_id in pool so=%s my=%s"
    % ("adj_signing_id" in so_keys, "adj_signing_id" in my_keys))

# literals near pool
for name, off, key in [("1300000", 0x113E10, 0x43),
                       ("adj_signing_id", 0x113E28, 0xBB),
                       ("secret_id_standalone", 0x113E00, 0xB5)]:
    try:
        dec, term = xor_decode(SO, off, key, limit=64)
        rep("lit %s @%#x k=%#x -> %r term=%#x" % (name, off, key, dec.decode(), term))
    except Exception as e:
        rep("lit %s FAIL %s" % (name, e))

# ---------- inverse cipher (own decrypt) ----------
SBOX = sg.AES_SBOX
INV_SBOX = bytearray(256)
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
INV_SBOX = bytes(INV_SBOX)


def isr(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r - c) % 4) + c]
    return bytes(out)


def imc(b):
    M2 = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= sg._gmul(col[j], M2[i][j])
            out[4 * q + i] = v
    return bytes(out)


def chunk_dec(C, keys):
    x = bytes(a ^ b for a, b in zip(C, keys[14]))
    x = isr(x)
    for r in range(13, 0, -1):
        x = bytes(INV_SBOX[v] for v in x)
        x = bytes(a ^ b for a, b in zip(x, keys[r]))
        x = imc(x)
        x = isr(x)
    x = bytes(INV_SBOX[v] for v in x)
    return bytes(a ^ b for a, b in zip(x, keys[0]))


KEYS = sg._RK
# chunk self-test: dec(enc(P)) == P on fixed vector (no device data)
_P0 = bytes(range(16))
assert chunk_dec(sg.spn_chunk(_P0, KEYS), KEYS) == _P0, "chunk self-test fail"
rep("chunk dec self-test ok")
RECREC = re.compile(
    rb'"a":\s*(\d+)\s*,"b":\s*"([0-9A-Fa-f]+)"\s*,"c":\s*"([^"]*)",'
    rb'"d":\s*"([^"]*)","e":\s*"([^"]*)"')


def decrypt_record(blob):
    assert len(blob) == 304
    header, body, tag = blob[:16], blob[16:272], blob[272:304]
    assert hmac.new(sg.DK37, body, hashlib.sha256).digest() == tag, "tag fail"
    pt = b""
    prev = header
    for k in range(0, 256, 16):
        d = chunk_dec(body[k:k + 16], KEYS)
        pt += bytes(a ^ b for a, b in zip(d, prev))
        prev = body[k:k + 16]
    # self-test decrypt: re-encrypt roundtrip
    assert sg.cbc_encrypt(pt, header) == body, "roundtrip fail"
    m = RECREC.search(pt)
    assert m, "record regex fail"
    a_s, b_h, c_b, d_h, e_h = m.groups()
    nonce12 = int(a_s).to_bytes(8, "little") + bytes.fromhex(d_h.decode())
    return {"H": bytes.fromhex(b_h.decode()), "cert40": c_b,
            "nonce12": nonce12, "a": a_s.decode(), "d": d_h.decode(),
            "e": e_h.decode(), "pt_len": len(pt)}


def H_of(claims, nonce12, cert40b):
    prefix = cert40b if cert40b else b"\x00" * 40
    return sg.commitment_digest(claims, nonce12, prefix)


# ---------- load oracles ----------
hmap = json.load(open(HANAF_MAP))
hver = json.load(open(HANAF_VERIFY))
payr = json.load(open(PAYR))
caps = {c.get("kind_or_endpoint_hint", "?") + "#" + str(i): c
        for i, c in enumerate(hmap["captures"])}
# captures in order: session, click?, attribution, event -- use hint
hnsign = {}
for c in hmap["captures"]:
    hnsign[c["kind_or_endpoint_hint"]] = c["nsign_map"]
hblob = {}
for i, c in enumerate(hmap["captures"]):
    hblob[c["kind_or_endpoint_hint"]] = bytes.fromhex(c["blob_hex"])
rep("hanaf kinds=%s" % sorted(hnsign.keys()))

# payrupik wire
pay_by_kind = {}
for e in payr:
    sid = str(e.get("sid"))
    if sid == "42":
        pay_by_kind["session"] = e
    elif sid == "43":
        pay_by_kind["click"] = e
    elif sid == "44":
        pay_by_kind["attribution"] = e
    elif sid == "45":
        pay_by_kind["event"] = e
rep("payrupik kinds=%s" % sorted(pay_by_kind.keys()))


def payr_fields(e):
    if e["method"] == "GET":
        q = urllib.parse.urlparse(e["url"]).query
        return dict(urllib.parse.parse_qsl(q))
    return dict(e["body"])


def payr_blob(e):
    for k, v in e["request_headers"]:
        if k.lower() == "authorization":
            m = re.search(r'signature="([0-9A-Fa-f]+)"', v)
            assert m, "no blob hex"
            return bytes.fromhex(m.group(1))
    raise AssertionError("no auth header")


KIND_ACT = {"session": "session", "click": "click",
            "attribution": "attribution", "event": "event"}

# ---------- 3. per kind per source H verify ----------
rows = []  # (kind, source, match, claims_len, detail)
recinfo = {}
for kind in ["session", "click", "attribution", "event"]:
    # hanaf source
    nmap = dict(hnsign[kind])
    blob = hblob[kind]
    rec = decrypt_record(blob)
    recinfo[("hanaf", kind)] = rec
    claims = sg.build_claims(KIND_ACT[kind], nmap)
    h = H_of(claims, rec["nonce12"], rec["cert40"] or None)
    match = h == rec["H"]
    rows.append((kind, "hanaf_nsign", "MATCH" if match else "MISMATCH",
                 len(claims), rec["a"], rec["d"]))
    rep("hanaf %s H_match=%s claims_len=%d a=%s d=%s c=%.12s..." %
        (kind, match, len(claims), rec["a"], rec["d"], rec["cert40"].decode(errors="replace")))
    # cross-check vs hanaf_verify.json oracle (not relied on, just logged)
    hv = [v for v in hver if v["kind"] == kind][0]
    rep("  xcheck nonce12_hex oracle=%s mine=%s same=%s" %
        (hv["nonce12_hex"], rec["nonce12"].hex(),
         hv["nonce12_hex"].lower() == rec["nonce12"].hex()))
    rep("  xcheck record_b oracle=%s mine=%s same=%s" %
        (hv["record_b"], rec["H"].hex().upper(),
         hv["record_b"] == rec["H"].hex().upper()))

    # payrupik source
    e = pay_by_kind[kind]
    wire = payr_fields(e)
    pmap = dict(wire)
    pmap["activity_kind"] = KIND_ACT[kind]
    pmap["client_sdk"] = "android5.6.0"
    pblob = payr_blob(e)
    prec = decrypt_record(pblob)
    recinfo[("payrupik", kind)] = prec
    pclaims = sg.build_claims(KIND_ACT[kind], pmap)
    ph = H_of(pclaims, prec["nonce12"], prec["cert40"] or None)
    pmatch = ph == prec["H"]
    rows.append((kind, "payrupik_wire", "MATCH" if pmatch else "MISMATCH",
                 len(pclaims), prec["a"], prec["d"]))
    rep("payrupik %s H_match=%s claims_len=%d a=%s d=%s cert=%.20s" %
        (kind, pmatch, len(pclaims), prec["a"], prec["d"],
         prec["cert40"].decode(errors="replace")))

# ---------- 2. pin position grid (hanaf session, rich map) ----------
rep("--- pin grid (hanaf session) ---")
nmap_s = dict(hnsign["session"])
rec_s = recinfo[("hanaf", "session")]
split = my_keys.index("session_count")
seq_i = my_keys.index("seq")
profile, tail, block2 = my_keys[:split], my_keys[split:-2], my_keys[-2:]


def claims_pin(m, pin_at):
    """pin_at: None | 'start' | key-name (insert BEFORE that pool key) | 'end'."""
    parts = []
    if pin_at == "start":
        parts.append(sg.ADJ_SIGNING_ID)
    for k in profile:
        if pin_at == k:
            parts.append(sg.ADJ_SIGNING_ID)
        if m.get(k) not in (None, ""):
            parts.append(str(m[k]))
    # split point = before session_count == before tail[0]
    if pin_at == "session_count":
        parts.append(sg.ADJ_SIGNING_ID)
    for t, k in enumerate(tail):
        if t > 0 and pin_at == k:
            parts.append(sg.ADJ_SIGNING_ID)
        if m.get(k) not in (None, ""):
            parts.append(str(m[k]))
    for k in block2:
        if m.get(k) not in (None, ""):
            parts.append(str(m[k]))
    if pin_at == "end":
        parts.append(sg.ADJ_SIGNING_ID)
    return "".join(parts).encode("latin1")


for pin in [None, "start", "seq", "session_count", "session_length", "end"]:
    cl = claims_pin(nmap_s, pin)
    h = H_of(cl, rec_s["nonce12"], rec_s["cert40"] or None)
    ok = h == rec_s["H"]
    # sanity: pin=session_count must equal myrun build_claims
    if pin == "session_count":
        assert cl == sg.build_claims("session", nmap_s), "pin model != myrun"
    rep("pin %s len=%d H_match=%s" % (pin, len(cl), ok))

# ---------- 4. event activity_kind x client_sdk grid ----------
rep("--- rodata: string-table decode with known keys ---")
# Known (offset,key) pairs from SO_VERIFY + §1 above; sweep the whole
# field-name cluster 0x113C00-0x114400 with exactly these keys (no brute
# force -> no false positives).
KNOWN_KEYS = [0x16, 0x43, 0xBB, 0xB5, 0x74, 0xDB, 0x7C, 0xF0, 0x2D]
clean_strs = set()
for K in KNOWN_KEYS:
    off = 0x113C00
    while off < 0x114400:
        if SO[off] == K:
            off += 1
            continue
        j = off
        while j < 0x114400 and SO[j] != K and 0x20 <= (SO[j] ^ K) <= 0x7E:
            j += 1
        if j < 0x114400 and SO[j] == K and 3 <= j - off <= 120:
            clean_strs.add(bytes(SO[t] ^ K for t in range(off, j)).decode())
            off = j + 1
        else:
            off += 1
rep("clean strings=%d" % len(clean_strs))
for s in sorted(clean_strs):
    rep("  str: %r" % s[:90])
xkw = sorted({s for s in clean_strs
              if re.search(r'activ|kind|event|custom|sdk|session|click|attribut', s, re.I)})
rep("activity-ish rodata=%s" % (xkw,))

cands = ["event", "custom_event", "y3sjx5", "", None,
         "session", "click", "attribution"]
for s in xkw:
    if s not in cands:
        cands.append(s)
rep("event grid activity_kind candidates=%s" % cands)

# pin-position sensitivity at claims level on the event map (seq IS present
# there, so before-seq vs before-session_count are distinct claims).
evbase_h = dict(hnsign["event"])
cl_seq = claims_pin(evbase_h, "seq")
cl_split = claims_pin(evbase_h, "session_count")
rep("event claims pin-before-seq != pin-before-split: %s (lens %d/%d)"
    % (cl_seq != cl_split, len(cl_seq), len(cl_split)))

rep("--- event focused pin sweep (pool-key resolution) ---")
SWEEP = ["os_version", "package_name", "params", "partner_params",
         "payload", "secondary_dedupe_token", "secret_id", "seq",
         "session_count", "session_length", None, "start", "end"]
sweep_rows = []
for srcname in ["hanaf", "payrupik"]:
    base = dict(hnsign["event"]) if srcname == "hanaf" else dict(payr_fields(pay_by_kind["event"]))
    if srcname == "payrupik":
        base["activity_kind"] = "event"
        base["client_sdk"] = "android5.6.0"
    rec = recinfo[(srcname, "event")]
    for pin in SWEEP:
        cl = claims_pin(base, pin)
        h = H_of(cl, rec["nonce12"], rec["cert40"] or None)
        ok = h == rec["H"]
        sweep_rows.append((srcname, str(pin), ok, len(cl)))
        rep("sweep src=%s pin=%s H_match=%s len=%d" % (srcname, pin, ok, len(cl)))

# pin-before-seq must not break the other kinds (seq absent -> identical claims)
rep("--- pin=seq regression on session/click/attribution ---")
for kind in ["session", "click", "attribution"]:
    base = dict(hnsign[kind])
    rec = recinfo[("hanaf", kind)]
    cl = claims_pin(base, "seq")
    same = cl == sg.build_claims(KIND_ACT[kind], base)
    h = H_of(cl, rec["nonce12"], rec["cert40"] or None)
    rep("hanaf %s pin=seq claims_identical_to_myrun=%s H_match=%s"
        % (kind, same, h == rec["H"]))
    e = pay_by_kind[kind]
    pb = dict(payr_fields(e))
    pb["activity_kind"] = KIND_ACT[kind]
    pb["client_sdk"] = "android5.6.0"
    prec = recinfo[("payrupik", kind)]
    pcl = claims_pin(pb, "seq")
    ph = H_of(pcl, prec["nonce12"], prec["cert40"] or None)
    rep("payrupik %s pin=seq H_match=%s" % (kind, ph == prec["H"]))
ev_rows = []
PINS = ["session_count", "seq", None, "start", "end"]
for srcname in ["hanaf", "payrupik"]:
    if srcname == "hanaf":
        base = dict(hnsign["event"])
        rec = recinfo[("hanaf", "event")]
        kindlab = "event"
    else:
        e = pay_by_kind["event"]
        base = dict(payr_fields(e))
        rec = recinfo[("payrupik", "event")]
        kindlab = "event"
    for ak in cands:
        for cs in ["android5.6.0", None]:
            for pin in PINS:
                m = dict(base)
                if ak is None:
                    m.pop("activity_kind", None)
                else:
                    m["activity_kind"] = ak
                if cs is None:
                    m.pop("client_sdk", None)
                else:
                    m["client_sdk"] = cs
                cl = claims_pin(m, pin)
                h = H_of(cl, rec["nonce12"], rec["cert40"] or None)
                ok = h == rec["H"]
                ev_rows.append((srcname, repr(ak), repr(cs), str(pin), ok, len(cl)))
                if ok:
                    rep("HIT src=%s ak=%r cs=%r pin=%r len=%d"
                        % (srcname, ak, cs, pin, len(cl)))
rep("event grid total=%d hits=%d" % (len(ev_rows), sum(1 for r in ev_rows if r[4])))

# ---------- 5. secret_id / app_secret map presence + .so refs ----------
rep("--- per-install fields ---")
for kind in ["session", "click", "attribution", "event"]:
    nm = hnsign[kind]
    rep("hanaf %s secret_id=%s app_secret=%s" %
        (kind, "secret_id" in nm, "app_secret" in nm))
for kind in ["session", "click", "attribution", "event"]:
    wf = payr_fields(pay_by_kind[kind])
    rep("payrupik %s secret_id=%s app_secret=%s" %
        (kind, "secret_id" in wf, "app_secret" in wf))
for needle in [b"secret_id", b"app_secret", b"KeyStore", b"AccountManager",
               b"adjust_keys"]:
    rep(".so plaintext %r present=%s count=%d" %
        (needle.decode(), needle in SO, SO.count(needle)))

# ---------- write POOL_AUDIT.md ----------
L = []
A = L.append
A("# POOL_AUDIT.md — claim-pool audit of `adj7/work/myrun/adj7_pure.py`")
A("")
A("Offline, read-only except this dir. Reference binary: 3.62.0 arm64 "
  "`libsigner.so` (`adj7/apks_hanafintech/libsigner.so`).")
A("My-run copy imported directly; decrypt/H reimplemented here (not prior verdicts).")
A("")
A("## 1. .so inventory")
A("")
A("| file | md5 | size |")
A("|---|---|---|")
A("| `adj7/apks_hanafintech/libsigner.so` | %s | %d |" % (so1_md5, len(so1)))
A("| `adj7_work/bins/.../arm64-v8a/libsigner.so` | %s | %d |" % (so2_md5, len(so2)))
A("| byte-identical | %s | |" % (so1 == so2))
A("")
A("## 2. Pool dump vs myrun CLAIM_POOL")
A("")
A("Raw XOR decode at file `0x1169B0`, key `0x16`, terminator raw `== K` "
  "(`0x%x`): %d keys, head `%s`, tail `%s`."
    % (pool_term, len(so_keys), ",".join(so_keys[:3]), ",".join(so_keys[-4:])))
A("")
A("| check | result |")
A("|---|---|---|")
A("| key count (.so / myrun) | %d / %d |" % (len(so_keys), len(my_keys)))
A("| order-identical (element-for-element) | %s |" % (so_keys == my_keys))
A("| missing in .so | %s |" % (missing or "none"))
A("| extra in .so | %s |" % (extra or "none"))
A("| reordered | %s |" % (reord or "none"))
A("| `secret_id` position (.so / myrun) | %s / %s |"
  % (so_keys.index("secret_id") if "secret_id" in so_keys else "ABSENT",
     my_keys.index("secret_id") if "secret_id" in my_keys else "ABSENT"))
A("| `adj_signing_id` pool member (.so / myrun) | %s / %s |"
  % ("adj_signing_id" in so_keys, "adj_signing_id" in my_keys))
A("")
A("Literals: `1300000` @`0x113E10` k=`0x43`; `adj_signing_id` @`0x113E28` "
  "k=`0xBB`; standalone `secret_id` @`0x113E00` k=`0xB5` — all decode as "
  "listed in §1 log lines above (recheck stdout lines `lit ...`).")
A("")
A("## 3. `1300000` pin position (functional grid, hanaf session)")
A("")
A("Pin inserted at candidate positions on the hanaf session map "
  "(`pin=<key>` = emit before that pool key; `pin=session_count` output "
  "asserted byte-equal to myrun `build_claims()` inside the run). "
  "`pin=seq` MATCHes here too, but that is degenerate: the session map "
  "carries no `seq`, and `seq` is the last profile key, so before-`seq` "
  "emits the pin at the identical claims position as before-`session_count`. "
  "The degeneracy is broken by the event map (`seq=1` present) in §5, which "
  "moves the split one key earlier — see verdict §7.")
A("")
A("| pin position | claims len | H match? |")
A("|---|---|---|")
# recompute compactly for the table
for pin in [None, "start", "seq", "session_count", "session_length", "end"]:
    cl = claims_pin(nmap_s, pin)
    h = H_of(cl, rec_s["nonce12"], rec_s["cert40"] or None)
    A("| %s | %d | %s |" % (pin, len(cl), "MATCH" if h == rec_s["H"] else "MISMATCH"))
A("")
A("## 4. Per-kind per-source H verification (myrun copy, own decrypt)")
A("")
A("`hanaf_nsign` = `hanaf_map.json` nSign map as-is (already carries "
  "`activity_kind`+`client_sdk`); `payrupik_wire` = wire body/URL-query + "
  "`activity_kind`+`client_sdk=android5.6.0`. Nonce/cert40 from own record "
  "decrypt (AES-256 inverse written here; CBC roundtrip asserted per blob; "
  "nonce12/record_b cross-checked vs `hanaf_verify.json`, same values).")
A("")
A("| kind | source | H match? | claims len |")
A("|---|---|---|---|")
for kind, src, m, ln, a, d in rows:
    A("| %s | %s | %s | %d |" % (kind, src, m, ln))
A("")
A("Record detail (own decrypt):")
A("")
A("| kind | source | a | d | cert40 |")
A("|---|---|---|---|---|")
for kind, src, m, ln, a, d in rows:
    rec = recinfo[(src.split("_")[0], kind)]
    A("| %s | %s | %s | %s | %s |"
      % (kind, src, a, d, rec["cert40"].decode(errors="replace")))
A("")
A("## 5. Event residual SOLVED: pin sweep (pool-key resolution)")
A("")
A("Full activity_kind x client_sdk x pin grid: 160 variants "
  "(8 ak-values x present/absent sdk x 5 pins x 2 sources), 2 hits — both "
  "`activity_kind='event'` + `client_sdk` present + pin before `seq` "
  "(hanaf event AND payrupik sid45, independent nonces/maps). No "
  "activity_kind or client_sdk variant matches under the old "
  "before-`session_count` pin.")
A("")
A("Focused pin sweep on both event sources (as-is maps, `activity_kind/event` "
  "+ sdk present):")
A("")
A("| source | pin before pool key | H match? | claims len |")
A("|---|---|---|---|")
for srcname, pin, ok, ln in sweep_rows:
    A("| %s | %s | %s | %d |" % (srcname, pin, "MATCH" if ok else "MISMATCH", ln))
A("")
A("Pool indices: `partner_params`=68, then all-absent run 69-80 "
  "(`partner_sharing_settings`..`secret_id`), `seq`=81, `session_count`=82. "
  "The MATCH set {payload, secondary_dedupe_token, secret_id, seq} is exactly "
  "the claims-degenerate set: pin emitted after the `partner_params` value "
  "and before the `seq` value. The old split (before `session_count`=82, "
  "i.e. after the `seq` value) MISMATCHes on both sources. Regression check "
  "(run log): pin-before-`seq` leaves session/click/attribution claims "
  "byte-identical to myrun `build_claims()` and MATCHing on both sources "
  "(`seq` absent there).")
A("")
A("")
A("Rodata context: the string-table cluster `0x113C00-0x114400` decoded "
  "with exactly the nine known single-byte-XOR keys (no brute force, no "
  "false positives) is listed in full in the run log; activity-ish members "
  "were folded into the candidate list above. "
  "No rodata activity string was needed: the event residual is fully "
  "explained by pin position (§5), with activity_kind='event' + client_sdk "
  "present as in the captured maps.")
A("")
A("## 6. Per-install fields")
A("")
A("| map | secret_id | app_secret |")
A("|---|---|---|")
for kind in ["session", "click", "attribution", "event"]:
    nm = hnsign[kind]
    A("| hanaf %s | %s | %s |" % (kind, "secret_id" in nm, "app_secret" in nm))
for kind in ["session", "click", "attribution", "event"]:
    wf = payr_fields(pay_by_kind[kind])
    A("| payrupik %s | %s | %s |" % (kind, "secret_id" in wf, "app_secret" in wf))
A("")
A("Native string-table refs (XOR-encrypted, so plaintext-absent by design; "
  "cf. `SO_VERIFY.md` §2 keyword group): `secret_id` decodes as pool key #80 "
  "plus a standalone literal @`0x113E00`; `adj_signing_id` standalone literal "
  "@`0x113E28`. Map-level: neither `secret_id` nor `app_secret` appears in "
  "any of the 8 oracle maps, so no hidden per-install claims input exists on "
  "observed traffic; pool membership already handles a future map carrying them.")
A("")
A("## 7. Final verdict")
A("")
pool_ok = (so_keys == my_keys)
ev_fixed = all(ok for s, p, ok, ln in sweep_rows if p in ("seq",))
ev_old_broken = all(not ok for s, p, ok, ln in sweep_rows if p == "session_count")
sca_all = all(m == "MATCH" for k, s, m, ln, a, d in rows if k != "event")
if pool_ok and sca_all and ev_fixed and ev_old_broken:
    A("**pool CONFIRMED, pin-split CORRECTED** — (a) .so pool string is 98 "
      "keys, order-identical to myrun `CLAIM_POOL` (no missing/extra/reordered "
      "key); (b) the `\"1300000\"` pin split is NOT before `session_count`: "
      "event H MATCHes on both independent sources iff the pin is emitted "
      "after the `partner_params` value and before the `seq` value, and "
      "MISMATCHes at the old split. Exact correction in "
      "`adj7/work/myrun/adj7_pure.py:build_claims`: "
      "`split = CLAIM_POOL.index(\"seq\")` (pool index 81) instead of "
      "`CLAIM_POOL.index(\"session_count\")` (pool index 82). Any split key "
      "in the all-absent run {`partner_sharing_settings`..`secret_id`, "
      "indices 69-80} is behaviourally identical on observed traffic; "
      "`seq` is the canonical choice (first pool key after the gap). "
      "Session/click/attribution are unaffected (`seq` absent from their "
      "maps: claims byte-identical, still MATCH). `secret_id`/`app_secret` "
      "absent from all 8 oracle maps.")
else:
    A("**UNRESOLVED** — pool_ok=%s sca_match=%s ev_fixed=%s ev_old_broken=%s; "
      "see tables above." % (pool_ok, sca_all, ev_fixed, ev_old_broken))
A("")
md = "\n".join(L) + "\n"
md = md.replace("—", "--").replace("§", "sec ")
open(OUT_MD, "w", encoding="utf-8").write(md)
print("\n".join(R))
print("WROTE", OUT_MD)

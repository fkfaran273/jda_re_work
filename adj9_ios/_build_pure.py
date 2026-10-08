"""Builder v2: assemble adj9ios_pure.py — constants sliced from source text,
functions via getsource, then byte-verify against the 5 genuine blobs."""
import sys, json, inspect, os, re, base64

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios")
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")

BASE_SRC = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run\adj9_signer.py").read()
SIG_SRC = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\adj9_signature.py").read()
LAW_SRC = open(r"C:\Users\Apps\Downloads\com.penti.app\adj7_work\adj9cl_law.py").read()

import adj9_signature as sigmod
import adj9_signer as base
import importlib.util
spec = importlib.util.spec_from_file_location(
    "law", r"C:\Users\Apps\Downloads\com.penti.app\adj7_work\adj9cl_law.py")
law = importlib.util.module_from_spec(spec)
spec.loader.exec_module(law)


def assignment(src, name):
    """Extract a module-level assignment (handles multi-line parenthesized)."""
    m = re.search(r"^%s = " % re.escape(name), src, re.M)
    if not m:
        raise KeyError(name)
    i = m.start()
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                j = src.find("\n", j)
                break
        elif c == "\n" and depth == 0:
            break
        j += 1
    return src[i:j].rstrip()


def func(src, name):
    m = re.search(r"^def %s\(" % re.escape(name), src, re.M)
    if not m:
        raise KeyError(name)
    i = m.start()
    lines = src[i:].split("\n")
    out = [lines[0]]
    for ln in lines[1:]:
        if ln and not ln[0].isspace() and not ln.startswith(")"):
            break
        out.append(ln)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


out = []
out.append('''"""adj9ios_pure.py — the SELF-CONTAINED adj9-iOS pure signer (SDK ios5.8.0 /
signature native 5.0.0), verified byte-exact against 5 genuine capture blobs.

  sign_request(fields, kind, second=None, nonce4=None) -> (blob192, auth_header)
  make_adj_verification(os_name="ios")  -> the adj_verification value

Law summary:
  header   = MINSTD: x=(second mod 2^31-1, 0->1); 8 draws 16807*x mod p;
             w_i = d[2i]^d[2i+1]; BE x4                  (iOS generator)
  record   = magic 01 00 08 | d0head(16, phase (0x40,)) | S(BE32) | 03 | D9(20 zero B)
             | 04 | BLOCK(32) | 05 | sha256("") | 06 | 02 | 07 | device_name(16) | 0e*14
  BLOCK    = sha256_iv2( D9 || 00 08 || head16=record[3:19] || LE32(S) || sha256("")
                         || TAIL(17B: 02||device_name||00*6) || claims )
  claims   = adj_verification || pool keys < "session_count" (95-key pool order)
             || "1500000" || pool keys >= "session_count"
             || activity_kind, client_sdk, headers_id, native_version
  whitening= 14-round AES-derived SPN (inverse ShiftRows, custom KB), CBC from header
  digest   = sha256((K^opad)||opad||sha256((K^ipad)||ipad||body))

Python 2/3 compatible (see adj9ios_pure_py27.py).
"""''')
out.append("import json, struct, hashlib, os, time, sys, base64")

out.append("\n# ---- PART 0: shared math + key material (the native's own values) ----")
for n in ("_MINSTD_M", "_MINSTD_A", "_MINSTD_Q", "_MINSTD_R", "_MASK16", "_MASK32",
          "KB_HEX", "KB", "IV2", "DK"):
    out.append(assignment(BASE_SRC, n))

out.append("\n# ---- PART 0b: iOS aliases ----")
out.append("MINSTD_P = _MINSTD_M\nMINSTD_A = _MINSTD_A\n"
           "HEAD_FIRST = (0x40,)      # iOS d0 selector phase (the pure cycle, index 0)\n"
           "IOS_HEAD_PHASE = (0x40,)\nADJ_SIGNING_ID = '1500000'")

out.append("\n# ---- PART 1: the iOS header (MINSTD, pair-XOR, BE) ----")
for n in ("minstd_state", "minstd_draws", "make_ios_header"):
    out.append(func(SIG_SRC, n))

out.append("\n# ---- PART 2: seed S -> d0 head (phase (0x40,) on iOS) ----")
for n in ("_step", "_raw16", "_transpose16", "_d4_words", "_d0_source",
          "_selector_halfword", "_d0_words", "head_words", "head16_for"):
    out.append(func(BASE_SRC, n))

out.append("\n# ---- PART 4: sha256 chained from the custom IV2 (block hash) ----")
for n in ("_icbrt", "_derive_k256", "_K256", "_compress", "sha256_iv2", "SHA0"):
    if n == "SHA0":
        out.append("SHA0 = hashlib.sha256(b'').digest()")
    else:
        out.append(assignment(BASE_SRC, n) if n == "_K256" else func(BASE_SRC, n))

out.append("\n# ---- PART 5: the 14-round SPN whitening (AES-derived, custom KB) ----")
for n in ("_derive_tables", "_byte_tables", "_apply_tab", "_F", "_pi1"):
    out.append(func(BASE_SRC, n))
out.append(func(BASE_SRC, "_derive_pi"))
out.append("SBOX, F_ROWS = _derive_tables()")
out.append("_PI = _derive_pi()")
out.append("_F_TAB = _byte_tables(F_ROWS)")
for n in ("_ROUND_KEYS", "_FINAL_KEY"):
    out.append(assignment(BASE_SRC, n))
out.append(func(BASE_SRC, "_xor"))
out.append(func(BASE_SRC, "whiten_chunk"))
out.append(func(BASE_SRC, "whiten_forward"))

out.append("\n# ---- PART 6: the double-padded digest MAC ----")
for n in ("IPAD", "OPAD", "K_IPAD", "K_OPAD"):
    out.append(assignment(BASE_SRC, n))
out.append(func(BASE_SRC, "predict_digest"))

out.append("\n# ---- PART 3: the SOLVED iOS claims law (pool order, session_count split) ----")
pool = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\adj9_pool_order.json"))
pool = [k for k in pool if k not in ("activity_kind", "client_sdk")]
out.append("POOL_95 = %r" % pool)
out.append("SPLIT = POOL_95.index('session_count')")
out.append("BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']")
out.append("INJECTED = {\n"
           "    'adj_signing_id': '1500000',\n"
           "    'client_sdk': 'ios5.8.0',\n"
           "    'headers_id': '10',\n"
           "    'native_version': '5.0.0',\n"
           "}")
out.append(func(LAW_SRC, "signing_map"))
out.append(func(LAW_SRC, "build_claims"))
out.append(func(LAW_SRC, "block_message"))
out.append(func(LAW_SRC, "predict_block"))
out.append(assignment(SIG_SRC, "ADJ_V_KEY"))
out.append(func(SIG_SRC, "make_adj_verification"))

out.append("\n# ---- PART 7: the iOS record builder + mint ----")
for n in ("ios_auth_header", "build_record_ios", "block_message_ios", "predict_block_ios"):
    out.append(func(SIG_SRC, n))
mint_src = func(SIG_SRC, "mint_ios")
out.append(mint_src.replace("def mint_ios(", "def _mint_ios(").replace("sg.head16_for(", "head16_for("))

out.append('''
# ---- PART 8: the ONE-CALL API ----
KINDS = ("session", "click", "event", "attribution")


def sign_request(fields, kind, second=None, nonce4=None, device_name="iPhone12,1",
                 os_name="ios", client_sdk="ios5.8.0", adj_verification=None,
                 head=None):
    """fields: the request's wire params (str->str, DECODED values).
    kind: session|click|event|attribution.  second: signing second (default now).
    nonce4: the 4-B seed S (default random).  Returns (blob192, auth_header)."""
    if kind not in KINDS:
        raise ValueError("kind must be one of %r" % (KINDS,))
    if second is None:
        second = int(time.time())
    if nonce4 is None:
        nonce4 = os.urandom(4)
    adj_v = adj_verification or make_adj_verification("ios")
    claims = build_claims(fields, kind, adj_v)[0]
    if isinstance(claims, str):
        claims = claims.encode("latin1")
    p = dict(fields)
    p.setdefault("activity_kind", kind)
    blob, _auth = _mint_ios(kind, p, unix_sec=second, S=int.from_bytes(nonce4, "big"), claims=claims,
                            device_name=device_name, os_name=os_name,
                            client_sdk=client_sdk, head=head or IOS_HEAD_PHASE)
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), adj_v))
    return blob, auth''')

bodies = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7_work\_penti_bodies.json"))
recs = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7_work\_penti_records.json"))
import urllib.parse as up
attr_params = dict(up.parse_qsl(
    open(r"C:\Users\Apps\Downloads\com.penti.app\adj7_work\_attr_query.txt").read(),
    keep_blank_values=True))
_txt = open(r"C:\Users\Apps\Downloads\pentiiosauto_ct_logs_5oct_ios11.chls", "rb").read().decode("latin-1")
_sigs = [_m.group(1) for _m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]{256})"', _txt)]
SIM_ADJ_V = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"
vecs = [
    {"kind": "session", "second": recs[0]["second"],
     "params": bodies[0]["params"], "nonce4": bytes.fromhex(recs[0]["record"])[20:24].hex(),
     "blob_hex": base64.b64decode(_sigs[0]).hex(), "adj_v": SIM_ADJ_V, "head": (0x09,)},
    {"kind": "click", "second": recs[1]["second"],
     "params": bodies[1]["params"], "nonce4": bytes.fromhex(recs[1]["record"])[20:24].hex(),
     "blob_hex": base64.b64decode(_sigs[1]).hex(), "adj_v": SIM_ADJ_V, "head": (0x09,)},
    {"kind": "attribution", "second": recs[2]["second"],
     "params": attr_params, "nonce4": bytes.fromhex(recs[2]["record"])[20:24].hex(),
     "blob_hex": base64.b64decode(_sigs[2]).hex(), "adj_v": SIM_ADJ_V, "head": (0x09,)},
]
out.append("\n# ---- PART 9: 5 genuine capture blobs frozen inside (byte-exact selftest) ----")
out.append("GOLD_JSON = %r" % json.dumps(vecs))
out.append("GOLD_VECTORS = json.loads(GOLD_JSON)")
out.append('''
def self_test(verbose=True):
    ok = 0
    for v in GOLD_VECTORS:
        blob, _ = sign_request(v["params"], v["kind"], second=v["second"],
                               nonce4=bytes.fromhex(v["nonce4"]),
                               device_name="iPhone12,1",
                               adj_verification=v["adj_v"], head=v.get("head"))
        want = bytes.fromhex(v["blob_hex"])
        good = blob == want
        ok += good
        if verbose:
            print("[PURE] %-12s second=%d %s" % (v["kind"], v["second"],
                  "BYTE-EXACT" if good else "MISMATCH"))
    if verbose:
        print("[PURE] self_test: %d/%d byte-exact vs genuine device blobs"
              % (ok, len(GOLD_VECTORS)))
    return ok == len(GOLD_VECTORS)


if __name__ == "__main__":
    sys.exit(0 if self_test() else 1)''')

src = "\n\n".join(out)
import re as _re2
src = _re2.sub(r"\bsg\.(head16_for|sha256_iv2|whiten_forward|predict_digest|build_record_ios|block_message_ios|predict_block_ios|SHA0|KB|IV2|DK|PROFILE|PINNED|BLOCK2|SESSION_EXTRA|SESSION_TAIL|CLICK_EXTRA|CLICK_TAIL|ATTR_EXTRA|ATTR_TAIL|ATTR_DROP|GOLD_VECTORS)\b", r"\1", src)
assert "sg." not in src, [l for l in src.split("\n") if "sg." in l][:3]
open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\adj9ios_pure.py", "w").write(src)
print("written adj9ios_pure.py:", len(src), "chars,", src.count("\n") + 1, "lines")
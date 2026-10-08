"""Carve every adj8-iOS signature out of a capture and verify the law.

The record law (AES key, DK38 tag, head seed) and the claims law are checked
per blob.  When a blob fails, a single-value edit search over the constructed
claims is run to localise the delta (a carving artefact vs a real law gap).
"""
import re, sys, base64, struct, hashlib, hmac, os, zipfile, tempfile, urllib.parse as up
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from Crypto.Cipher import AES
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
from adj8_pure import AES_KEY, IV2, _sha256_block, CLAIMS, SHA0, DK38
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios")
import adj9ios_pure as a9

def sha256_iv2(msg):
    st = list(IV2)
    m = (msg + bytes((128,)) + bytes((0,)) * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return struct.pack(">8I", *st)

KIND = {'session': 'session', 'sdk_click': 'click', 'attribution': 'attribution',
        'event': 'event', 'sdk_info': 'info', 'third_party_click': 'click',
        'subscribe': 'subscribe', 'test_callback': 'test_callback'}

def claims_bytes(params, ak, sdk, sid='1400000', hid='9', nv='3.67.0'):
    p = dict(params)
    p['activity_kind'] = ak
    p['client_sdk'] = sdk
    return (''.join([str(p[k]) for k in CLAIMS['main'] if p.get(k) not in (None, '')]
                    + [sid]
                    + [str(p[k]) for k in CLAIMS['rest'] if p.get(k) not in (None, '')])
            + hid + nv).encode('latin-1')

def split_blob(blob):
    pt = AES.new(AES_KEY, AES.MODE_CBC, blob[:16]).decrypt(blob[16:144])
    tag_ok = hmac.new(DK38, blob[16:144], hashlib.sha256).digest() == blob[144:]
    S = pt[20:24]
    head_ok = a9.head16_for(int.from_bytes(S, 'big'), (0x09,)) == pt[3:19]
    return pt, tag_ok, head_ok

def preimage(pt):
    return pt[25:45] + b'\x00\x08' + pt[3:19] + pt[20:24][::-1] + SHA0 + bytes((pt[112],))

def block_ok(pt, params, ak, sdk):
    return sha256_iv2(preimage(pt) + claims_bytes(params, ak, sdk)) == pt[46:78]

# ---------------------------------------------------------------- carvers
URLCH = set("=%&_.-+~:")
ASCII_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

def _urlchar(ch):
    # ASCII only: str.isalnum() is True for latin-1 letters (ae, ff, ...) which
    # are Charles payload bytes, not query characters.
    return ch in ASCII_OK or ch in URLCH

def carve_query(raw, pos):
    """Carve the query buffer containing `pos`.

    Charles stores the request body as one text chunk followed by binary
    framing (`...sq\\x00~\\x00<idx>`, `...t\\x00<len>`, `...q\\x00~`).  A naive
    "walk while the char is URL-safe" sweep swallows the trailing dictionary
    key letters into the last value (`att_status=0sq`, `...att_status=0q`,
    `...att_status=0t`), which silently breaks the claims.  So: walk on an
    ASCII-only class, and when the sweep stops on the `\\x00~` frame header,
    strip the key letters that immediately precede it.
    """
    st = pos
    while st > 0 and _urlchar(raw[st-1]):
        st -= 1
    en = pos
    while en < len(raw) and _urlchar(raw[en]):
        en += 1
    if en < len(raw) and raw[en] < ' ':            # end of frame -> drop the key
        j = en
        n = 0
        while n < 3 and j > 0 and 'a' <= raw[j-1] <= 'z':
            j -= 1
            n += 1
        if n:
            en = j
    return raw[st:en]


def sdk_of(path):
    """The client-sdk value this app signs with (carried verbatim in claims)."""
    if path.lower().endswith('.saz'):
        t = tempfile.mkdtemp()
        zipfile.ZipFile(path).extractall(t)
        d = os.path.join(t, 'raw')
        for f in sorted(os.listdir(d)):
            if f.endswith('_c.txt'):
                raw = open(os.path.join(d, f), 'rb').read().decode('latin-1')
                m = re.search(r'client-sdk: (\S+)', raw)
                if m:
                    return m.group(1)
        return None
    raw = open(path, 'rb').read().decode('latin-1')
    hits = [m.group(0) for m in
            re.finditer(r'[A-Za-z0-9.\-]{0,24}@ios[0-9.]+'
                        r'|[A-Za-z0-9.\-]{0,24}ios[0-9]\.[0-9.]+', raw)]
    return max(hits, key=len) if hits else None


def carve_saz(path):
    t = tempfile.mkdtemp()
    zipfile.ZipFile(path).extractall(t)
    d = os.path.join(t, 'raw')
    for f in sorted(os.listdir(d)):
        if not f.endswith('_c.txt'):
            continue
        raw = open(os.path.join(d, f), 'rb').read().decode('latin-1')
        mm = re.search(r'signature="([^"]+)"', raw)
        if not mm:
            continue
        line = raw.splitlines()[0]
        m = re.search(r'https?://[^/]+(/[^ ?]*)', line)
        kind = KIND.get(m.group(1).lstrip('/'), 'session') if m else 'session'
        if '?' in line:
            q = line.split('?', 1)[1].rsplit(' ', 1)[0]
        else:
            q = raw.split('\r\n\r\n', 1)[1].split('\r\n')[0]
        sdk = re.search(r'client-sdk: (\S+)', raw).group(1)
        yield f, dict(up.parse_qsl(q, keep_blank_values=True)), kind, base64.b64decode(mm.group(1)), sdk

def carve_chls(path):
    raw = open(path, 'rb').read().decode('latin-1')
    sdks = [m.group(0) for m in re.finditer(r'[A-Za-z0-9.\-]{0,24}@ios[0-9.]+|[A-Za-z0-9.\-]{0,24}ios[0-9]\.[0-9.]+', raw)]
    sdk = max(sdks, key=len) if sdks else None
    out = []
    for i, m in enumerate(re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', raw)):
        blob = base64.b64decode(m.group(1))
        if len(blob) != 176:
            continue
        bufs = []
        seen = set()
        for x in re.finditer(r'bundle_id=|app_token=|idfv=|idfa=', raw[:m.start()]):
            q = carve_query(raw, x.start())
            if 'app_token' in q and q.count('&') > 6 and q not in seen:
                seen.add(q)
                bufs.append((x.start(), q))
        kinds = [k for k in KIND if ('/' + k) in raw[max(0, m.start()-2500):m.start()]]
        kind = kinds[-1] if kinds else 'session'
        out.append((i+1, bufs[-6:], kind, blob, sdk))
    return out

def search_delta(pt, params, ak, sdk, target, limit=400):
    """Try to explain a failing block by a single edit of our claims."""
    base = claims_bytes(params, ak, sdk)
    pre = preimage(pt)
    ok = lambda b: sha256_iv2(pre + b) == pt[46:78]
    cand = {str(v) for v in params.values()}
    cand |= {ak, sdk, '1400000', '9', '3.67.0', '1', '0'}
    cand = {c for c in cand if c}
    for c in cand:
        cb = c.encode()
        for p in range(len(base) + 1):
            if ok(base[:p] + cb + base[p:]):
                return ('insert', c, p)
    for p in range(len(base)):
        for ln in (1, 2, 4, 8, 12, 16, 24, 32, 40, 48):
            if p + ln <= len(base) and ok(base[:p] + base[p+ln:]):
                return ('delete', base[p:p+ln].decode('latin-1'), p)
    for c in cand:
        cb = c.encode()
        for p in range(len(base) + 1):
            for ln in (1, 2, 4, 8, 12, 16, 24, 32, 40, 48):
                if p + ln <= len(base) and base[p:p+ln] != cb and ok(base[:p] + cb + base[p+ln:]):
                    return ('replace', c, p, base[p:p+ln].decode('latin-1'))
    return None

"""make_py27_adj9ios.py -- generate Python 2.7 copies of adj9ios_pure.py and
run_install.py (the adj8 transformer pattern, adapted).

Transforms: bytes.fromhex -> bytearray.fromhex; bytes(...) -> _b(...);
int.from_bytes -> struct.unpack; .hex() -> binascii.hexlify; bytearray(int)
-> zero string; perf_counter -> time.  The runner is generated from
run_install.py with curl_cffi replaced by the dual-mode httplib transport.
"""
import re

SRC = "adj9ios_pure.py"
DST = "adj9ios_pure_py27.py"

s = open(SRC, encoding="utf-8").read()

if not s.startswith("# -*- coding"):
    s = "# -*- coding: utf-8 -*-\n" + s

s = s.replace(
    '"""adj9ios_pure.py — the SELF-CONTAINED adj9-iOS pure signer',
    '"""adj9ios_pure_py27.py -- the adj9 iOS signature, Python 2.7.\n\n'
    'Generated from adj9ios_pure.py by make_py27_adj9ios.py.  Same algorithm,\n'
    'same bytes; only the syntax is 2.7.  Do not edit by hand -- re-run\n'
    'the generator and copy any change made to adj9ios_pure.py.\n\n'
    'adj9ios_pure.py — the SELF-CONTAINED adj9-iOS pure signer', 1)

# PRE-transform: the py3 _F mixes chained to_bytes/from_bytes — rewrite it in
# an already-2/3-neutral loop form BEFORE the generic passes touch it.
s = s.replace(
    '    return b"".join(_apply_tab(_F_TAB,\n'
    '                               int.from_bytes(chunk[4 * b:4 * b + 4],\n'
    '                                              "little")).to_bytes(4, "little")\n'
    '                    for b in range(4))',
    '    out_b = bytearray()\n'
    '    for b4 in range(4):\n'
    '        x = struct.unpack("<I", chunk[4 * b4:4 * b4 + 4])[0]\n'
    '        out_b += struct.pack("<I", _apply_tab(_F_TAB, x))\n'
    '    return _b(out_b)', 1)

# int.from_bytes(x, "big") -> struct.unpack  (4-byte cases)
s = s.replace('int.from_bytes(nonce4, "big")', 'struct.unpack(">I", nonce4)[0]')
s = re.sub(r"int\.from_bytes\(([^,]+), \"big\"\)",
           r'struct.unpack(">I", \1)[0]', s)
# multi-line variant (the _F mix): normalize first
s = s.replace('int.from_bytes(chunk[4 * b:4 * b + 4],\n'
              '                                              "little")',
              'struct.unpack("<I", chunk[4 * b:4 * b + 4])[0]')
# 2-byte little case (d4_words slice)
s = s.replace('int.from_bytes(d4_bytes[i:i + 2], "little")',
              'struct.unpack("<H", d4_bytes[i:i + 2])[0]')
# int.to_bytes -> struct.pack (all sizes/orders used in the file)
s = s.replace('x.to_bytes(2, "little")', 'struct.pack("<H", x)')
s = s.replace('word.to_bytes(4, "big")', 'struct.pack(">I", word)')
s = s.replace('v.to_bytes(2, "little")', 'struct.pack("<H", v)')
s = s.replace('_apply_tab(_F_TAB, struct.unpack("<I", chunk[4 * b:4 * b + 4])[0]).to_bytes(4, "little")',
              'struct.pack("<I", _apply_tab(_F_TAB, struct.unpack("<I", chunk[4 * b:4 * b + 4])[0]))')

# bytes.fromhex -> bytearray.fromhex
s = s.replace("bytes.fromhex(", "bytearray.fromhex(")

# bytes(x) -> _b(x)  (py2 bytes is str; str(bytearray(x)) is faithful)
s = s.replace("bytes(", "_b(")
# py2 str-iteration fix: _xor must operate on ints
s = s.replace(
    'return _b(x ^ y for x, y in zip(a, b))',
    'return _b(bytearray(x ^ y for x, y in zip(bytearray(a), bytearray(b))))')

# .hex() -> binascii.hexlify
s = re.sub(r"bytearray\(([^()]*)\)\.hex\(\)", r"binascii.hexlify(bytearray(\1))", s)
s = re.sub(r"(?<![\w.\)])(\w+\[[^\]]*\])\.hex\(\)", r"binascii.hexlify(\1)", s)
s = re.sub(r"(?<![\w.\)])(\w+)\.hex\(\)", r"binascii.hexlify(bytearray(\1))", s)
if "import binascii" not in s:
    s = s.replace("import base64",
                  "import base64" + chr(10) + "import binascii", 1)

# (no zero-fill string rule: _b returns a real bytearray, so bytearray(int)
#  zero-fills correctly on py2 and item assignment works)

HELPER = (
    '\n\ndef _b(x):\n'
    '    """bytes() shim: return a bytearray so iteration yields ints on py2."""\n'
    '    if isinstance(x, int):\n'
    '        return bytearray(x)\n'
    '    if isinstance(x, unicode):\n'
    '        return bytearray(x.encode("latin-1"))\n'
    '    return bytearray(x)\n'
    '\n\ndef _u2b(x):\n'
    '    """unicode -> py2 bytes (latin-1)."""\n'
    '    if isinstance(x, unicode):\n'
    '        return x.encode("latin-1")\n'
    '    return x\n'
)
_import_line = "import json, struct, hashlib, os, time, sys, base64"
if _import_line in s:
    s = s.replace(_import_line,
                  _import_line + HELPER, 1)
else:
    s = s.replace("\nimport base64", HELPER + "\nimport base64", 1)

open(DST, "w", encoding="utf-8").write(s)
print("wrote %s" % DST)

left = re.findall(r"\.to_bytes\(|\.from_bytes\(|bytes\.fromhex\(", s)
left += re.findall(r"(?<!bytearray\()bytes\(", s)
print("suspicious leftovers:", left or "none")

# POST-pass: make_adj_verification's XOR genexpr — py2 str iteration fix
s2 = open(DST, encoding="utf-8").read()
s2 = s2.replace(
    "return base64.b64encode(_b(b ^ key[i % len(key)]\n"
    "                                  for i, b in enumerate(plain))).decode()",
    "return base64.b64encode(_b(bytearray(b ^ bytearray(key)[i % len(key)]\n"
    "                                  for i, b in enumerate(bytearray(plain))))).decode()")
open(DST, "w", encoding="utf-8").write(s2)
print("post-pass applied (adj_verification xor)")


# ---- the runner ----
# py2 print has no flush kwarg: strip them and rely on -u or buffering
RGEN_FLUSH = True
SRC_R = "run_install.py"
DST_R = "run_install_py27.py"
r = open(SRC_R, encoding="utf-8").read()
if not r.startswith("# -*- coding"):
    r = "# -*- coding: utf-8 -*-\n" + r
r = r.replace('"""run_install.py — adj9-iOS fresh-install funnel',
              '"""run_install_py27.py -- adj9-iOS fresh-install funnel, Python 2.7\n'
              '(stdlib httplib transport; TLS impersonation is py3-only).\n\n'
              'run_install.py — adj9-iOS fresh-install funnel', 1)
r = r.replace("import adj9_claims_law as law\n", "")
r = r.replace("law.build_claims(", "sg.build_claims(")   # the py27 pure file has the law built in
r = r.replace("import adj9ios_pure as sg",
              "import adj9ios_pure_py27 as sg")
r = r.replace("from urllib.parse import urlencode",
              "try:\n    from urllib.parse import urlencode"
              "\nexcept ImportError:\n    from urllib import urlencode")
# curl_cffi session -> a tiny stdlib shim with the same .get/.post calls
r = r.replace(
    "from curl_cffi import requests as cr",
    "import httplib as httpclient\n"
    "import urllib2\n"
    "from urllib import urlencode as _urlencode\n\n"
    "class _Resp:\n"
    "    def __init__(self, status, body, url=''):\n"
    "        self.status_code = status\n"
    "        self.text = body\n"
    "        self.url = url\n"
    "    def json(self):\n"
    "        import json as _j\n"
    "        return _j.loads(self.text)\n\n"
    "class _Session:\n"
    "    def get(self, url, headers=None, timeout=30, allow_redirects=True):\n"
    "        c = httpclient.HTTPSConnection(url.split('/')[2], 443, timeout=timeout)\n"
    "        p = '/' + url.split('/', 3)[3] if url.count('/') >= 3 else '/'\n"
    "        c.request('GET', p, headers=headers or {})\n"
    "        resp = c.getresponse()\n"
    "        return _Resp(resp.status, resp.read(), url)\n"
    "    def post(self, url, data=None, headers=None, timeout=30):\n"
    "        c = httpclient.HTTPSConnection(url.split('/')[2], 443, timeout=timeout)\n"
    "        p = '/' + url.split('/', 3)[3] if url.count('/') >= 3 else '/'\n"
    "        if isinstance(data, dict):\n"
    "            data = _urlencode(data)\n"
    "        c.request('POST', p, body=data, headers=headers or {})\n"
    "        resp = c.getresponse()\n"
    "        return _Resp(resp.status, resp.read())\n\n"
    "def cr_Session(impersonate=None):\n"
    "    return _Session()\n\n"
    "S = cr_Session()")
r = r.replace("S = cr.Session(impersonate=\"safari17_0\")\n", "")
r = r.replace(", flush=True)", ")")
r = r.replace(" flush=True)", ")")
open(DST_R, "w", encoding="utf-8").write(r)
print("wrote %s" % DST_R)
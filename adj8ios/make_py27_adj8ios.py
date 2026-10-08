"""make_py27_adj8ios.py -- generate the Python 2.7 copies of adj8ios_pure.py
and run_install.py (the adj9ios transformer pattern, adapted).

Transforms: bytes.fromhex -> bytearray.fromhex; bytes(...) -> _b(...);
int.from_bytes -> struct.unpack; int.to_bytes -> struct.pack; .hex() ->
binascii.hexlify; print(flush=) -> plain print.  The runner gets the stdlib
httplib transport instead of curl_cffi (TLS impersonation is py3-only).
"""
import re

HERE = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
SRC, DST = "adj8ios_pure.py", "adj8ios_pure_py27.py"
SRC_R, DST_R = "run_install.py", "run_install_py27.py"

s = open(SRC, encoding="utf-8").read()
if not s.startswith("# -*- coding"):
    s = "# -*- coding: utf-8 -*-\n" + s

s = s.replace(
    '"""adj8ios_pure.py -- the Adjust adj8 signature on iOS',
    '"""adj8ios_pure_py27.py -- the adj8-iOS signature, Python 2.7.\n\n'
    'Generated from adj8ios_pure.py by make_py27_adj8ios.py.  Same algorithm,\n'
    'same bytes; only the syntax is 2.7.  Do not edit by hand -- change\n'
    'adj8ios_pure.py and re-run the generator.\n\n'
    'adj8ios_pure.py -- the Adjust adj8 signature on iOS', 1)

# --- integer/bytes conversions -------------------------------------------------
s = s.replace('int.from_bytes(raw[i:i + 4], "big")',
              'struct.unpack(">I", raw[i:i + 4])[0]')
s = s.replace('w.to_bytes(4, "big")', 'struct.pack(">I", w)')
s = s.replace('int.from_bytes(d4_bytes[i:i + 2], "little")',
              'struct.unpack("<H", d4_bytes[i:i + 2])[0]')
s = s.replace('int.from_bytes(packed[i:i + 4], "big")',
              'struct.unpack(">I", packed[i:i + 4])[0]')
s = s.replace('x.to_bytes(2, "little")', 'struct.pack("<H", x)')
s = s.replace('v.to_bytes(2, "little")', 'struct.pack("<H", v)')
s = s.replace('int.from_bytes(raw[i:i + 4], "big")',
              'struct.unpack(">I", raw[i:i + 4])[0]')
s = s.replace('pt[20:24].hex()', '_hex(pt[20:24])')
s = s.replace('bytes.fromhex(', 'bytearray.fromhex(')
s = s.replace('bytes(', '_b(')
s = s.replace('bytes([variant])', '_b(bytearray([variant]))')
s = s.replace('bytes((variant,))', '_b(bytearray((variant,)))')
s = s.replace('bytearray([variant])', '_b(bytearray([variant]))')
s = re.sub(r'(?<![\w.\)])(\w+\[[^\]]*\])\.hex\(\)', r'_hex(\1)', s)
s = re.sub(r'(?<![\w.\)])(\w+)\.hex\(\)', r'_hex(\1)', s)
s = s.replace('_hex(pt[20:24])', 'binascii.hexlify(pt[20:24]).decode("ascii")')

# py2 str-iteration fix: the XOR comprehension in encrypt()
s = s.replace(
    'c = _encrypt_chunk([a ^ b for a, b in\n'
    '                            zip(bytearray(record[k:k + 16]), bytearray(wa))])',
    'c = _encrypt_chunk([a ^ b for a, b in\n'
    '                            zip(bytearray(record[k:k + 16]),\n'
    '                                bytearray(wa))])')

HELPER = (
    '\n\ndef _b(x):\n'
    '    """bytes() shim: return a bytearray so iteration yields ints on py2."""\n'
    '    if isinstance(x, int):\n'
    '        return bytearray(x)\n'
    '    if isinstance(x, unicode):\n'
    '        return bytearray(x.encode("latin-1"))\n'
    '    return bytearray(x)\n'
    '\n\ndef _hex(x):\n'
    '    """bytes.hex() shim."""\n'
    '    return binascii.hexlify(bytearray(x)).decode("ascii")\n'
)
s = s.replace("import base64, hashlib, hmac, json, os, struct, sys, time",
              "import base64" + chr(10) + "import binascii" + chr(10)
              + "import hashlib, hmac, json, os, struct, sys, time" + HELPER, 1)
open(DST, "w", encoding="utf-8").write(s)
print("wrote %s" % DST)
left = (re.findall(r"\.to_bytes\(|\.from_bytes\(|bytes\.fromhex\(", s)
        + re.findall(r"(?<!bytearray\()(?<!_b\()bytes\(", s))
print("suspicious leftovers:", left or "none")

# ---- the runner ---------------------------------------------------------------
r = open(SRC_R, encoding="utf-8").read()
if not r.startswith("# -*- coding"):
    r = "# -*- coding: utf-8 -*-\n" + r
r = r.replace('"""run_install.py — adj8-iOS install funnel',
              '"""run_install_py27.py -- adj8-iOS install funnel, Python 2.7\n'
              '(stdlib httplib transport; TLS impersonation is py3-only).\n\n'
              'run_install.py — adj8-iOS install funnel', 1)
r = r.replace("import adj8ios_pure as sg", "import adj8ios_pure_py27 as sg")
# py2.7 has no datetime.timezone
r = r.replace("from datetime import datetime, timedelta, timezone",
              "from datetime import datetime, timedelta")
r = r.replace("return datetime.now(timezone.utc).replace(tzinfo=None)",
              "return datetime.utcnow()")
# urllib.parse is py3-only; resolve_click() uses parse_qsl / urlparse
r = r.replace("import time, base64, sys, os, json, uuid, argparse, urllib.parse",
              "import time, base64, sys, os, json, uuid, argparse")
r = r.replace("urllib.parse.parse_qsl(", "_parse_qsl(")
r = r.replace("urllib.parse.urlparse(", "_urlparse(")
r = r.replace("urllib.parse.urlencode(", "urlencode(")
r = r.replace("urllib.parse.quote(", "_quote(")
r = r.replace("from urllib.parse import urlencode",
              "try:\n    from urllib.parse import urlencode, quote as _quote\n"
              "except ImportError:\n"
              "    from urllib import urlencode, quote as _quote\n"
              "try:\n"
              "    from urllib.parse import parse_qsl as _parse_qsl, urlparse as _urlparse\n"
              "except ImportError:\n"
              "    from urlparse import urlparse as _urlparse, parse_qsl as _parse_qsl")
r = r.replace(", flush=True)", ")")
r = r.replace(" flush=True)", ")")
r = re.sub(r",\s*\)", ")", r)                       # the trailing comma print(...,)
r = re.sub(r"(?m)^(\s*)print\(", r"\1say(", r)      # py2 print has no flush / u'' noise
r = r.replace("HERE = os.path.dirname(os.path.abspath(__file__))",
              "HERE = os.path.dirname(os.path.abspath(__file__))\n\n\n"
              "def say(*a):\n"
              "    import sys\n"
              "    sys.stdout.write(\" \".join(str(x) for x in a) + \"\\n\")\n"
              "    sys.stdout.flush()")
open(DST_R, "w", encoding="utf-8").write(r)
print("wrote %s" % DST_R)

TRANSPORT = '''"""_py27_transport.py -- the stdlib stand-in for curl_cffi on Python 2.7.

Scheme-aware (http/https), exposes .status_code / .text / .json() / .headers /
.url like curl_cffi's Response, which is what run_install_py27.py uses.
TLS impersonation is NOT available here -- that part is py3/curl_cffi only.
"""
import httplib as httpclient
from urlparse import urlparse
from urllib import urlencode as _urlencode


class _Resp(object):
    def __init__(self, status, body, url='', headers=None):
        self.status_code = status
        self.text = body
        self.url = url
        self.headers = headers or {}

    def json(self):
        import json as _j
        return _j.loads(self.text)


class _Session(object):
    def _open(self, url, method, body=None, headers=None, timeout=30):
        u = urlparse(url)
        host = u.netloc.split('@')[-1].split(':')[0]
        path = u.path or '/'
        if u.query:
            path += '?' + u.query
        h = dict(headers or {})
        if u.scheme == 'http':
            c = httpclient.HTTPConnection(host, u.port or 80, timeout=timeout)
        else:
            c = httpclient.HTTPSConnection(host, u.port or 443, timeout=timeout)
        c.request(method, path, body=body, headers=h)
        resp = c.getresponse()
        raw = resp.read()
        hdrs = {}
        for k, v in resp.getheaders():
            hdrs[k] = v
            hdrs[k.lower()] = v
        return _Resp(resp.status, raw, url, hdrs)

    def get(self, url, headers=None, timeout=30, allow_redirects=True, **kw):
        r = self._open(url, 'GET', None, headers, timeout)
        if allow_redirects:
            seen = 0
            while r.status_code in (301, 302, 303, 307, 308) and seen < 5:
                loc = r.headers.get('location') or r.headers.get('Location')
                if not loc:
                    break
                if loc.startswith('/'):
                    p = urlparse(url)
                    loc = '%s://%s%s' % (p.scheme, p.netloc, loc)
                r = self._open(loc, 'GET', None, headers, timeout)
                seen += 1
        return r

    def post(self, url, data=None, headers=None, timeout=30, **kw):
        if isinstance(data, dict):
            data = _urlencode(data)
        return self._open(url, 'POST', data, headers, timeout)


class _CR(object):
    Session = staticmethod(lambda impersonate=None: _Session())
    get = staticmethod(lambda url, **kw: _Session().get(url, **kw))
    post = staticmethod(lambda url, **kw: _Session().post(url, **kw))


cr = _CR()
'''
open("_py27_transport.py", "w", encoding="utf-8").write(TRANSPORT)
print("wrote _py27_transport.py")

# ---- self-check: the generated files must be clean 2.7 ----------------------
# Every hand-edit to the py3 sources has taught this generator a new construct
# (urlencode, parse_qsl, quote...).  Fail loudly instead of shipping a runner
# that dies on the backend with NameError / IndentationError.
import subprocess, sys as _sys

PY3_ONLY = [
    (r"\bdatetime\.timezone\b", "datetime.timezone (py3.2+, not 2.7)"),
    (r"\bint\.from_bytes\b", "int.from_bytes"),
    (r"\.to_bytes\(", ".to_bytes()"),
    (r"(?<![\"'])\bflush=True\b", "print(..., flush=True)"),
    (r":=", "walrus operator"),
    (r"\byield from\b", "yield from"),
    (r"\bnonlocal\b", "nonlocal"),
    (r"(?<![A-Za-z0-9_])f[\"']", "f-string"),
]

def check(path):
    """Flag py3-only constructs.  urllib.parse.* is allowed ONLY inside the
    generator's own `try:` / `from urllib.parse import ...` compat blocks."""
    bad = []
    src = open(path, encoding="utf-8").read().splitlines()
    for n, line in enumerate(src, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat, why in PY3_ONLY:
            if re.search(pat, line):
                bad.append("  %s:%d  %s  ->  %s" % (path, n, why, stripped[:70]))
        if "urllib.parse." in line and "import urllib.parse" not in line:
            bad.append("  %s:%d  urllib.parse.* outside a compat import  ->  %s"
                       % (path, n, stripped[:70]))
    return bad

problems = []
for f in (DST, DST_R, "_py27_transport.py"):
    problems += check(f)

# and it must actually byte-compile under the real 2.7
for f in (DST, DST_R, "_py27_transport.py"):
    try:
        r = subprocess.run(["py", "-2.7", "-m", "py_compile", f],
                           capture_output=True, text=True)
        if r.returncode != 0:
            problems.append("  %s fails to compile under py -2.7:\n%s"
                            % (f, (r.stderr or "").strip()[-600:]))
    except Exception as e:                       # no 2.7 on this box
        print("note: could not run py -2.7 (%s)" % e)

if problems:
    print("\nPY27 SELF-CHECK FAILED:")
    print("\n".join(problems))
    _sys.exit(1)
print("py27 self-check: clean (no py3-only constructs, compiles under py -2.7)")

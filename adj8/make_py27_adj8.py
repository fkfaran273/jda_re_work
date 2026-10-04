"""make_py27_adj8.py -- generate a Python 2.7-compatible copy of adj8_pure.py.

The source happens to be nearly 2/3-neutral; four transforms remain:

  * v.to_bytes(4, "big") does not exist on 2.7           -> struct.pack(">I", v)
  * bytes.fromhex does not exist on 2.7 (bytes is str)   -> bytearray.fromhex
  * bytes(<iterable of ints>) would repr() on 2.7        -> bytearray(...)
  * bytes(2000) zero-fill would repr() on 2.7            -> bytearray(2000)
  * .hex() on a str is missing on 2.7                    -> bytearray(x).hex()

verify: python2.7 adj8_pure_py27.py --selftest  (mints under real 2.7 and
checks the golden laws), plus a py2-vs-py3 same-input blob comparison.
"""
import re

SRC = "adj8_pure.py"
DST = "adj8_pure_py27.py"

s = open(SRC, encoding="utf-8").read()

# 0. py2.7 needs a coding declaration for the non-ASCII docstring/em dashes
if not s.startswith("# -*- coding"):
    s = "# -*- coding: utf-8 -*-\n" + s

# 1. port note INSIDE the existing docstring (one opener, never two)
s = s.replace(
    '"""adj8_pure.py — the adj8 signature',
    '"""adj8_pure_py27.py -- the Adjust adj8 signature, Python 2.7.\n\n'
    'Generated from adj8_pure.py by make_py27_adj8.py.  Same algorithm,\n'
    'same bytes; only the syntax is 2.7.  Do not edit by hand -- re-run\n'
    'the generator and copy any change made to adj8_pure.py.\n\n'
    'adj8_pure.py -- the adj8 signature', 1)

# 2. int.to_bytes -> struct
s = s.replace('b"".join(v.to_bytes(4, "big") for v in w)',
              'b"".join(struct.pack(">I", v) for v in w)')

# 3. bytes.fromhex -> bytearray.fromhex
s = s.replace("bytes.fromhex(", "bytearray.fromhex(")

# 4. bytes(x): on py2 bytes is str, so str(x) is the faithful conversion;
#    bytearray would be unhashable (it is used as a dict key in the JNI
#    read_cstr path) and py2's unicorn rejects it.  Route through _b().
s = s.replace("bytes(", "_b(")

# 5. .hex() does not exist on 2.7 str/bytearray -> binascii.hexlify
s = re.sub(r"bytearray\(([^()]*)\)\.hex\(\)", r"binascii.hexlify(bytearray(\1))", s)
s = re.sub(r"(?<![\w.\)])(\w+\[[^\]]*\])\.hex\(\)", r"binascii.hexlify(\1)", s)
s = re.sub(r"(?<![\w.\)])(\w+)\.hex\(\)", r"binascii.hexlify(bytearray(\1))", s)
if "import binascii" not in s:
    s = s.replace("import base64",
                  "import base64" + chr(10) + "import binascii", 1)

# 6b. bytearray(<int>) is a zero-fill on py3 but str(int) on py2 -- and py2.7's
#      unicorn wants str.  Emit an explicit zero string instead.
s = re.sub(r"bytearray\((\d+)\)", r'b"\\x00" * \1', s)

# 4b. zero-fill: bytes(N) / _b(N) is N zero bytes on py3 but str(N) on py2
s = re.sub(r"\b_b\((\d+)\)", r'b"\\x00" * \1', s)

# 6c. py2.7's unicorn mem_write wants str (py3 wants bytes) -- route every
#      write through a tiny helper.  Match self.uc.mem_write first, then the
#      bare uc.mem_write (lookbehind keeps the first pass from re-matching).
s = s.replace("self.uc.mem_write(", "_w(self.uc, ")
s = re.sub(r"(?<![.\w])uc\.mem_write\(", "_w(uc, ", s)
HELPER = (
    '\n\ndef _b(x):\n'
    '    """bytes() shim: on py2 bytes IS str, so str() is faithful."""\n'
    '    return str(bytearray(x))\n'
    '\n\ndef _w(uc, addr, data):\n'
    '    """mem_write shim: py2.7 unicorn wants str, py3 wants bytes."""\n'
    '    if not isinstance(data, str):\n'
    '        data = str(bytearray(data))\n'
    '    uc.mem_write(addr, data)\n'
)
anchor = "SO_BYTES = "
if anchor in s:
    s = s.replace(anchor, HELPER.strip() + "\n\n\n" + anchor, 1)
else:
    s = s.replace("\nimport base64", HELPER + "\nimport base64", 1)

# 6. time.perf_counter is 3.3+; 2.7 has time.time()
s = s.replace("time.perf_counter()", "time.time()")

open(DST, "w", encoding="utf-8").write(s)
print("wrote %s" % DST)

# report leftovers that would break 2.7
left = re.findall(r"\.to_bytes\(|\.from_bytes\(|bytes\.fromhex\(", s)
left += re.findall(r"(?<!bytearray\()bytes\(", s)
print("suspicious leftovers:", left or "none")

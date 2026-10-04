"""make_py27.py -- generate a Python 2.7-compatible copy of adj9_pure.py.

The source is written 2/3-neutral (no annotations, no f-strings, struct for
every int<->bytes conversion), so four mechanical transforms remain:

  * bytes.fromhex does not exist on 2.7 (bytes is str)   -> bytearray.fromhex
  * bytes(genexpr) would repr() on 2.7                   -> bytearray(genexpr)
  * _mix_chunk's b"".join returns str on 2.7, and the round loop must
    iterate integers                                      -> re-materialise
  * zip(chunk, wa) must pair INTEGERS on 2.7, where iterating a str yields
    1-character strings                                   -> bytearray both

verify_py27.py signs under real 2.7 and 3.x and compares the hex.
"""
import re

SRC = 'adj9_pure.py'
DST = 'adj9_pure_py27.py'

s = open(SRC, encoding='utf-8').read()

# 1. port note in the docstring
s = s.replace('"""adj9_pure.py -- the Adjust adj9 signature in pure Python.  No VM.',
              '"""adj9_pure_py27.py -- the Adjust adj9 signature, Python 2.7.\n\n'
              'Generated from adj9_pure.py by make_py27.py.  Same algorithm, same\n'
              'bytes; only the syntax is 2.7.  Do not edit by hand -- re-run the\n'
              'generator and copy any change made to adj9_pure.py.\n\n'
              'The Adjust adj9 signature in pure Python.  No VM.')

# 2. 2.7's bytes is str and has no fromhex
s = s.replace('bytes.fromhex(', 'bytearray.fromhex(')

# 3. bytes(<iterable of ints>) -> bytearray(<...>): on 2.7, str(generator)
#    would give the repr.  bytearray accepts int iterables on both.
s = s.replace('bytes(', 'bytearray(')

# 4. the round loop iterates its state as ints; the join returns str on 2.7
s = s.replace('x = _mix_chunk(x)', 'x = bytearray(_mix_chunk(x))')

# 5. the CBC seed XOR must see ints on both sides
s = s.replace('x = bytearray(a ^ b for a, b in zip(chunk, wa))',
              'x = bytearray(a ^ b for a, b in zip(bytearray(chunk),\n'
              '                                     bytearray(wa)))')

# any annotation we missed
left = re.findall(r'def \w+\([^)]*:\s*\w', s)
left += re.findall(r'def [^(]*\([^)]*:\s*\w[^)]*\)\s*->', s)
print('annotations left:', left or 'none')

open(DST, 'w', encoding='utf-8').write(s)
print('wrote %s' % DST)

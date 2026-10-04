"""make_run27.py -- generate a Python 2.7-compatible copy of run_install.py.

run_install.py itself stays py3.  The copy differs only in stdlib names and
the one 3.x-only call; the requests it builds are byte-identical.  Every
transform asserts it fired, so a change to run_install.py that invalidates
one fails loudly here instead of drifting silently.

    python make_run27.py                            # regenerate
    py -2.7 run_install_py27.py --dry-run           # sign only
    py -2.7 run_install_py27.py --gap 0             # live, under real 2.7

The signer under the copy is always adj9_pure_py27 (the py3 module cannot
even import on 2.7: bytes.fromhex).
"""
import sys

SRC = 'run_install.py'
DST = 'run_install_py27.py'

s = open(SRC, encoding='utf-8').read()
s = s.replace(u'\u2014', '--')       # ASCII source: no coding declaration


def sub(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        sys.exit('make_run27: expected %r x%d, found %d' % (old[:70], count, n))
    s = s.replace(old, new)


# docstring: note the port
sub('"""run_install.py -- register a click, report an install, read the attribution.',
    '"""run_install_py27.py -- the Python 2.7 build of run_install.py, generated\n'
    'by make_run27.py (do not edit by hand; re-run the generator).  Same wire\n'
    'bytes; only the stdlib names differ.  Original header:')

# the signer is always the 2.7 build (the py3 module cannot import on 2.7);
# tolerate the source import being commented out
if '# import adj9_pure as S' in s:
    sub('# import adj9_pure as S', 'import adj9_pure_py27 as S')
else:
    sub('import adj9_pure as S', 'import adj9_pure_py27 as S')

# stdlib renames (only open_click_link still uses the raw http stack)
sub('import http.client', 'import httplib')
sub('http.client.HTTPSConnection', 'httplib.HTTPSConnection', 2)
sub('http.client.HTTPConnection', 'httplib.HTTPConnection')
sub('import urllib.parse', 'import urllib\nimport urlparse')
sub('urllib.parse.', 'urlparse.', 6)    # urlsplit, urlunsplit,
                                        # unquote, urljoin + proxy branch

# 3.2+: datetime.timezone
sub('datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)',
    'datetime.datetime.utcfromtimestamp(ts)')

# py3's bare print() prints an empty line; py2 would print the empty tuple
sub('\n    print()\n', "\n    print ''\n")

open(DST, 'w', encoding='utf-8').write(s)
print('wrote %s (%d lines)' % (DST, s.count('\n') + 1))

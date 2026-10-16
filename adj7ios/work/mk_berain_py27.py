# -*- coding: utf-8 -*-
"""mk_berain_py27.py -- generate run_berain_py27.py from run_berain.py."""
import io

HEADER = '''# -*- coding: utf-8 -*-
"""run_berain_py27.py -- the adj7-iOS fresh install funnel for
com.berain.berain (Berain Water), PYTHON 2.7.

The click link is HARDCODED below (the tracker-20yvzdd5 direct Adjust link
that booked non-organic TMV Media / 20fholu3 on 2026-10-09).

    python2.7 run_berain_py27.py --dry-run
    python2.7 run_berain_py27.py
"""
from __future__ import print_function

'''

src = io.open('run_berain.py', encoding='utf-8').read()
# strip the original header/docstring up to the first import
idx = src.index('import gzip')
body = src[idx:]
out = (body
       .replace('from datetime import datetime, timezone',
                'from datetime import datetime')
       .replace('import urllib.parse\nimport uuid\n',
                'import urllib\nimport urllib2\nimport uuid\n')
       .replace('urllib.parse.urlencode', 'urllib.urlencode')
       .replace('urllib.parse.unquote(', 'urllib.unquote(')
       .replace('dt = datetime.fromtimestamp(ts + off, timezone.utc)',
                'dt = datetime.utcfromtimestamp(ts + off)'))
io.open('run_berain_py27.py', 'w', encoding='utf-8').write(HEADER + out)
print('written run_berain_py27.py,', (HEADER + out).count('\n'), 'lines')

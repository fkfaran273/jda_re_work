# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
s = s.replace('import hashlib\nimport hmac\nimport json\nimport os\n'
              'import struct\nimport time\n',
              'import binascii\nimport hashlib\nimport hmac\nimport json\n'
              'import os\nimport re\nimport struct\nimport time\n')
io.open(p, 'w', encoding='utf-8').write(s)
print('binascii imported:', 'import binascii' in s,
      '| re imported:', 'import re' in s)

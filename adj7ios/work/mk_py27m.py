# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = '    vectors = json.load(open(path, encoding="utf-8"))\n'
new = ('    try:\n'
       '        vectors = json.load(open(path, encoding="utf-8"))\n'
       '    except TypeError:          # py2: open() has no encoding kwarg\n'
       '        vectors = json.load(open(path))\n')
assert old in s
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched json.load')

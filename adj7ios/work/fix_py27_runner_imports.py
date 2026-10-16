# -*- coding: utf-8 -*-
"""fix_py27_runner_imports.py -- py2: urllib2 provides Request/build_opener/
HTTPError/HTTPRedirectHandler; urllib provides urlencode/unquote."""
import io
p = 'run_install_ios_py27.py'
s = io.open(p, encoding='utf-8').read()
# imports
s = s.replace('import urllib\nimport uuid\n',
              'import urllib\nimport urllib2\nimport uuid\n')
# class + fallback client
s = s.replace('class NoRedirect(urllib.HTTPRedirectHandler):',
              'class NoRedirect(urllib2.HTTPRedirectHandler):')
s = s.replace('        req = urllib.Request(url, headers={',
              '        req = urllib2.Request(url, headers={')
s = s.replace('        opener = urllib.build_opener(NoRedirect)',
              '        opener = urllib2.build_opener(NoRedirect)')
s = s.replace('        except urllib.HTTPError as e:',
              '        except urllib2.HTTPError as e:')
io.open(p, 'w', encoding='utf-8').write(s)
print('imports patched')

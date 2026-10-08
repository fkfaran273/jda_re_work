"""_py27_transport.py -- the stdlib stand-in for curl_cffi on Python 2.7.

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

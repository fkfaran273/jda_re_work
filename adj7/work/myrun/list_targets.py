try:
    from curl_cffi.const import CurlImpersonate
    print([x for x in dir(CurlImpersonate) if not x.startswith('_')])
except Exception as e:
    print('ERR', e)
try:
    import curl_cffi.requests as R
    import inspect
    src = inspect.getsource(R)
    import re
    m = re.findall(r'"(chrome131_android|chrome[^"]*android[^"]*|[^"]*android[^"]*)"', src)
    print('android targets:', sorted(set(m))[:10])
except Exception as e:
    print('ERR2', e)

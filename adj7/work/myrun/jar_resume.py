import os, time, sys
DST = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conscrypt-uber.jar')
URL = 'https://repo1.maven.org/maven2/org/conscrypt/conscrypt-openjdk-uber/2.5.2/conscrypt-openjdk-uber-2.5.2.jar'
have = os.path.getsize(DST) if os.path.exists(DST) else 0
print('resume from', have, flush=True)
import urllib.request
while True:
    try:
        req = urllib.request.Request(URL, headers={'Range': 'bytes=%d-' % have})
        with urllib.request.urlopen(req, timeout=30) as r, open(DST, 'ab') as f:
            while True:
                ch = r.read(65536)
                if not ch: break
                f.write(ch); have += len(ch)
        print('done, size', have, flush=True)
        break
    except Exception as e:
        print('retry:', type(e).__name__, str(e)[:100], 'have', have, flush=True)
        time.sleep(10)

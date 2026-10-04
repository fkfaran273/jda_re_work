# parse_queue.py - extract signed packages from AdjustIoPackageQueue
import base64, re, json

b = open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/queue_b64.txt', 'rb').read()
if b[:2] in (b'\xff\xfe', b'\xfe\xff'):
    txt = b.decode('utf-16')
else:
    txt = b.decode('utf-8', 'ignore')
raw = base64.b64decode(''.join(txt.split()))
print('queue bytes:', len(raw))
open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/queue_raw.bin', 'wb').write(raw)
s = raw.decode('latin1')

sigs = re.findall(r'Signature signature="([A-Za-z0-9+/=]{300,400})"', s)
print('signatures found:', len(sigs))
kinds = re.findall(r'activity_kind=([a-z_]+)', s)
print('kinds:', kinds)
gps = set(re.findall(r'gps_adid=([0-9a-f-]{36})', s))
print('gps in pkgs:', gps)

blocks = re.findall(r'[ -~]{300,}', s)
pkgs = [b for b in blocks if ('activity_kind=' in b) or ('created_at=' in b)]
print('param blocks:', len(pkgs))
for i, b in enumerate(pkgs):
    k = re.search(r'activity_kind=([a-z_]+)', b)
    print('--- block %d len=%d kind=%s head=%s' % (i, len(b), k.group(1) if k else '?', b[:110]))

# pair each signature with the nearest long printable param block
out = []
for sig in sigs:
    j = s.find(sig)
    lo = max(0, j - 6000)
    hi = min(len(s), j + 6000)
    win = s[lo:hi]
    mb = re.findall(r'[ -~]{300,}', win)
    best = max(mb, key=len) if mb else ''
    out.append({'sig': sig, 'params': best})
for i, o in enumerate(out):
    k = re.search(r'activity_kind=([a-z_]+)', o['params'])
    print('pkg %d: sig_len=%d params_len=%d kind=%s' % (i, len(o['sig']), len(o['params']), k.group(1) if k else '?'))
json.dump(out, open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/queue_pkgs.json', 'w'), indent=1)
print('saved queue_pkgs.json')

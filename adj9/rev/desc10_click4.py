# desc10_click4.py - min-token DP segmentation of the 387B click desc10 against the
# value dictionary built from ALL sign_input maps (wh4_records.json + golden), to read
# off the literal token sequence and its candidate keys.
import json, re

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
R = json.load(open(REV + r'\desc10_runs.json', encoding='utf-8'))
click = R['click']

W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))

def fields_of(si):
    out = []
    for part in si['order'].split('\x02'):
        if '\x01' in part:
            k, v = part.split('\x01', 1)
            out.append((k, v))
    return out

V = {}
for si in W['sign_inputs']:
    for k, v in fields_of(si):
        if v:
            V.setdefault(v, set()).add(k)
# add values seen in desc10 runs that may not be in any map (timestamps, referrer)
for extra, k in [('utm_source=google-play&utm_medium=organic', 'referrer'),
                 ('google', 'referrer_api'),
                 ('install_referrer', 'source')]:
    V.setdefault(extra, set()).add(k)
for m in re.finditer(r'\d{4}-\d\d-\d\dT[\d:.]+Z[+-]\d{4}', click):
    V.setdefault(m.group(0), set()).add('created_at/updated_at')

vals = sorted(V, key=len, reverse=True)
print('dictionary: %d values' % len(vals))

n = len(click)
INF = 10 ** 9
dp = [INF] * (n + 1)
back = [None] * (n + 1)
dp[0] = 0
for i in range(n):
    if dp[i] >= INF:
        continue
    for v in vals:
        if click.startswith(v, i):
            j = i + len(v)
            if dp[i] + 1 < dp[j]:
                dp[j] = dp[i] + 1
                back[j] = (i, v)
print('min tokens to cover %d bytes: %s' % (n, dp[n] if dp[n] < INF else 'UNREACHABLE'))
if dp[n] < INF:
    seq = []
    j = n
    while j > 0:
        i, v = back[j]
        seq.append(v)
        j = i
    seq.reverse()
    off = 0
    print('=== CLICK token sequence (%d) ===' % len(seq))
    for v in seq:
        keys = sorted(V[v])
        print('  %4d %3d %-45r %s' % (off, len(v), v, keys))
        off += len(v)

# same for session (sanity)
sess = R['session']
dp2 = [INF] * (len(sess) + 1); back2 = [None] * (len(sess) + 1); dp2[0] = 0
for i in range(len(sess)):
    if dp2[i] >= INF:
        continue
    for v in vals:
        if sess.startswith(v, i):
            j = i + len(v)
            if dp2[i] + 1 < dp2[j]:
                dp2[j] = dp2[i] + 1; back2[j] = (i, v)
print()
print('SESSION min tokens:', dp2[len(sess)])
seq2 = []
j = len(sess)
while j > 0:
    i, v = back2[j]; seq2.append(v); j = i
seq2.reverse()
off = 0
for v in seq2:
    print('  %4d %3d %-45r %s' % (off, len(v), v, sorted(V[v])))
    off += len(v)

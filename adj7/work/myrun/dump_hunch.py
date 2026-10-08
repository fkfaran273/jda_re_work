import urllib.parse, os
HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, 'saz_hunch_new', 'raw')
def req(n):
    t = open(os.path.join(RAW, '%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    line0 = t.split('\r\n', 1)[0]
    head, _, body = t.partition('\r\n\r\n')
    return line0, head, body.strip()
def resp(n):
    t = open(os.path.join(RAW, '%02d_s.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    return head, body.strip()
for n in (29, 30, 32):
    line0, head, body = req(n)
    print('##### req', n, line0[:150])
    if n in (29, 30):
        f = urllib.parse.parse_qsl(body, keep_blank_values=True)
        print(' fields:', len(f))
        print(' order:', [k for k, _ in f])
    else:
        print(' query:', line0.split(' ', 2)[1][:400])
    for line in head.split('\r\n'):
        if line.startswith(('Client-SDK', 'User-Agent', 'Content-Length')):
            print('  ', line[:120])
    h, b = resp(n)
    print(' resp:', h.split('\r\n')[0], '|', b[:500])
    print()

import urllib.parse, re, os
HERE = os.path.dirname(os.path.abspath(__file__))
def load_c(folder, n):
    p = os.path.join(HERE, folder, '%02d_c.txt' % n)
    t = open(p, encoding='utf-8', errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    return head, body.strip()
for label, folder, n in [('LIVE sdk_click','saz_live/raw',8),('MANUAL sdk_click','saz_new/raw',66),('LIVE session','saz_live/raw',6),('MANUAL session','saz_new/raw',65)]:
    head, body = load_c(folder, n)
    print('====', label)
    for line in head.split('\r\n')[:12]:
        if 'Authorization' in line:
            print('AUTH total len', len(line))
            print('  head60:', line[:60])
            print('  tail:', line[-115:])
            m = re.search(r'signature="([0-9A-F]+)"', line)
            if m:
                print('  blob hex len', len(m.group(1)), 'first24', m.group(1)[:24])
        elif line.startswith(('POST','GET','Client-SDK','User-Agent','Host','Content-Type','Content-Length','Connection')):
            print(' ', line[:130])
    print('  body bytes', len(body.encode()), 'fields', len(urllib.parse.parse_qsl(body, keep_blank_values=True)))

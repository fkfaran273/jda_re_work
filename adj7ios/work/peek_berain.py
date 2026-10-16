import os, re
raw = 'saz_berain/raw'
for n in (17, 44, 45, 46, 75):
    t = open('%s/%03d_c.txt' % (raw, n), encoding='utf-8',
             errors='replace', newline='').read()
    head = t.split('\r\n\r\n', 1)[0]
    auth = [l for l in head.split('\r\n') if 'Authorization' in l]
    cs = [l for l in head.split('\r\n') if l.lower().startswith('client-sdk')]
    ua = [l for l in head.split('\r\n') if l.startswith('User-Agent')]
    m = re.search(r'signature="([0-9A-Fa-f]+)"', auth[0]) if auth else None
    print('row %d | %s' % (n, cs[0] if cs else 'no Client-Sdk'))
    print('   UA:', ua[0][:80] if ua else '')
    print('   attrs:', auth[0][-95:] if auth else 'NONE',
          '| blob len', len(m.group(1)) if m else 0)
    body = t.split('\r\n\r\n', 1)[1].strip() if '\r\n\r\n' in t else ''
    print('   body bytes:', len(body))

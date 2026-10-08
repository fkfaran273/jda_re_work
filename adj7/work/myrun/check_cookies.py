import os
HERE = os.path.dirname(os.path.abspath(__file__))
for folder, rows in (('saz_hunch_new/raw', (29, 30, 32)), ('saz_new/raw', (65, 66, 67))):
    print('#####', folder)
    for n in rows:
        t = open(os.path.join(HERE, folder, '%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
        head = t.split('\r\n\r\n', 1)[0]
        ck = [l for l in head.split('\r\n') if l.lower().startswith('cookie')]
        print(' row %02d Cookie: %s' % (n, ck if ck else None))
    # click-hop set-cookie from our chrome log
print('##### our chrome click set-cookie:')
t = open(os.path.join(HERE, 'click_chain_hunch_chrome.log'), encoding='utf-8', errors='replace').read()
for line in t.split('\n'):
    if 'setcookie=' in line and len(line.split('setcookie=')[1]) > 3:
        print(' ', line[:400])
        break
else:
    print('  (no Set-Cookie logged on any hop)')

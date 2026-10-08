import os
HERE = os.path.dirname(os.path.abspath(__file__))
def hello(folder):
    import glob
    out = {}
    for p in sorted(glob.glob(os.path.join(HERE, folder, '*_c.txt'))):
        t = open(p, encoding='utf-8', errors='replace', newline='').read()
        if 'ClientHello' in t:
            # Fiddler annotation block after headers
            i = t.find('ClientHello')
            out[os.path.basename(p)] = t[i-200:i+1200]
    return out
for folder in ('saz_live/raw', 'saz_new/raw'):
    print('#####', folder)
    h = hello(folder)
    print('rows with hello:', sorted(h.keys())[:6])
    for k in sorted(h.keys())[:2]:
        print('---', k)
        print(h[k][:1100])

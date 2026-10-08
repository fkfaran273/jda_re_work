import os
HERE = os.path.dirname(os.path.abspath(__file__))
def full(folder, n):
    t = open(os.path.join(HERE, folder, '%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    i = t.find('Version: ')
    return t[i:i+2500] if i >= 0 else 'NO-HELLO'
for folder, n in [('saz_live/raw',2),('saz_live/raw',5),('saz_new/raw',59),('saz_new/raw',62)]:
    print('##### %s/%02d' % (folder, n))
    print(full(folder, n))
    print()

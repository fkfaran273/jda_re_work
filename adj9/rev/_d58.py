"""_d58.py — is desc10_58 the proven 5.7.0 law, or EXTENDED with extra keys?"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'creditsea'))
import mint_pipeline as M
import desc10_58 as D58
print('desc10_58 exports:', [n for n in dir(D58) if not n.startswith('_')][:20])
print()
fn = None
for name in ('desc10_keys_58', 'desc10_keys', 'KEYS_58'):
    if hasattr(D58, name):
        fn = getattr(D58, name); print('using', name); break
for kind in ('session', 'click', 'attribution'):
    k57 = M.desc10_keys(kind, {})
    k58 = None
    if fn is not None:
        try:
            k58 = fn(kind, {})
        except TypeError:
            try: k58 = fn(kind)
            except Exception: k58 = None
    print('=== %s ===' % kind)
    print('  5.7.0 n=%d' % len(k57))
    if k58:
        print('  5.8.0 n=%d' % len(k58))
        print('  ADDED   :', sorted(set(k58) - set(k57)))
        print('  REMOVED :', sorted(set(k57) - set(k58)))
        print('  SAME ORDER:', k57 == k58)
    else:
        print('  5.8.0 keys unavailable via that export')
    print()

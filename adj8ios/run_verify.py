import sys, base64, urllib.parse as up
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8ios")
from carve import carve_saz, carve_chls, split_blob, block_ok, search_delta, claims_bytes

def run_saz(path):
    ok = tot = 0
    for name, params, kind, blob, sdk in carve_saz(path):
        pt, tag_ok, head_ok = split_blob(blob)
        b = block_ok(pt, params, kind, sdk)
        tot += 1; ok += (tag_ok and head_ok and b)
        print('%-8s %-13s tag=%s head=%s block=%s  claims=%dB'
              % (name, kind, tag_ok, head_ok, b, len(claims_bytes(params, kind, sdk))))
    print('== %d/%d byte-exact (%s)' % (ok, tot, path))

def run_chls(path, deep=False):
    items = carve_chls(path)
    ok = tot = 0
    for idx, bufs, kind, blob, sdk in items:
        pt, tag_ok, head_ok = split_blob(blob)
        best = None
        for st, q in bufs:
            params = dict(up.parse_qsl(q, keep_blank_values=True))
            for ak in (kind, 'session', 'click', 'attribution', 'event', 'info', 'sdk_info'):
                if block_ok(pt, params, ak, sdk):
                    best = (ak, len(params), st, params)
                    break
            if best:
                break
        tot += 1
        good = tag_ok and head_ok and best is not None
        ok += good
        print('%2d %-13s sdk=%-26s tag=%s head=%s block=%s %s'
              % (idx, kind, sdk, tag_ok, head_ok, best[0] if best else False,
                 ('ak=%s params=%d' % (best[0], best[1])) if best else ''))
        if not best and deep and bufs:
            st, q = bufs[-1]
            params = dict(up.parse_qsl(q, keep_blank_values=True))
            d = search_delta(pt, params, kind, sdk, None)
            print('      delta:', d)
    print('== %d/%d byte-exact (%s)' % (ok, tot, path))

if __name__ == '__main__':
    for p in sys.argv[1:]:
        if p.lower().endswith('.saz'):
            run_saz(p)
        else:
            run_chls(p, deep=('-deep' in sys.argv))

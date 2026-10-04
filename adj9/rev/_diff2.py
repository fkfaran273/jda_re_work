"""_diff2.py — what differs between the WORKING replay and the FAILING fresh run?"""
import sys, urllib.parse, uuid, time
sys.path.insert(0, '.')
import offline_funnel_freshregion as FFN
import nonorg_redrive as R
import adj9_full_chain as fc

# the replay that WORKED (genuine params, fresh GAID)
sp_w = R.rebase(R.load('1_c.txt'), 'GPS', 'AUID', 0)
cp_w = R.rebase(R.load('2_c.txt'), 'GPS', 'AUID', 0)

# the fresh synthetic that FAILED
ins = fc.fmt(int(time.time())+220, 774).decode()
sp_f = FFN.build_session('GPS','AUID', ins, int(time.time())+275)
cp_f = FFN.build_sdk_click('GPS','AUID','adjust_reftag=XXXX&utm_source=VKM+Digital+Yeni',
                           int(time.time()), int(time.time())+20, ins,
                           int(time.time())+275)

for name, w, f in (('SESSION', sp_w, sp_f), ('CLICK', cp_w, cp_f)):
    sw, sf = set(w), set(f)
    print('=== %s  replay=%d keys  fresh=%d keys ===' % (name, len(w), len(f)))
    only_w = sorted(sw - sf); only_f = sorted(sf - sw)
    print('  only in WORKING replay (%d): %s' % (len(only_w), only_w))
    print('  only in FAILING fresh  (%d): %s' % (len(only_f), only_f))
    diff = [(k, w[k], f[k]) for k in sorted(sw & sf) if str(w[k]) != str(f[k])]
    print('  same key, different value (%d):' % len(diff))
    for k, a, b in diff[:14]:
        print('     %-26s replay=%-34s fresh=%s' % (k, str(a)[:34], str(b)[:34]))
    print()

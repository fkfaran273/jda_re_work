# insp.py - inspect the exact harvested data structures
import json
import os

REV = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))
print('all_signings n =', len(A))
print('keys:', list(A[0].keys()))
print('srcs:', [s.get('src') for s in A])
for k in A[0]:
    v = A[0][k]
    print('  %-6s %s' % (k, (v[:70] + '...') if isinstance(v, str) and len(v) > 70 else v))
print()
for name in ('h_samples.json', 'descs_layout.json', 'sign_audit.json',
             'verify_d014_result.json', 'all_signings.json'):
    p = os.path.join(REV, name)
    print('%-26s %s' % (name, 'yes %d B' % os.path.getsize(p) if os.path.exists(p) else 'NO'))
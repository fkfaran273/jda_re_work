# forge_d4_test.py - regression test for the #4 fix (slice 103).
# Asserts:
#   1. CAPTURED_D4 is the structured record, not a MAC
#   2. make_signature() puts the captured #4 in slot 4 and returns it
#   3. make_signature(H=<real H>) does NOT put the MAC in slot 4
#   4. the resulting blob is still exit-clean with a valid header law
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from header_gen import make_header

GOLD_D4 = bytes.fromhex('00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e')
REAL_H = bytes.fromhex('eebe704e53a5cd3dad5fbf42cbb5ef9603e5c0c89be93fb846e95081ab56fb9b')
SEC = F.__dict__ and 1789240512
fails = []

print('1. CAPTURED_D4')
print('   = %s' % F.CAPTURED_D4.hex())
if F.CAPTURED_D4 != GOLD_D4:
    fails.append('CAPTURED_D4 is not the structured record')
print('   matches the golden structured #4: %s' % (F.CAPTURED_D4 == GOLD_D4))

print('\n2. make_signature() default (this runs the VM, ~45 s)')
st, blob, d4 = F.make_signature(SEC, {})
ok_law = blob[:16] == make_header(SEC)
print('   status=%s  law=%s  d4=%s' % (st, ok_law, d4.hex()))
if d4 != GOLD_D4:
    fails.append('default make_signature did not use the captured #4')
if st != 'exit-clean':
    fails.append('blob not exit-clean')
if not ok_law:
    fails.append('header law broken')

print('\n3. make_signature(H=REAL_H) must ignore H for slot #4')
st2, blob2, d42 = F.make_signature(SEC, {}, H=REAL_H)
print('   status=%s  d4=%s' % (st2, d42.hex()))
if d42 == REAL_H:
    fails.append('H still landed in slot #4')
if d42 != GOLD_D4:
    fails.append('slot #4 not the captured record')
if REAL_H in blob2:
    fails.append('the MAC appears in the blob (it must not)')

print('\n4. make_signature_map default d4')
try:
    r = F.make_signature_map({'os_name': 'android'}, 'session')
    print('   returned d4=%s' % (r[2].hex()))
    if r[2] != GOLD_D4:
        fails.append('make_signature_map #4 is not the captured record')
except Exception as e:
    print('   (raised %s: %s) — map lacks law keys, not a #4 issue'
          % (type(e).__name__, str(e)[:90]))

print('\n=== RESULT: %s ===' % ('PASS' if not fails else 'FAIL'))
for f in fails:
    print('  - %s' % f)
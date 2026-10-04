"""_cmp.py — what differed between the WORKING self-click and this one?"""
import json, sys
sys.path.insert(0, '.')
ok = json.load(open('selfclick_result.json'))   # NON-ORGANIC
print('WORKING self-click run:')
print('  gps      :', ok['gps'])
print('  reftag   :', ok['reftag'])
print('  skeys    :', ok['skeys'], ' ckeys:', ok['ckeys'])
print('  t_click  :', ok['t_click'])
print('  session  :', ok['session'][0])
print()
print('FAILED single-command run: GAID a7bd6580-728a-41eb-a98d-76e0751eb46b')
print('  reftag   : adjust_reftag=cUDKur8xwLIBH&...')
print()
print('Key question: is the difference the CLICK (manual browser vs our GET),')
print('or something in the request? Both runs used identical code paths')
print('except _run5.py/_run4.py read GAID/REFTAG from env.')

"""_miss.py — genuine non-organic keys vs the golden_saz canonical base."""
import sys, json
sys.path.insert(0, '.')
import nonorg_redrive as R
gs = R.load('1_c.txt'); gc = R.load('2_c.txt')
GOLD = json.load(open('golden_saz.json'))
S1P, S2P = GOLD['s1']['params'], GOLD['s2']['params']
print('genuine non-organic SESSION: %d keys | golden s1: %d' % (len(gs), len(S1P)))
print('genuine non-organic CLICK:   %d keys | golden s2: %d' % (len(gc), len(S2P)))
print()
print('in GENUINE session, not in golden s1 (%d):' % len(set(gs)-set(S1P)))
for k in sorted(set(gs)-set(S1P)): print('   +', k, '=', str(gs[k])[:40])
print()
print('in GENUINE click, not in golden s2 (%d):' % len(set(gc)-set(S2P)))
for k in sorted(set(gc)-set(S2P)): print('   +', k, '=', str(gc[k])[:40])
print()
print('in golden s1, not in GENUINE session (%d): %s' % (len(set(S1P)-set(gs)), sorted(set(S1P)-set(gs))))

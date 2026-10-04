"""_prune_region.py -- the gates can ask for the head directly.

Every gate recovered a head phase with two awkward steps:

    d0w, _, _ = P.region(seed, 0, 0, head=phase)
    if P.head_words(d0w) == captured_head:

but head16_for(seed, phase) returns exactly those 16 bytes (proved over
27,063 seed/phase combinations by verify_region_short.py).  So the two-step
becomes one call, and the whole descriptor chain becomes dead:

    region, _d0_words, _d0_source, _d4_words, head_words
"""
import re

# ---- 1. the gates: one call instead of two --------------------------------
for fn in ('verify_pure.py', 'verify_event_law.py', 'verify_F_formula.py'):
    s = open(fn, encoding='utf-8').read()
    s = re.sub(
        r'\n *d0w, _, _ = P\.region\(\s*\n?\s*seed, 0, 0, head=(\w+)\)\n'
        r' *if P\.head_words\(d0w\) == ([\w\[\]:\'"]+)\:',
        lambda m: '\n                if P.head16_for(seed, %s) == %s:' % (m.group(1),
                                                                     m.group(2)),
        s)
    # single-line variants
    s = s.replace('d0w, _, _ = P.region(seed, 0, 0, head=q)\n', '')
    s = s.replace('if P.head_words(d0w) == rec[3:19]:',
                  'if P.head16_for(seed, q) == rec[3:19]:')
    s = s.replace('if P.head_words(d0w) == head:',
                  'if P.head16_for(seed, ph) == head:')
    open(fn, 'w', encoding='utf-8').write(s)
    print('rewrote', fn)

# ---- 2. drop the dead chain from the signer ------------------------------
p = 'adj9_pure.py'
s = open(p, encoding='utf-8').read()

for name in ('region', 'head_words', '_d0_words', '_d0_source', '_d4_words'):
    i = s.index('def %s(' % name)
    j = s.index('\n\n\ndef ', i) if '\n\n\ndef ' in s[i:] else len(s)
    j = i + s[i:].index('\n\n\ndef ') if '\n\n\ndef ' in s[i:] else len(s)
    s = s[:i] + s[j + 3:]

open(p, 'w', encoding='utf-8').write(s)
print('removed region, head_words, _d0_words, _d0_source, _d4_words')
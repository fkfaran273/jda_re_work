"""_expl.py — what the head phase actually IS, and what changing it does."""
import sys
sys.path.insert(0, '.')
import adj9_signature as S

S_ = 0xf049c0ae          # a real declic seed from the capture
d4 = S._d4_words(S_)
print('seed S   = %08x  (a per-fill value, different every signing)' % S_)
print('d4 (descriptor #4) =', ' '.join('%08x' % w for w in d4))
print()
print('d0 (descriptor #0), first 4 words, for each candidate head:')
for name, head in (('(0x2b,)   <- declic/creditsea', (0x2B,)),
                   ('(0x2b,0x48) <- penti', (0x2B, 0x48)),
                   ('(0x22,0x2e) <- F.HEAD_FIRST', (0x22, 0x2E)),
                   ('(0x2b,0x07,0x22,0x2e) HEAD_RESIGN', (0x2B, 0x07, 0x22, 0x2E))):
    w = S._d0_words(d4, head=head)
    print('  %-34s %s' % (name, ' '.join('%08x' % x for x in w[:4])))
print()
print('The head only changes the FIRST FEW words of d0; everything from')
print('word 4 on is identical.  d0 is descriptor #0, which lives INSIDE the')
print('signed blob, so the head is part of what the server sees.')

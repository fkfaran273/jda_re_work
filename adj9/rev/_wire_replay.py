"""_wire_replay.py — replay the queue-op wire log, classify each PUSH.

Classification: given the last POP values before a PUSH on the same queue:
  const   — push of a value with no intervening POPs (immediate / LENQ)
  copy    — push == last popped value
  xor     — push == last pop ^ previous pop
  other   — anything else (add/mul/etc.)  -> print pc histogram
"""
import json
import sys
from collections import Counter, defaultdict

wl = json.load(open(sys.argv[1] if len(sys.argv) > 1 else '_wire_row7.json'))
queues = defaultdict(list)      # qva -> list of values (head first)
last_pops = Counter()           # pc -> list of recent popped values (global)
recent = []                     # recent popped values (any queue)
cls = Counter()
other_pcs = Counter()
xor_pcs = Counter()
last_pop = None
prev_pop = None
for idx, ev in enumerate(wl):
    op = ev[0]
    if op == 'POP':
        _, pc, qva, v = ev
        recent.append(v)
        last_pop = v
    elif op == 'PUSH':
        _, pc, qva, v = ev
        if last_pop is None:
            k = 'const'
        elif v == last_pop:
            k = 'copy'
        elif prev_pop is not None and v == (last_pop ^ prev_pop):
            k = 'xor'
        elif prev_pop is not None and v == ((last_pop + prev_pop) & 0xFFFFFFFF):
            k = 'add'
        elif prev_pop is not None and v == ((last_pop - prev_pop) & 0xFFFFFFFF):
            k = 'sub'
        elif prev_pop is not None and v == ((last_pop * prev_pop) & 0xFFFFFFFF):
            k = 'mul'
        else:
            k = 'other'
        cls[k] += 1
        if k == 'other':
            other_pcs[pc] += 1
        elif k == 'xor':
            xor_pcs[pc] += 1
        prev_pop = last_pop
        last_pop = None
    elif op == 'Q':
        pass  # LENQ results go to w0, may become PUSH const
print("PUSH classification:", dict(cls))
print("top 'other' pcs:", [(hex(k), v) for k, v in other_pcs.most_common(15)])
print("top 'xor' pcs:", [(hex(k), v) for k, v in xor_pcs.most_common(10)])

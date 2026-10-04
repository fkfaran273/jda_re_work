import json
from collections import Counter
ops = json.load(open("..\\device\\ops_log.json"))
em = [o for o in ops if o["op"] == "EMIT"]
print("emits:", len(em))
sinks = Counter(o["x1"] for o in em)
for s, n in sinks.most_common(10):
    print(s, n)
# first-appearance order of sinks
seen = []
for o in em:
    if o["x1"] not in seen:
        seen.append(o["x1"])
print("sink order:", len(seen))
# per-sink (n, v) sequences (first sink)
s0 = seen[0]
seq = [(int(o["x2"], 16), int(o["x3"], 16)) for o in em if o["x1"] == s0]
print("sink0 pushes:", len(seq), seq[:6])

"""probe_d0.py — record descriptor #0's 36 EMIT (sink, position) pairs.

Reuses recompute_body.build_descriptors/run (placeholder #0), then dumps
ex.emit_trace in order. #0 is first in pass order, so its 36 field EMITs
(j=0..35) should be the first 36 EMIT events. Verifies count + contiguity.
Saves d0_positions.json: [(sink_hex, pos), ...].
"""
import json
import sys

sys.path.insert(0, ".")
import recompute_body as R

rounds = R.live_field_values()
descs = R.build_descriptors(rounds[0] if rounds else [])
ex, status = R.run(descs, R.SESSION_SECOND)
print("status:", status, "steps:", ex.steps)
tr = ex.emit_trace
print("total emits:", len(tr))
first36 = [(s, n, v) for (s, n, v) in tr[:36]]
sinks = {s for (s, n, v) in first36}
print("distinct sinks in first 36:", [hex(s) for s in sinks])
ns = [n for (s, n, v) in first36]
print("positions 0..35?", ns == list(range(36)))
json.dump({"pairs": [[hex(s), n] for (s, n, v) in first36],
           "steps": ex.steps, "status": status},
          open("d0_positions.json", "w"), indent=1)
print("saved d0_positions.json")

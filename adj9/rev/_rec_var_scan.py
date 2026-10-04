"""_rec_var_scan.py — dump N probe records for a row and find ALL varying
record positions (checks the VAR_POS assumption)."""
import json
import sys

HERE = sys.path.insert(0, '.')
from validate_body_decoder import base_descs, asg, ph3  # noqa: E402
from body_decoder import BodyDecoder, VAR_POS           # noqa: E402

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7
N = int(sys.argv[2]) if len(sys.argv) > 2 else 6

dec = BodyDecoder.__new__(BodyDecoder)
dec.descs_base = [list(t) for t in base_descs(ROW)]
dec.second = ph3[ROW]["second"]
dec.verbose = True
dec.n_probes = N
dec._probe_seed = 0x5EED
dec._workers = N
probes = dec._run_probes()
recs = [r for (r, b) in probes]
json.dump([r.hex() for r in recs], open('_probe_records_row%d.json' % ROW, 'w'))
var_all = [i for i in range(144) if len(set(r[i] for r in recs)) > 1]
print("positions varying across probes:", var_all)
print("outside VAR_POS:", [i for i in var_all if i not in VAR_POS])
print("record0:", recs[0].hex())
for i in var_all:
    print(i, ["%02x" % r[i] for r in recs])

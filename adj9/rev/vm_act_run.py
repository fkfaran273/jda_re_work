"""vm_act_run.py — full-program interpreter run over the REAL corpus rows.

Runs the corrected full interpreter executor (fin_vm2.FinEx, byte-exact on
signing A per fin_result.md) over every region row, with each row's REAL
descriptors and seed = the row's own header-inverted second.  Measures:

  * nrand          — rand() draws consumed by the whole interpreter run
  * activations    — nrand / 8  (whiten-cycle 0x2e6 activations, 4 units x 2 draws)
  * blob window    — output sink F0 [0..48) vs the row's real 192-B blob

Also scans D(claims_len): synthetic descriptor sets with d10 (claims) padded
length varied, everything else held at row 7's values.

Run:  python vm_act_run.py [maxsteps]
"""
import json, struct, sys, time

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev')
from fin_vm2 import FinEx

HERE = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]      # from fin_descs.json
BASE_LENS = {0: 36, 9: 5, 8: 4, 4: 8, 2: 1, 7: 1, 5: 1, 1: 0, 6: 1, 3: 0}


def descs_from_row(r):
    """Build the 11-descriptor list (va order) from an all_signings row."""
    out = []
    for k in VA_ORDER:
        if k == 10:
            hx = r['d10']
        elif k in (1, 3):
            hx = ''
        else:
            hx = r['d%d' % k]
        data = bytes.fromhex(hx)
        out.append((len(data) // 4, 0, data))
    return out


def run_row(descs, seed, maxsteps, blob=None):
    ex = FinEx(seed, descs)
    t0 = time.time()
    status = ex.run(max_steps=maxsteps)
    dt = time.time() - t0
    slotmap = {0x5500000000 + 0x1000 * i: i for i in range(16)}
    f0 = {}
    for (sva, n, v) in ex.emit_trace:
        sva &= 0xFFFFFFFFFFFF
        if sva in slotmap and slotmap[sva] == 0:
            f0[n & 0xFFFFFFFF] = v & 0xFFFFFFFF
    words = [f0.get(i) for i in range(48)]
    hit = 0
    if blob is not None:
        tgt = [struct.unpack_from('>I', blob, 4 * i)[0] for i in range(48)]
        hit = sum(1 for i in range(48) if words[i] == tgt[i])
    return {'status': status, 'steps': ex.steps, 'nrand': ex.nrand,
            'dt': dt, 'hit48': hit, 'words': words}


def main():
    maxsteps = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000_000
    rows = json.load(open(HERE + '/all_signings.json'))
    ph3 = json.load(open(HERE + '/pair_h3.json'))
    print('row | claims_B | status | steps | nrand | act(0x2e6) | blob48/48 | time_s')
    for i, r in enumerate(rows):
        blob = None
        sec = None
        if i < len(ph3):
            blob = bytes.fromhex(ph3[i]['blob'])
            sec = ph3[i]['second']
        else:
            sec = 1789240512          # rows 8/9: desc_det explicit second
        descs = descs_from_row(r)
        res = run_row(descs, sec, maxsteps, blob)
        claims = len(r['d10']) // 2
        print('%3d | %8d | %s | %8d | %5d | %10.2f | %9d/48 | %6.1f' %
              (i, claims, res['status'], res['steps'], res['nrand'],
               res['nrand'] / 8.0, res['hit48'], res['dt']))
        sys.stdout.flush()
        if res['hit48'] not in (0, 48) and blob is not None:
            # show first mismatches for diagnosis
            tgt = [struct.unpack_from('>I', blob, 4 * k)[0] for k in range(48)]
            bad = [(k, '%08x' % res['words'][k] if res['words'][k] is not None else '-',
                    '%08x' % tgt[k]) for k in range(48) if res['words'][k] != tgt[k]]
            print('    first mismatching words:', bad[:8])


if __name__ == '__main__':
    main()

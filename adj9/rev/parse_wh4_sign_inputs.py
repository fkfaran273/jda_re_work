# parse_wh4_sign_inputs.py - extract nsign + sign_input + canonical records from adj9_wh4.log
# goal: the GOLDEN signing's own map_order (nsign blob 5595c3c4...,
# created_at 2026-09-12T21:15:11.678Z+0200) = the pairing order_check2 needed.
import json, re

LOG = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\adj9_wh4.log'
OUT = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\wh4_records.json'

cur = None
nsigns, sign_inputs, canonicals, hfins = [], [], [], []
with open(LOG, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = re.match(r'###ADJ9_BEGIN type=(\w+)', line)
        if m:
            cur = m.group(1)
            continue
        if cur == 'nsign':
            mm = re.match(r'hex=([0-9a-f]+)', line)
            if mm:
                nsigns.append({'hex': mm.group(1)})
            mm = re.match(r'ts=(\d+)', line)
            if mm and nsigns and 'ts' not in nsigns[-1]:
                nsigns[-1]['ts'] = int(mm.group(1))
        elif cur == 'sign_input':
            if line.startswith('map_toString='):
                sign_inputs.append({'toString': line[13:].rstrip('\r\n')})
            elif line.startswith('map_order='):
                if sign_inputs:
                    sign_inputs[-1]['order'] = line[10:].rstrip('\r\n')
        elif cur == 'canonical':
            if line.startswith('text: '):
                canonicals.append({'text': line[6:].rstrip('\r\n')})
        elif cur == 'jca_mac_doFinal':
            if line.startswith('hex='):
                hfins.append({'hex': line[4:].rstrip('\r\n')})

print('nsigns:', len(nsigns), '| sign_inputs:', len(sign_inputs),
      '| canonicals:', len(canonicals), '| mac_doFinal:', len(hfins))
golden = None
for i, n in enumerate(nsigns):
    print('nsign[%d] ts=%s blob=%s...' % (i, n.get('ts'), n['hex'][:16]))
    if n['hex'].startswith('5595c3c4'):
        golden = i
print('golden nsign index (5595c3c4):', golden)
for i, s in enumerate(sign_inputs):
    ca = re.search(r'2026-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z[+-]\d{4}', s.get('toString', ''))
    print('sign_input[%d] created_at=%s order=%s' % (
        i, ca.group(0) if ca else '?', 'yes' if 'order' in s else 'MISSING'))
# pair: golden sign_input = the one whose created_at == 21:15:11.678Z (same signing)
gi = None
for i, s in enumerate(sign_inputs):
    if '2026-09-12T21:15:11.678Z' in s.get('toString', ''):
        gi = i
print('golden sign_input index (21:15:11.678Z):', gi)
# sanity: canonical at the same burst must equal the sign_input toString
match = [c for c in canonicals if '2026-09-12T21:15:11.678Z' in c['text']]
print('canonical records containing golden created_at:', len(match))
if gi is not None and match:
    print('canonical == sign_input.toString:', match[0]['text'] == sign_inputs[gi]['toString'])
json.dump({'nsigns': nsigns, 'sign_inputs': sign_inputs,
           'canonicals': canonicals, 'mac_doFinal': hfins,
           'golden_nsign_idx': golden, 'golden_sign_input_idx': gi},
          open(OUT, 'w', encoding='utf-8'), indent=1)
print('wrote', OUT)

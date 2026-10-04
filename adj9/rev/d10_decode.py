"""d10_decode.py — decode a captured descriptor-#10 claim string into key/value
pairs, and diff a captured (real app) d10 against our script's synthetic d10.

The claim string is a plain concatenation of values in a fixed key order
(desc10_law.desc10_keys), with no separators. Decoding is done by splitting on
recognizable anchors (UUIDs, ISO timestamps, known literals) and walking the key
order left-to-right.
"""
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from desc10_law import desc10_keys

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z[+-]\d{4}")


def decode(d10, kind, val_hints=None):
    """Split concatenated d10 into {key: value}. Uses val_hints (a dict of
    key->exact-value) to pin ambiguous values (e.g. adj_verification, gaid)."""
    keys = desc10_keys(kind, val_hints)
    hints = dict(val_hints or {})
    # Anchor scan: find positions of all UUIDs and ISOs.
    anchors = []  # (start, end, value, kindtag)
    for m in UUID_RE.finditer(d10):
        anchors.append((m.start(), m.end(), m.group(0), 'uuid'))
    for m in ISO_RE.finditer(d10):
        anchors.append((m.start(), m.end(), m.group(0), 'iso'))
    anchors.sort()

    out = {}
    pos = 0
    for i, k in enumerate(keys):
        if k in hints:
            v = hints[k]
            idx = d10.find(v, pos)
            if idx != pos:
                # hint present but not immediately at pos -> record and resync
                out[k] = v
                pos = d10.find(v, pos) + len(v)
                continue
            out[k] = v
            pos = idx + len(v)
            continue
        # find the next anchor that belongs to this key (by heuristic: the next
        # anchor start), else take up to the next known literal.
        nxt = None
        for (s, e, val, tag) in anchors:
            if s >= pos:
                nxt = (s, e, val, tag)
                break
        # Known literals that can also anchor a value
        lit = None
        for cand in ('com.penti.app', 'com.android.vending', 'moto g42',
                     'production', 'service', 'android', 'phone',
                     'S2SE32.28-28-4', 'jut9tib0eeps', '1500000',
                     '3.14.0', '3.13.9', '5.0.0', '10', '5.7.0',
                     'session', 'sdk_click', 'attribution',
                     'adjust_reftag', 'click'):
            idx = d10.find(cand, pos)
            if idx != -1 and (lit is None or idx < lit[0]):
                lit = (idx, cand)
        # choose whichever boundary is nearest
        bounds = []
        if nxt:
            bounds.append((nxt[0], 'anchor:' + nxt[3]))
        if lit:
            bounds.append((lit[0], 'lit'))
        if not bounds:
            out[k] = d10[pos:]
            pos = len(d10)
            continue
        bounds.sort()
        end = bounds[0][0]
        out[k] = d10[pos:end]
        pos = end
    return out


def load_real(path, row=0, kind='session', hints=None):
    d = json.load(open(path, encoding='utf-8'))
    rows = d['rows']
    r = rows[row]
    d10 = bytes.fromhex(r['d10_hex']).decode('latin1')
    return d10, r, decode(d10, kind, hints)


if __name__ == '__main__':
    # quick self: decode the winning session capture
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                     'device', 'win_capture_rows.json')
    d10, r, kv = load_real(p, 0, 'session')
    print('real session d10 len=%d second=%s head=%s' %
          (r['d10_len'], r['second'],
           ' '.join('%02x' % h['w1'] for h in (r.get('head') or []))))
    for k, v in kv.items():
        print('  %-26s %r' % (k, v))
    # roundtrip check
    from desc10_law import build_desc10
    try:
        recon = build_desc10(kv, 'session')
        print('roundtrip ==', recon == d10)
    except Exception as e:
        print('roundtrip build failed:', e)

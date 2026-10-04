#!/usr/bin/env python -u
"""Scratch: extract genuine sign_input maps + split all_signings d10 strings."""
import re, json, os, sys

DEV = r"C:\Users\Apps\Downloads\com.penti.app\adj9\device\adj9_capture_full.log"
REV = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"

def blocks():
    data = open(DEV, 'rb').read().decode('utf-8', 'replace')
    out = []
    for m in re.finditer(r'ADJ9_BEGIN type=sign_input utf8len=(\d+) ts=(\d+)\ntext: ', data):
        s = m.start(); e = data.find('ADJ9_END', s)
        blk = data[s:e]
        ms = re.search(r'map_size=(\d+)', blk)
        ts = re.search(r'map_toString=(\{.*?\})\nmap_order=', blk, re.S)
        k2 = re.search(r'key2_len=(\d+)\nkey2_hex=([0-9a-fA-F]*)', blk)
        out.append(dict(idx=len(out), utf8len=int(m.group(1)), ts=m.group(2),
                        map_size=int(ms.group(1)) if ms else None,
                        toString=ts.group(1) if ts else None,
                        key2_len=int(k2.group(1)) if k2 else None,
                        key2_hex=k2.group(2) if k2 else None, raw=blk))
    return out

def parse_map(ts):
    """Split {k=v, k=v} on ', ' respecting nothing weird; values have no ', '."""
    assert ts.startswith('{') and ts.endswith('}')
    inner = ts[1:-1]
    parts = re.findall(r'([A-Za-z0-9_]+)=(.*?)(?=, [A-Za-z0-9_]+=|$)', inner)
    return parts

if __name__ == '__main__':
    B = blocks()
    json.dump([{k: v for k, v in b.items() if k != 'raw'} for b in B],
              open(os.path.join(REV, '_rv_blocks.json'), 'w', encoding='utf-8'),
              indent=1, ensure_ascii=False)
    for b in B:
        ak = re.search(r'activity_kind=([A-Za-z0-9_]+)', b['toString'])
        print(b['idx'], ak.group(1) if ak else '?', 'map_size', b['map_size'],
              'parsed', len(parse_map(b['toString'])) if b['toString'] else None,
              'key2_len', b['key2_len'])

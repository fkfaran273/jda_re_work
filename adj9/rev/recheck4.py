# recheck4.py - verify all_signings S7 == the golden signing, and compare d0/d2/d4
import json
import os
import struct
import sys

REV = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REV)
from header_gen import make_header

A = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))
FIN = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
D = {x['build_idx']: x['data_hex'] for x in FIN['descs']}
hdr = bytes.fromhex(FIN['target']['blob_hex'])[:16]
sec = FIN['target']['second']
print('make_header(%d) = %s' % (sec, make_header(sec).hex()))
print('golden blob hdr  = %s   match=%s'
      % (hdr.hex(), make_header(sec) == hdr))
print()
print('fin_descs d0 (%d B) = %s' % (len(bytes.fromhex(D[0])) // 2, D[0]))
print('fin_descs d2        = %s' % D[2])
print('fin_descs d4        = %s' % D[4])
print('fin_descs d7/d8     = %s / %s' % (D[7], D[8]))
print()
for k, s in enumerate(A):
    same0 = s['d0'] == D[0]
    same2 = s['d2'] == D[2]
    same4 = s['d4'] == D[4]
    same7 = s['d7'] == D[7]
    print('S%-2d %-18s d0==%s d2==%s d4==%s d7==%s  d2=%s'
          % (k, s['src'], same0, same2, same4, same7, s['d2']))
print()
print('=== all 10 d2 values, and d4 heads/tails ===')
for k, s in enumerate(A):
    d4 = bytes.fromhex(s['d4'])
    print('  S%-2d d2=%s  d4head=%s tail=%s'
          % (k, s['d2'], d4[:8].hex(), d4[8:].hex()))
print()
print('=== d2 vs d7 vs desc lengths ===')
for k, s in enumerate(A):
    d7 = struct.unpack('>I', bytes.fromhex(s['d7']))[0]
    d10len = len(bytes.fromhex(s['d10']))
    d10unp = len(bytes.fromhex(s['d10']).rstrip(b'\0'))
    d2 = struct.unpack('>I', bytes.fromhex(s['d2']))[0]
    d2le = struct.unpack('<I', bytes.fromhex(s['d2']))[0]
    print('  S%-2d d7=%-6d d10len=%-5d unp=%-5d d2be=%-12d d2le=%-12d'
          % (k, d7, d10len, d10unp, d2, d2le))

# mints_same_map.md — E1 verdict input: two device mints of the SAME map, 1 s apart
mint1: stamp=2026-09-19T11:30:01.491Z+0530 ok=False canonical=NO blobLen=0
mint2: stamp=2026-09-19T11:30:01.491Z+0530 ok=False canonical=NO blobLen=0
mapPairs identical: True (46 keys)
header A: 186b2ceb5a1d15b15a6e55b660686224
header B: 70afa79d29a62e1420ef256158ae756e
decoded: 192 B vs 192 B
equal bytes: 1/192 ; diff runs: (0,85) (87,191)
diff-byte mean A=120.7 B=121.1
NOTE: headers differ too - under the proven header law these two mints fell in
DIFFERENT seconds. Same-second control still open (device/mint_pairs.py).
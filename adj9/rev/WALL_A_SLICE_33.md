# Wall A - slice 33: end-to-end map - header loop reached (2026-09-11)

## 1. Router tree (w0-valued, static extraction `scan_flow.py`, kept)

Full table (selection): dispatch 0x2d/0x37e/0x19f/0xeb/0xbb/0x7d/0x99, then
per-case cascades (0x651/0x534/0x4de/0x3e5/0x3d9, 0x27f/0x1fb/0x1cd/0x1bb,
0x727/0x6bb/0x685/0x65d, 0x143/0x10b/0x101, 0x583/0x55e/0x549, ...), loop-back
`0x12a8b4` as the universal else, PUSH(109) and PUSH(557) (`0x12a9d8`,
w2=0x22d) reseeders, PUSH(6) for ==0x99, PUSH(0x13) pair + `udiv` preamble
before the header loop.

## 2. Gateway RETRACTED: live edge `0x101300 -> 0x128eec` (w0 < 0x319)

The slice-32 "dead junk" verdict was wrong: missed this edge in the first
scan (desync). Live semantics: OUTLEN-derived w0 >= 742 (0x2e6) -> header
path 0x12a1f8; == 725 (0x2d5) -> header via second door; else loop-back.
725/742 are OUTLEN (workspace-size) thresholds, not decoys. Correction
recorded plainly; the SM4-opaque analogy does not apply here.

## 3. force=742: header loop FIRES (nrand 0 -> 2), dies on depth

Path: dispatch(742) -> ... -> gateway (128eec=1) -> 0x12a1f8=1 ->
0x12a2f8=1: two `rand` draws execute, then POP-underflow kills before
XOR/EMIT (queue empty). Expected header for the seed
(`make_header`: 4999f1bf...) therefore uncompared — the draws never reach
EMIT. force=725 reaches gateway but not header (falls to loop-back);
force=800 takes an unrelated case. Forced sweep 45/100/124/126/130/150/
153/200/400/700: all route per-table, none deeper than their case bodies.

## 4. Complete end-to-end map (first full version)

passes (const-reseed 109/557, workspace warms) -> dispatch/case/router
descents (values evolve) -> gateway OUTLEN>=742 (per selected stream) ->
header loop (8 draws, needs queue depth 2 sustained) -> workhorse
per-dword LENQ/EMIT (0x12a880, counter) -> cases -> assembly (0xbb548:
NewByteArray idx23 + SetByteArrayRegion idx170) -> 192 B. Every gap left
is queue DEPTH, i.e. real workspace values, i.e. real inputs (R4). No
unknown control remains on this path.

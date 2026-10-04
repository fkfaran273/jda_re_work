# Wall A - slice 49: caller-based EMIT, acc growth, gateway windows (2026-09-11)

## EMIT modes by caller pc (vm_final.py, replaces fresh/merge heuristic)

- Field range (`0x10015C-0x100220`): bulk data store (n==len appends).
- Elsewhere fresh (offs==[0], acc==0, n >= len): append (header XORs etc.).
- Elsewhere live: workspace `offs[TOP+n]` + `acc=idx+1`, malloc-grow
  modeled to 4M entries (native: unbounded realloc or fail - open).

## Accumulator growth (verified)

MAIN acc: 0 -> 176, offs len 1 -> 176 on placeholder runs (merge EMITs
with small TOPs land in-range and stick). acc persists across EMITs now
(sync_struct preserves live fields - slice fix).

## Gateway windows (exact dispatch arithmetic)

- Gateway path entry needs dispatch in [369,415): >=0xeb lands 0x100a2c,
  <0x19f keeps it there, >=0x143 reaches 0x101098, >=0x171 reaches the
  0x12924c workhorse gate; 0x100bd8/0x101300/gateway need staged w0
  (700/800/700/742-exact) as established.
- Tail-steering law (`dispatch#1 = -rev32(#0-tail)`) reaches any window
  with one dword (10/10 verified). 0x101300->gateway needs OUTLEN>=742
  from a real selected stream (acc - TOP with real TOPs).
- Natural runs never enter these windows (placeholder dispatch 0/small or
  huge-overshoot into upper cases). Real #0-tail + real TOPs route here.

## Standing

Every number on the path is now exact (windows, gates, modes, growth).
The machine awaits real content; no code unknown remains on stages
reached (field 62/62, header 4/4 byte-exact, workhorse 44-structure,
gateway arithmetic, assembly call-level).

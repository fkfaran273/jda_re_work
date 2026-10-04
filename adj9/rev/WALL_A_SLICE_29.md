# Wall A — slice 29: iteration-body blocks enumerated, walk forks on 2 runtime values (2026-09-11)

Hub `0xba674` (`walk_ba.py`, `enum_ba.py` — kept? no, deleted after use;
rerunnable): entry `x9=0xe5b2ef1cd426b6e5`, tokens resolved except
`x22=None` (JNIEnv, entry arg) and `x26={2}` (csel on runtime flags).
Walk dies at first `x26`-materializing alias (`0xba740`).

## 23 work blocks (order-free census)

- JNI blocks: `0xbaa70` (static idx107 + `0x9afa4`), `0xbabe4` (CallV idx31
  + `0x9afa4` — the get-style call), `0xbad50` (Alloc idx23),
  `0xbaf04` (Alloc idx23), `0xbb0fc` (BoolV idx34 + `0x9afa4`, result saved
  `str x0,[x8]`), `0xbb238` (Bool idx33 + `0x9afa4`).
- Env/string blocks: `0xba970` + `0xbb3b4` (property checker), `0xbb040` /
  `0xbae58` (inline XOR decrypts: sig @`0x153910` key `0xbe`; `31 T`
  @`0x153f68` key `0x54` + flag store — one-shot mutable cells, NOT data;
  my earlier "record assembly" reading of `0xbae58` withdrawn).
- Frame slots `[x29−0x18/−0x20]` written by `0xbaf04`/`0xbaff8` (shared —
  loop-carried ptr/acc pattern = the iteration loop lives hereabouts).
- `0x9afa4` helper (106 insns, clean): single JNI call idx15
  (`PushLocalFrame`-class) — frame/exception management around fetched
  objects, called after every fetch.

## Verdict

The iteration body's block SET is fully enumerated (calls + stores each);
executing it in ORDER needs exactly 2 runtime values (`x22` JNIEnv,
`x26` fork) — fourth confirmation of the input wall (merge dispatch,
`0xbb548` route, `0xba674` walk). No unhandled insns anywhere in the walk
span. The walk resumes the moment concrete regs exist (runtime log or
caller-frame recovery of JNIEnv + the csel condition).

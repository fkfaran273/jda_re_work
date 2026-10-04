# Wall A - slice 55: assembly call args decoded (2026-09-11)

`0xdbb64 bl 0xbb548` args (all verified):

| arg | value | note |
|---|---|---|
| x0 | `x29-0x60` | level cell (`stp wzr,w5` at hub prologue) |
| x1 | `[sp+0x18]` | = x19 = **JNIEnv** (stored at `0xdb248`) |
| x2 | `[x29-0x50]` | saved MAP (`stp x3,x2`: x3 = Java activity map) |
| x3 | `adr 0x154870` | string-table entry (needs decode - claim name? format?) |
| x4 | `sp+0x40` | output struct (8B zeroed just before) |

Preceded by `bl 0x13d874` (time builder) + one-shot flag clears
(`0x155d90`, `0x155d84`).

## Missing: stream inputs

NO stream pointer among the args - the VM's streams must reach the
assembler via globals/statics (set by stamp/VM; candidates: the 0xA0 CTX
object address stashed somewhere, or fixed slots) or the assembler
re-derives (re-runs VM? reads map + recomputes?). Next: find static
stores of stream/CTX addresses (scan for `str x?,[0x15xxxx]`-pattern
writes into .data/.bss from VM/stamp/builder ranges), decode `0x154870`.

# Wall A — slice 117: nSign's real body reversed; the builders are its callees

Date: 2026-09-19. Scripts/logs: `rev/nsign_scan.py` / `.log` / `nsign_scan.json`,
`rev/nsign_body.py` / `nsign_body_run.log` / `nsign_body.log`.

## 0. Correcting the address

`dump_fn.py 0xdb1cc` reported "function start guess: 0xda980" — that heuristic
scan walked back to the *previous* function's prologue, so every earlier dump of
"the nSign body" (`nsign_fn.log`, and the case table derived from it) was in fact
`sub_da980`, the state machine of the other JNI entry.

Resolved properly from `.dynsym` (`nsign_scan.log`):

```
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume  va=0xda4b0 size=0x4
Java_com_adjust_sdk_sig_NativeLibHelper_nSign      va=0xdb1cc size=0xc74
```

## 1. nSign's argument layout — confirms the hook signature

From its own prologue (`nsign_body.log`):

```
mov x19, x0                       ; JNIEnv*
stp  x3, x2, [x29, #-0x50]        ; save Context, LinkedHashMap
stur x4,     [x29, #-0x58]        ; save byte[] H     <- the key2 MAC (arg3)
stp  wzr, w5,[x29, #-0x60]        ; int status, and w5 = sdk int
mov  w22, w5 ; mov w0, w22 ; mov x1, x19
bl   0x95fc4                      ; (sdk, env, &ctx, &map, &H, &status)
```

So the native signature is `nSign(JNIEnv*, jobject, Context, LinkedHashMap,
byte[] H, int sdk)` and **H is passed in as a 5th argument**, exactly as
`rev/agent/sign_bundle.js` hooks it.

## 2. nSign is a state-machine wrapper, not the builder

797 instructions (0xdb1cc–0xdbe3f) reduce to:

* **24 `adrp`/`adr`** into two pages only: `0x155000` (per-symbol "decrypted"
  latches at offsets 0xd91/0xd92/0xd93/0xd94) and `0x1548xx`;
* the obfuscator's **in-place decrypt-then-latch** blocks, e.g.

```
adr  x13, #0x1548c0 ; movi v1.16b, #0x3a
ldrb w8,[x13,#0x18] ; eor w8,w8,#0x3a ; strb w8,[x13,#0x18]   (x8 bytes)
ldr  q0,[x13]       ; eor v0.16b,v0.16b,v1.16b ; str q0,[x13]
adrp x13, #0x155000 ; strb w11,[x13,#0xd94]                    (latch = 1)
```

with three page keys seen so far (`0x3a`, `0xd4`, `0x33`) — the same pattern
`rev/decryptors.py` harvests;
* a **dispatch ladder over `w26`** (status word returned by its callees) with ~90
  inline 64-bit constants, every arm tail-branching back to `0xdb2e8` with a
  `csel`-selected pair;
* **8 internal calls only**:

| call site | target | role |
|---|---|---|
| 0xdb21c | `sub_e2be0` | init/validate, takes `(sdk, env, &status)` |
| **0xdb24c** | **`sub_95fc4`** | takes `(sdk, env, &ctx, &map, &H, &status)` — **the builder** |
| 0xdb898 | `sub_da97c` | helper on `sp+0x48` |
| **0xdbb64** | **`sub_bb548`** | takes `(ctx, env, &H, &blob, &out)` — assembly incl. H |
| 0xdb1c8 | `__stack_chk_fail` | epilogue guard |

## 3. What this means for the offline goal

The descriptor set (`#0…#10`) — and therefore the region `#0/#2/#4` — is **not**
materialised in nSign; nSign only decides *which* path to run (its `w26` state)
and hands `ctx`, the map, and H to `sub_95fc4`, then assembles with `sub_bb548`.
So the extraction target is now two concrete functions rather than a 797-insn
state machine:

```
next:  python dump_fn.py 0x95fc4     # map -> descriptors (#0,#2,#4,#7,#8,#9,#10)
       python dump_fn.py 0xbb548     # H + descriptors -> 192-byte blob
```

Both are reachable with the tooling already in the repo (`dump_fn.py`,
`callgraph.py`, `datarefs.py`, `decryptors.py`), and the device doublets of slice
116 give the ground-truth `(map, second) -> blob` pairs to validate against.

## 4. Artifacts

| file | role |
|---|---|
| `nsign_scan.py` / `.log` / `nsign_scan.json` | dynsym-resolved JNI entries + head dumps |
| `nsign_body.py` / `nsign_body_run.log` / `nsign_body.log` | full 797-insn nSign body, imports, adrp/adr, callees |
| `rev/nsign_fn.log` | the earlier (mis-addressed) dump — kept only as the case-table source, now known to be `sub_da980` |

## 5. Addendum — the two builder dumps (same session)

```
python dump_fn.py 0x95fc4  ->  sub_95fc4.log   571 lines   (fn start 0x956e4, end 0x95fc8)
python dump_fn.py 0xbb548  ->  sub_bb548.log  1066 lines   (fn start 0xba4ac, end 0xbb54c)
```

Both open with the identical obfuscated constant-fold two-arm dispatch
(`cmp x0,#0` / `csel x28, x9, x8, eq` …), i.e. the same OLLVM flattening as nSign,
and they are the only two places where the map and H are consumed. They are the
ground-truth construction sites to reduce next, and every candidate must
reproduce the slice-116 doublet bytes for the same (map, second).
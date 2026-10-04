# OPS_LIFT — aligned-session field descriptors + CAP drop-in contract (2026-09-12)

Evidence: `device/vm_full.json` (pid 12438 = the ALIGNED session, H=46cb9a96…,
sess second 1789207344 — see `target_body.json`), `device/vm_mem/` (3 regions),
`device/st_out/` (adj9-oracle thread stack sweeps of a related session).
Artifacts: `rev/extract_desc.py` (reproduces everything below),
`rev/descriptors_aligned.json` (machine-readable deliverable).

---

## 1. How the records decode (the key that unlocks everything)

`device/vmhook.js` arms three hooks — this was previously undocumented:

| tag | hook VA | fires |
|---|---|---|
| `vm` | `0x100094` | once per VM(0x100094) call |
| `fieldloop` | `0x100114` | **12x per VM call** — the loop head `cmp x23,x26` for i = 0..11 |
| `workhorse` | `0x12A880` | the claim-fetch loop inside the same builder fn |

At the loop-head hit i the captured registers mean:

- `x2` = the last value written to `w2` = the **previous descriptor's last
  EMIT index** (for i=0 the untouched arg2 = `0xb` = desc count);
- `x3` = the previous desc's **last emit value** (the `rev w3,w8` BE view);
  for i=0 the untouched arg3 = **desc-pass[0] node pointer**;
- `x1` = `[ctx + 0x20 + (i-1)*8]` = the **previous desc's sink stream**;
- `x0`/`x19` = writer obj, `x20`/`x1` = CTX (round A `0x6ed2ade2d0`,
  round B `0x6ed2ae6af0`).

So the 12 records per round = 1 entry + 11 per-descriptor "last emit" probes.
Descriptors that emit nothing (the two empty descs) leave `(x2,x3)`
unchanged — the two duplicated trailing records identify them.

Disasm reference (verified this session, `0x100094..0x100228`):
`x27 = [va slot]` -> node `{u32 w0; u32 pad; u64 data}`; `x21 = w0>>2`;
inner `0x100164`: `EMIT(x0=writer, x1=[ctx+0x20+i*8], w2=j, w3=rev32(data[j]))`;
tail `0x1001a8..0x100214`: `EMIT(..., w2=w21=L, w3=tail)` with
1B `byte<<24` / 2B `rev16&0xffff0000` / 3B `b0<<24|b1<<16|b2<<8` / tag 0 none.

## 2. The 11 descriptors — pass order, lens, values (aligned session)

The va_list pass order is **NOT** the stamp's mkdesc build order. Both rounds
give the unique consistent permutation:

```
pass  = [ #0, #9, #8, #4, #2, #7, #10, #5, #6, #1, #3 ]
lens  = [ 36,  5,  4,  8,  1,  1, RT,   1,  1,  0,  0 ]  (dwords)
```

| build# | pass# | len_dw | tag | w0 | data / source | round A last dw | round B last dw |
|---|---|---|---|---|---|---|---|
| 0 | 0 | 36 | 0 | 0x90 | 144-B core record @struct+0x50 | `3465d635` (j=35) | `0c5bc6be` |
| 9 | 1 | 5 | 0 | 0x14 | **SHA-1(cert) `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd`** | `ae7d74bd` (j=4) | same |
| 8 | 2 | 4 | 0 | 0x10 | 16 B, dword3 = 0 | `00000000` (j=3) | same |
| 4 | 3 | 8 | 0 | 0x20 | **H (TEE-HMAC, arg3), 32 B** | `77dbc67c` (j=7) | `17e17287` |
| 2 | 4 | 1 | 0 | 0x04 | u32 @struct+0x20 (per-signing) | `59521d1d` | `005803e2` |
| 7 | 5 | 1 | 0 | 0x04 | u32 @struct+0x128 = **byte-len of #10 = raw w0 word of #10** | `00000168` | `00000183` |
| 10 | 6 | 90 / 96 | 0 / 3 | 0x168 / 0x183 | packed fetch-claim strings @struct+0x130 | `.0.0` (j=89) | tail j=96 = `"0.0"` (387 B) |
| 5 | 7 | 1 | 0 | 0x04 | proven constant 0 (slice 27) | `00000000` | same |
| 6 | 8 | 1 | 0 | 0x04 | proven constant 0 (slice 27) | `00000000` | same |
| 1 | 9 | 0 | 0 | 0x00 | empty {0, NULL} (slice 27) | — no emit — | — |
| 3 | 10 | 0 | 0 | 0x00 | empty {0, NULL} (slice 27) | — no emit — | — |

Total field-loop input: **147 dwords (round A) / 154 (round B)** — the old
"62 dwords in" (slice 7, static lens `36,0,1,0,8,1,1,1,4,5,5`) is **WRONG**;
it must not be used by the interpreter. Per-round `#10` length varies
(360 B vs 387 B packed claims).

Byte-order law (proved on the SHA-1 anchor): the loop emits
`rev32(LE_u32(data+4j))` = the **BE view** of the raw bytes. The SHA-1 sits in
memory in natural digest byte order and emits `fad0f10d...ae7d74bd` unchanged.
The scalar descs are stored **pre-reversed** (BE bytes) by the stamp
(e.g. #7 emits 0x168 -> memory bytes `00 00 01 68`), so emitted value ==
native u32 value. vm_final.py's `rev` accounting stays correct.

Corrections to slices 23/26 forced by live data:

- **#8 is not the digest prefix.** Slice 26 put #8 (16 B) at the same
  struct+0x100 base as #9 (20 B); then #8's dword3 would be `b6c09691`.
  Live: dword3 = 0 (both rounds). #8 is a different 16-B buffer ending in
  zero; its source slot attribution in slice 23 (`[sp+0x48]`) is unreliable.
  dwords 0-2: UNKNOWN.
- **#9's data pointer is not struct+0x100 in the live session** (see §4:
  the node points at a heap buffer `0x6fe66a96e0` in the st_out session).
- **#10's tail is real:** round B w0 = `0x183` -> L=96 + tag 3 -> the loop's
  tail emit at index 96 packs bytes[384..386] = `"0.0"`; round A w0 = `0x168`
  -> L=90 tag 0, last inner j=89. #7's value == #10's w0 both rounds — the
  two descriptors are coupled through `[x19+0x128]` exactly as slice 27 said.

## 3. Round/capture facts (for replay determinism)

- Round A: writer `x19=0x6d9ac072b8`, ctx `0x6ed2ade2d0`,
  desc node ptrs (arg3/arg4) `0x6e629fd2d0` / `0x6e62a0bdb0`.
- Round B: writer `0x6d9af18da8`, ctx `0x6ed2ae6af0`, nodes
  `0x6e62a0ebf0` / `0x6e62a0eb90`.
- vm records (n=1, n=104) are register-identical to the first fieldloop hit
  of their round (verified) — same call.
- Sinks (ctx+0x20+8i, round A): `a62260, ab0e90, ab1280, ab0c80, ab1370,
  ab10a0, aac1e0, ab0c20, ab0c20, a633d0, a633d0` — **#5/#6 share one stream
  and #1/#3 share one** (the empties' slots hold a dummy stream, never used).
- Workhorse (`0x12A880`), round A: init record (x1=0, x2=string-table base
  `0x6e62a0bf70`, x4=0x10, **x9=0x5a=90 = the #10 dword count**) + 89 fetches
  (x1 = 1..89, x2 = table slots `0x54..0xac`, x3 = 4-byte string chunks,
  ending `...nand roid 5.7. 0105`). It is the VM's hardcoded claim re-fetch
  (fetch order differs from the stamp's map-order pack). UNKNOWN: exact
  per-slot key map.

## 4. Memory-dump truth (where the struct is and is not)

- `vm_mem` (aligned session, taken hours after the signings): **H = 0 hits,
  cert-SHA1 = 0 hits in all three regions** (R_6e629fb000/R_6e72a60000/
  R_6ed2adc000). The master struct (orchestrator `sp+0xb0`) and the desc
  data buffers are NOT captured; the desc-node stack slots were reused by
  later calls (e.g. round A pass[0] node @0x6e629fd2d0 now holds an unrelated
  `{3, ptr}` string pair). Stream structs at the recorded sink VAs are
  likewise post-session stale. => aligned-session descriptor CONTENT beyond
  the table above is not extractable from vm_mem. The H-anchor plan must run
  on a dump taken DURING the stamp.
- `st_out/st*.bin` = **adj9-oracle thread stack**, `[stack_end-0xC0000,
  stack_end)` (snap2.sh: region `6ef917b000-6ef9282000` => dump VA base
  **0x6ef91c2000**; confirmed by 302 self-referential frame pointers).
  Contains: a raw cert-SHA1 copy @VA `0x6ef91cca40` (st6+ files; `0xba9c0`
  in st1-5) and the **SHA-1 desc node `{w0=0x14, pad=0, ptr=0xb400006fe66a96e0}`**
  (offset 0xb5cf8; 0xb5c78 in st1-5). The node's data ptr = a scudo:primary
  heap buffer (region `0x6fe6697000`) already zeroed at dump time (freed).
  The stale stack copy has +0x128/+0x130 = 0, i.e. it is not the live master
  struct either. The method is ready though:
  `extract_desc.py:extract_from_memory()` finds the struct via the
  session-independent SHA-1 at +0x100 and validates +0x128/+0x130; it needs
  one dump taken while the stamp is on the stack (e.g. the grabtail
  stall-sweep timed at the fieldloop hook).

## 5. Part 2a — field-loop cross-check vs vm_full.json (results)

`python rev/extract_desc.py` — both rounds: **all 12/12 records match
(x1, x2, x3) and all 10 independent checks PASS**:

- static lens == live last-j for #0(36), #9(5), #8(4), #4(8);
- #9's last emit == SHA-1 dword4 `ae7d74bd` derived from the constant digest
  (non-circular);
- #5/#6 == 0 (slice 27 statics); #1/#3 produce no emit (carry-over records
  match);
- #7 value == #10's w0 word (0x168/0x183), and w0 == 4*L+tag self-consistent
  (round B tag-3 tail at index 96 == the recorded j=96).

Per-descriptor verdict: **no mismatch found**; the only N/A cells are emit
VALUES whose content is unknown (#0 dwords 0-34, #4 dwords 0-6, #8 dwords
0-2, #10 content, #2's source u32) — marked `unknown_dwords` in the JSON.

## 6. Part 2b — CAP `0x14784c` drop-in contract for vm_final.py

Verified against disasm (slices 44/45 confirmed in outline; two claims
corrected — see §7). The opaque-const machine is fully enumerated:

```
CAP(x0=writer, x1=queue, w2=k)                 ; 0x14784c (entry)
  count  = u32[queue + 0]                      ; ldr w8,[x1],#8 (post-inc x1)
  if count <= k (UNSIGNED 32-bit cmp):
      u32[writer] = 4                          ; 0x14794c: str w9,[x23]
      return x0                                ; VM then does ldr w8,[x19];
                                               ; cbnz -> exits (0x100318)
  node = u64[queue + 8]                        ; head (most recent push)
  repeat k times:  node = u64[node + 8]        ; 0x1479e4/x28 walk (w12=0..k)
  PUSH(writer, queue, u32[node])               ; 0x147968: bl 0x147630
  return x0                                    ; [writer] untouched (0) -> OK
```

Wrapper `0x147a20` = CAP with **k forced to 0** (`mov w2, wzr; b 0x14784c`);
the caller's `mov w2,#imm` there is a decoy.

Queue/node layout (from PUSH `0x147630` / POP `0x147734`, both verified):

- queue: `{u32 count@0; pad; node* head@8}` — head = MOST RECENT push;
  PUSH prepends (malloc 16 B via 0x148b90, `node.value=v`, `node.next=head`,
  `head=node`, `count++`); POP removes head, `count--`, empty -> `[writer]=3`.
- node: `{u32 value@0; u32 pad@4; node* next@8}` (16 B).

Semantics in one line: **CAP(queue, k) re-appends (prepends) a copy of the
value that sits k entries deep from the head of the SAME queue — i.e. the
value pushed k pushes ago (0-based); it errors the writer with 4 if the
queue holds fewer than k+1 entries.** It is the in-band feedback/whitening
op, not a "pad".

Call-site facts (VM builder `0x100094..0x12aa48`): 302 direct `bl 0x14784c`
+ 240 wrapper `bl 0x147a20` = **542 CAP ops**; every one does
`ldr x1,[x20]` (ctx[0] = queue1) + `mov x0,x19` immediately before. Direct k
distribution: {1:160, 2:67, 3:43, 4:17, 5:10, 6:2, 0:2 (wzr), 0x11:1}; the
k=0x11 site sits late (header-loop region). Typical program shape:
`PUSH(v); CAP(queue, k)` — CAP feeds an older value back into the stream.

Suggested vm_final.py drop-in (pure model, no memory needed):

```python
def op_cap(writer, queues, queue_va, k):
    q = queues[queue_va]                # {'count': int, 'head': node|None, ...}
    if q['count'] <= k:                 # UNSIGNED compare
        writer['status'] = 4            # caller exits (cbnz)
        return
    node = q['head']
    for _ in range(k):
        node = node['next']             # k next-hops; count>k guarantees hit
    push(q, node['value'])              # prepend + count += 1
    # writer status untouched on success
```

(Remap onto vm_final.py's StreamObj/queue dict; keep the `[x19]` check
semantics: success leaves status 0, failure sets 4.)

## 7. Slice 44/45 verification — what stands, what is corrected

Stands: entry `w8=[x1]; x1+=8`; `csel x8 = (count>k) ? C2 : C1` with
C2=0x549f0add957dd282 (slice 44 read it as `0xd282...`, slice 45 as `0x549f...`
— both are the same const x25); count<=k -> `[writer]=4` -> caller exits;
`0x147968` PUSH exit; `x8==x22const` (0x875396cceef20d05b — slice 45's
"RETURN") at `0x1479f8`; the `0x1479c8`/`0x1479ac` loop states; return via
`0x147a14`.

Corrected:

1. **"PUSH exit pushes live R[x21]" — wrong.** CAP overwrites x21 with the
   walked node pointer (`x21 = [x10]`); the pushed value is `u32[node]`, the
   k-th-deep queue entry. The caller's x21 is restored on exit
   (`ldp x22,x21,[sp,#0x80]`). Slice 45's trace evidence ("pad == iteration's
   draw value") is explained by the k=0 wrapper sites: CAP(0) re-pushes the
   value that was just PUSHed.
2. **"no per-queue counter anywhere" — wrong.** The queue's `count` field
   (+0) IS the trigger (`count <= k` -> error), and the walk depth is k.
3. "Both the trigger and the pad value are guesses" (slice 44) — resolved:
   trigger = queue depth vs k; "pad" = the k-th-deep value.
4. The 7-state hub (consts x22/x27/x19/x26/x25/x28/x24) is a closed machine:
   x26 = entry dispatcher (reads the saved csel result), x25 = walk-init
   (`x10 = [x29-0x18]` = orig x1+8, w12=0), x27 = load+test, x28 = advance
   (`x10 = prev node+8`, w12++), x19 = PUSH+finish, x24 = error+finish,
   x22 = epilogue. No other exits; no unmatched-const path reachable.

UNKNOWN (explicit, bounded): which VM program positions use which k beyond
the histogram (needs the op walk in vm_final.py); whether any queue ever
reaches count <= k in a valid signing (native never errors — the program
must guarantee depth; not proven here); CAP's use inside the header loop
(the single k=0x11 site) is not yet traced to its op.

## 8. Files

- `rev/extract_desc.py` — both extraction paths + full cross-check
  (`python extract_desc.py` prints the verdicts, writes the JSON).
- `rev/descriptors_aligned.json` — the 11 descriptors per round (len_dw, tag,
  w0, last emit, sink, data_hex where known, unknown_dwords), record-level
  cross-check results, anchor-scan results, st_out findings.
- Do NOT modify `vm_final.py` (owned by another agent) — the CAP drop-in is
  section 6 above.

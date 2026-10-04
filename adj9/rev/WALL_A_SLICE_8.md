# Wall A — slice 8: 192B DECODE vs the 38-blob corpus (2026-09-11)

Goal for this slice (user-set): decode the 4 SAZ bodies + 34 oracle blobs.
Scripts: `final_decode.py`, `final_validate.py`, `final_samesec.py`,
`final_bodydiff.py`, `final_fieldloop.py` (all in `rev/`). No device used.

## 1. Corpus parsed to 48 BE dwords each (38/38)

Every blob = 192 B = **48 big-endian u32** (`struct.unpack(">48I")`):
dwords 0–3 = 16-B header, dwords 4–47 = 176-B body.

| source | n | parse |
|---|---|---|
| oracle `blobset.json` | 34 | 34/34 header-match (`ts//1000` ±2 s), MSB viol 0 |
| SAZ `saz_sigs.json` (server-200 OK) | 4 | 4/4 header-match at `created_at+1` (S1==S2 `40c8114d…`) |
| `pairset.json` (H-paired) | 22 | sizes all 192, repeat-H group 192/192 diff |

Corpus-wide: **0/48 dword positions constant** across devices/sessions —
every dword is live (time or per-call record content). No version magic, no
fixed tag.

## 2. Same-second pair = the decisive split (header vs body)

`blobset.json` contains exactly one same-second group (sec 1788954632,
dt 376 ms). `final_samesec.py`:

```
stable dwords: [0,1,2,3] = 6b6dcc31 7c207d15 139bc3c4 72deff54
header_diff 0/16, byte_diff 175/192, dword_diff 44/48
```

The ONLY stable dwords are the 4 header dwords. **All 44 body dwords differ
within the same second.** Combined with the exhaustive site scan (srand×1
`0x12cbc0`, rand×2 `0x12a2fc/0x12a31c`, all draws consumed by the header
loop ops 7425–7443), this proves the body's entropy is **not** the rand
stream: it is the sub-second record (2× `clock_gettime` ns stamps + live
env inputs) diffused by the 465 LENQ feedback accumulators.

## 3. H is whitened, not stored (6/6 negative, both endians)

For each `pairset.json` entry the true 32-B arg3 H is logged alongside its
blob. `final_decode.py` slides the 8 H-dwords over all 41 windows of the 48
blob dwords, BE and LE:

```
H-contain rawBE=False rawLE=False (6/6 shown, holds across the set)
```

H never appears as 8 consecutive dwords in its own blob. It enters the VM
as descriptor `0x20` (8 dwords) into its own sink, then the queue-merge
program mixes it via POP/XOR/EMIT + LENQ accumulators — exactly why the
raw-draw/raw-H containment tests (`noise_match_test.py`,
`body_unmask_test.py`) are negative. The server reads H after re-running
the same merge, not by substring search.

## 4. Executor fix: runaway → clean exit at step 734 (blockage pinpointed)

Two one-line fixes this session:
- `header_gen.py:1` byte `0x97` (em-dash) → `-` (Python 3.14 refused the import).
- `vm_final.py` POP-empty: was `w0 = queue.pop(0) if queue else 0`
  (underflow silently yields 0 → infinite loop at `0x100354` ×19864, 3M-step
  runaway, `nrand=0`). Now matches native (`0x147734`: empty → writer
  `[x19]=3, ret 0`), so the next `ldr w8,[x19]; cbnz → 0x100318` exits.

After: `status: exit-clean steps: 734 nrand: 0`, 16 field-sink emits + 3
queue emits, hotspot `0x1002xx` field tail. I.e. the field loop
(`0x100114..0x100228`: sink `ctx[0x20+i*8]`, `rev` BE, tag&3 tails —
re-proven by `final_fieldloop.py`: 11 descs = 62 dw in → 48 dw out) completes
into per-field sinks, and execution stops at the **first queue-merge POP
that native would have filled** — the fill's PUSH sequence (MKITER/counter
loop just before) is where our register/branch tracking diverges. Remaining
for named-field map (which of dwords 4–47 = H[0..7], SHA-1[0..4],
timestamps, env verdicts): trace that merge fill + `0x146ed8` offset roles +
`0xbb548` concat order against the 38-pair corpus. No key, no cipher, no
device needed — pure serialization trace.

## 5. What "decrypted signature(192B)" means now (honest)

| bytes | state |
|---|---|
| 0–15 header (4 dw) | **DECRYPTED**: `Random3(sec)` regenerable, invertible to exact second (38/38) |
| 16–191 body (44 dw) | **PARSED, not field-mapped**: BE dword stream, proved time-independent, H-whitened, ns+env-entropic; per-dword attribution (H vs digest vs stamps vs verdicts) pending the §4 merge trace |
| `adj_verification` | **DECRYPTED**: `{"os_name":"android"}` (XOR `Quoh8uafohgh7CahM2h`) |
| full offline forge | structurally possible (no TEE key needed — H is borrowable opaque tag), gated on the §4 trace |

Validation corpus stands ready: 4 SAZ (server-accepted) + 34 oracle + 22
H-paired. Next run: fixed merge trace → per-dword field labels → Python
forward VM → byte-exact match on all 38.

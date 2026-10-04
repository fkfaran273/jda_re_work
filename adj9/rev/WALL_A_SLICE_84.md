# Wall A - slice 84: taint probe - 0/44 verifiable; #0's tiled shape (2026-09-13)

Follows slices 81-83 (live 200s). This slice measures the two things
those slices asserted, and pins down #0's actual content.

## 1. Differential taint probe (`rev/taint44.py`, `taint44_out.json`)

Method: 48/48-validated executor, 6 runs (baseline + 5 single-input
probes), diff slot-0 output window [0..48). Baseline reproduced the
captured blob; header [0..4) never moved in any terminating run
(method sanity OK).

| probe | body dwords changed | termination |
|---|---|---|
| claims swap (moto g42->g43) | all 44 | exit-clean, same 9,871,985 steps |
| #2 (1 dw) random | all 44 | exit-clean, same steps |
| #0 (36 dw) fully random x2 | all (header too - never emitted) | **12M-step cap, no exit** |
| H (8 dw) random | all (header too - never emitted) | **12M-step cap, no exit** |

**Measured: 0 of 44 body dwords are known-only** - every transmitted
dword is value-tainted by claims AND by every unknown input. No
per-position strict verification exists for anyone. (Confirms slice 83
by measurement instead of argument.)

**Refinement of slice 82's zero-filled #0**: termination is a ROUTING
property, not a server property. Zeros route (clean exit -> accepted
200 live); fully-random #0/H do not terminate (12M steps) - which is
presumably why sign_fresh.py zero-fills. Real captured values route.
So the practical rule stands: #0 = zeros(+entropy dword) or captured;
H = captured. "Random everything" is not craftable offline at all.

## 2. #0's real shape (fin_descs.json, the 48/48 session)

The 36-dword core record is NOT 36 words of entropy:

```
#0 = 13271271 | db50f44c b63798cc dab7f51a b7d0992b  (tiled to 36 dw)
      dword0    \_____ 4-word cycle repeated 8.75x _____/
```

Verified: `all(w[i] == w[1+(i-1)%4])`; the 48/48 recompute consumed
exactly these values. True per-signing surface: <= 5 dwords (leading
word A + 16-B block B). Consistent with slice 80's varying scalars
(0x59521d1d / 0x3465d635 / 0x77dbc67c = A/B-words of other sessions;
"dword35 varies" was each session's last tiled B-word). Since the
server accepted zero-filled #0 (slice 82), A/B are client-side
uniqueness state, not verification material.

Open (one cheap capture): does B vary signing-to-signing?
`device/get0.py` + `get0.js` dump struct+0x50 (144 B) per signing at
VM entry AND fieldloop head - blocked by USB drop; run when phone
returns: `python device/get0.py`.

## 3. Generator (`rev/adj9_sign.py`) - fixed + re-verified

- Bare invocation = CONTROL: now defaults --second to the captured
  second, prints `48/48 BYTE-EXACT == captured blob` (verified).
- os_version swap made equal-length (`12com.penti.app` ->
  `11com.penti.app`); dynamic SAZ run no longer skips it and
  reproduces the real S1 header 40c8114d3f66c6da1f0f75727e1c44e6 at
  second 1788856523, exit-clean.
- `--H random` downgraded in the docstring sense: cannot yield a
  terminable program (see 1); H must be captured.

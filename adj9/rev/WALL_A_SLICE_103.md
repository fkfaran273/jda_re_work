# Wall A — slice 103: descriptor `#4` is NOT `H` — the mislabel that corrupted every "H" experiment

Date: 2026-09-18. Method: fully offline, against the authoritative pairing in
`rev/wh4_records.json` (`mac_doFinal` = the real `Mac.doFinal` output that the SDK
hands to `nSign` as `arg3`). Scripts: `rev/h_ident.py`, `rev/h_ident2.py`,
`rev/h4_derive.py`, `rev/h4_vs_H.py`.

## 0. Headline

`OPS_LIFT.md` labels descriptor `#4` as "**H (TEE-HMAC, arg3), 32 B**", and every
"H" experiment in the campaign (H-random, H-borrowed, H-constant, H-freshness)
manipulated that slot. **The label is wrong.** `#4` is a *structured, non-uniform
32-byte record*; the real `H` is a *uniform* 32-byte MAC that **never appears in
the blob and is not needed to compute it**.

## 1. Measured (all offline, reproducible)

```
golden #4 = 00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e
golden H  = eebe704e53a5cd3dad5fbf42cbb5ef9603e5c0c89be93fb846e95081ab56fb9b
```

| test | result |
|---|---|
| `fin_descs[#4]` ∈ captured-H set (`wh4_records.mac_doFinal`, 4 distinct values of 32 B) | **False (0/1)** |
| any of the 10 harvested `all_signings` `#4` ∈ captured-H set | **False (0/10)** |
| any of the 3 `desc_det_result` `d4` ∈ captured-H set | **False (0/3)** |
| any captured H occurs anywhere in the golden 192-B blob | **False** (`blob.find(H) == -1`, 8/8 — matches `h_crack.py`) |
| is `#4` a simple transform (rot/reverse/word-swap) of a captured H | **NONE** |
| is `#4` a digest (MD5/SHA-1/256/512/CRC32, 10 variants) of sign_input / canonical / claims / H / second | **0 hits** |

Uniformity, side by side:

```
captured H byte0 alphabet : {62, 65, 8f, e6, ee}   <- uniform, as HMAC-SHA256 requires
harvested #4 byte0 alphabet: {00 x8, 02, 04}        <- and 29/256 always-zero bits
```

## 2. The clincher: the blob needs no H at all

`fin_descs.json` holds **11 descriptors and no H**, and the VM reproduces the
golden 192-B blob **48/48** (`desc_bisect.py` control arm: `exit-clean`,
9 871 985 steps, `diff=0/48 IDENTICAL`).

⇒ **`H` is not an input to the blob computation.** `blob = f(#0..#10)`, full stop.
`H` (`nSign` arg3) is something else — argued about since slice 84 on the
assumption that it was the `#4` slot.

## 3. The consequence, measured (`h4_vs_H.py`)

`adj9_forge.make_signature_map()` writes `by[4] = (8, h_input)`, and callers pass
`H` there (`--H random`, borrowed H, the H-constant arm of slice 92 §5). So those
arms put a **uniform MAC into the structured `#4` slot**. Measured effect:

```
#4 = captured structured record (device) : exit-clean  9871985 steps  == golden blob
#4 = the REAL H (maker's slot)           : exit-clean 16117703 steps  law=OK  diff=44/48
```

A real `H` in `#4` yields a **different blob in 44 of 48 dwords**. So every
crafted blob in the "H" experiments was structurally incapable of matching a
device blob in that slot — and its Organic answer carries **no information about
H** whatsoever.

## 4. Claims retracted or corrected by this

| # | claim | correction |
|---|---|---|
| 1 | "`#4` = H (TEE-HMAC, arg3), 32 B" — `OPS_LIFT.md` §2; `ADJ9_VALIDATION_MODEL.md` §1 | **WRONG** — `#4` is a structured record; H is elsewhere and is not a descriptor |
| 2 | "H random / #0 random → VM does not terminate" — slice 84 §1 | **MISLABELLED** — those arms randomized `#4`/`#0`, not H. (And re-measured this session: `#4 <- zeros`, `#4 <- foreign #4`, `#0 <- zeros` are all `exit-clean`.) |
| 3 | "`#4` = [8-B structured head][24-B opaque **MAC** tail]" — slice 99 §4 | **VOID as a MAC statement** — there is no MAC in `#4`. The structure is real; the interpretation as "a signed record / keyed function" is not supported. |
| 4 | "H freshness is not checked / a borrowed H passes / H must be captured" — slices 82/84/92 §5 | **UNINFORMATIVE** — all these arms varied the wrong slot |
| 5 | "the 32-byte MAC is not inside the blob" — `h_crack.py` | **CONFIRMED and explained**: H is not a blob input at all (§2) |
| 6 | "key2 (TEE) is the wall for a pure-Python signer" — `PYTHON_REMAINING.md` §A.3, `adj9/TASKS.md` | **NOT the wall for generating the blob** — the blob does not depend on key2/H |

## 5. So what IS the blocker now?

Exactly two per-call descriptor values remain non-derivable, and **neither is
cryptographic**:

| slot | nature | evidence |
|---|---|---|
| `#2` | 1 dword, per-call; no derivation found | slice 99 §2; `#2`-derivation battery all miss |
| `#4` | 32 B **structured** record, per-call; all 10 heads distinct; bit-density increases across dwords (popcount 2,4,5,8,9,13,12,18 → 71/256 bits) | this slice |
| `#0` | 7 heap + 4 MTE-tagged **pointers**; zeros proven acceptable (200) | slice 85, slice 82 |

`key2` / `H` are **not** on that list. `#4` is non-cryptographic, small-alphabet,
bit-flag-like, and per-call — the most derivable-looking target left, and the
only one whose derivation is not blocked by a hardware boundary.

**Also note** `desc_bisect.py` proved every single-descriptor arm is `exit-clean`
with a valid header law (including `#4 <- zeros`), so the `#4`-derivation work and
the server-side input-space bisection are both immediately actionable.

## 6. Next

1. Derive `#4` (and `#2`) from the signing's own material — the battery here
   excluded digests and simple transforms; the bit-structure (increasing density,
   tiny byte alphabets in bytes 0–7) suggests a bit-packed flags/counter record,
   so test enumerative/bitfield hypotheses rather than hash hypotheses.
2. `#4`-first server bisection: send golden + `#4`-arms (`zeros`, `foreign #4`,
   real-H-in-#4 as the maker did) with a byte-identical claim set. Since a real-H
   `#4` is measurably 44/48 off the device blob, this directly quantifies what the
   server tolerates in the one slot the maker has been getting wrong.
3. Fix `adj9_forge`: rename `H=` to `d4=` (or `#4=`) so no future arm passes a MAC
   into `#4`; keep the captured `#4` as the default.
---
title: WALL_A_SLICE_126
---

# SLICE 126 — claim-layout hypothesis tested; the offline hypothesis space is exhausted

## 0. What was tested

`rev/geom_probe3.py`: for all 10 real signings, locate the recognisable anchors inside the
(separator-less) claim string and test them against the region:

```
i   len   uuid1  uuid2  nU  iso_off  ver_off  afterIso  #2
0   504   28     136    2   84       78       391       41aa16f5
3   532   28     137    2   84       78       419       6b157640
4   360   28     136    2   84       78       247       2ecacaaf
8   388   28     137    2   84       78       275       7c933329
…  (9 of 10 identical in every anchor except the varying-length tail)
```

Tested as dwords, 16-bit halves, bytes, set-bit positions, and folds — **no consistent
encoding**: the only "hits" are single-byte coincidences with small numbers that are present
in every sample's geometry set (2, 10, 28), and they do not align to the same field across
samples (e.g. rows with `uuid2=136` vs `137` show no corresponding change anywhere in the
region). `rev/geom_probe3.log`.

The earlier, malformed attempt (`geom_probe.py`) also produced a useful correction:
**`#10` is a separator-less concatenation of claim VALUES** in the law's key order
(`token(28) + uuid(36) + "31" + app_token + app_version + created_at + …`), which is exactly
what `desc10_law` builds — so the law's construction is confirmed from a third direction.

## 1. The exhausted list (all measured, none repeated)

For the 56-byte region (`#0` 20 informative bytes, `#4` 32 B, `#2` 4 B):

| family | result |
|---|---|
| `Random3(second)` output (raw / xor-pair) | 0 hits |
| generated from `W0` as seed (`Random3`, `rand()`, `rand_r`) | 0 hits |
| crc32 / adler32 / fnv1a / Java-hash / md5 / sha1 / sha256 / blake2 of claims, `#0`, `#4`, `#7`, tile | 0 hits |
| HMAC-SHA256/SHA1 of (H,claims), (claims,H), (H,second); SHA256 of concatenations | 0 hits |
| any slice of `H` at any 4-byte offset | 0 hits |
| `X = E ^ K` and `X == E` for 96 expressions over `H` words (single, reversed, rotated, XOR/ADD of two) | 0 hits |
| constant relations **among** the unknowns (91 pairs × XOR/ADD/SUB) | 0 hits |
| claim-layout encoding (offsets/lengths of recognisable fields) | 0 consistent hits |

⇒ The region is **per-call keyed material produced inside the recursive builder**
(`sub_9afa4`: `eor word, word, key-register` ×4 → `eor v0.16b` → `str q`, keys from a
`mov/movk` table — slice 124), i.e. `region = plaintext ^ keystream` where the keystream is
per-call and internal. That is exactly why every output-side relation fails: a per-call
keystream destroys XOR/ADD structure, digests don't apply, and the plaintext (likely process
state — slice 115 read `#0` as heap/MTE-pointer-shaped) is not in the request.

## 2. What this means for the goal, stated plainly

The blob is keyless on the wire (slice 125: no MAC is transmitted), and its region cannot be
recomputed from anything the request contains. Therefore the offline signer can only be
completed by **reading the builder** (Path B) or by **capturing a complete descriptor set
from an app signing** (Path A) — there is no remaining output-side shortcut, and that is now
demonstrated rather than assumed.

* **Path A** — needs one working injection route (attach is refused with `ptrace pokedata:
  I/O error`; frida-spawn loses the process ~2–4 s after resume). Options recorded in
  `rev/REMAINING_WORK.md` §4: clean-boot + first-launch attach (it worked twice earlier:
  `pid=9410`, `pid=22668`), frida-gadget repackaging, or the SDK's event path.
* **Path B** — reduce `sub_9afa4` (3072 insns, recursive, 21 calls, 32 `eor`, 4 `str q`) with
  `rev/dump_at.py` and use `pair_h3.json`'s 6 rows as the correctness oracle.

## 3. Artifacts

- `rev/geom_probe3.py` + `geom_probe3.log` — anchor/layout test on the 10 signings
- `rev/geom_probe2.py` + `geom_probe2.log` — the (malformed) first attempt + the `#10` format correction
- `rev/WALL_A_SLICE_124.md` (builder structure), `rev/WALL_A_SLICE_125.md` (no MAC on the wire)
- `rev/REMAINING_WORK.md` — handoff, device runbook, both paths
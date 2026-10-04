# The key2 / arg3-H theory is REFUTED

**Date:** 2026-09-24
**Supersedes:** the actionable half of `KEY2_H_RESULT.md`

## Verdict

H (the 32-byte HMAC-SHA256 under the TEE `key2`) never influences the 176-byte
body. The envelope is a pure function of `(signing second, claims, cert)`.
Since our Python mint already reproduces the app's blob **byte-exactly**, the
adj9 signature is NOT the organic/non-organic gate, and wiring H into `FinEx`
would have been wasted work on a wrong premise.

## Three independent lines of evidence

### 1. Descriptor #4 is not H (`h4_vs_H.py`, `WALL_A_SLICE_103/112.md`)

Same-signing pairs show descriptor #4 is a structured native record:

```
#4 = 00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e
H  = eebe704e53a5cd3dad5fbf42cbb5ef9603e5c0c89be93fb846e95081ab56fb9b
```

Neither equal, nor a prefix/suffix relation. Replacing #4 with the real H
produces a different blob than the golden one.

### 2. H reaches the builder but not the body (disassembly trace)

`nSign` is at VA `0xdb1cc`. JNI mapping: `x0`=JNIEnv, `x2`=Context, `x3`=map,
**`x4`=H**, `w5`=SDK int. H is preserved at `0xdb214 stur x4, [x29, #-0x58]`
and reaches the builder via `0xdb24c bl #0x95fc4`, and is observed as `x3` at
the VM call `0xfb64 bl #0x8d6f4`.

But the final assembly call `0xdbb64 bl #0xbb548` passes:

| reg | value |
|---|---|
| x0 | `[x29-0x60]` status cell |
| x1 | JNIEnv* |
| x2 | saved map |
| x3 | static `0x154870` |
| x4 | `sp+0x40` output struct |

**No H pointer in any argument register.** Any H influence at this stage would
have to be indirect via state produced earlier — and line 3 shows it is not.

### 3. Decisive: the region is a pure function of `d2` (`h_invariant_test.py`)

The region law is `d2 = LE-store(seed)` read BE, `d4 = f(seed)`, `d0 = g(d4)`.
Since `d2` is 4 bytes and fully determines `seed`, if `d4`/`d0` are recoverable
from `d2` alone then descriptor #4 carries no information H could supply.

Result on the 6 verifiably self-consistent capture rows:

```
[ 0] seed=f516aa41  d4 MATCH  d0 MATCH
[ 1] seed=12b21e6b  d4 MATCH  d0 MATCH
[ 4] seed=afcaca2e  d4 MATCH  d0 MATCH
[ 5] seed=985f5c11  d4 MATCH  d0 MATCH
[ 6] seed=6a896959  d4 MATCH  d0 MATCH
[ 7] seed=96821afb  d4 MATCH  d0 MATCH

d4 recoverable from d2 alone: 6/6
d0 recoverable from d2 alone: 6/6
```

Six different H values, all six reproducing perfectly from a 4-byte seed. The
32-byte descriptor is 100% redundant with `d2`.

## Side finding: `pair_h3.json` rows 2 and 3 are mispaired

Found while validating the above. Rows 2 and 4 both recorded blob `211c2cd4…`
with identical `log`, `nsign_ts`, `second`, and `H`, but different `d0/d2/d4` —
which is impossible, since identical blobs cannot yield different correct decodes.

Cause: `pair_h3.py:96` copies `d0/d2/d4` from `all_signings.json` while pairing
the blob by header timestamp. `reempair.py` then patched only rows `i in (2,3)`
— row 4 kept a blob it does not own.

`audit_pairs.py` settles it by asking FinEx directly whether each row's own
descriptors at its own second reproduce its recorded blob:

```
[ 0] -> exact        [ 4] -> exact
[ 1] -> exact        [ 5] -> exact
[ 2] -> nomatch      [ 6] -> exact
[ 3] -> nomatch      [ 7] -> exact

self-consistent rows: 6/8
mispaired rows      : [2, 3]
```

So the true figure is **6/8 byte-exact, not 8/8**. The six good rows are more
than enough for the H-invariance result, which is why the conclusion stands.

## What this means for the Organic problem

`arm_transport2` sent a byte-identical envelope over the device's own network,
from the device's own GAID, after the device's own click, at the real CTIT — and
still came back Organic. Combined with this result, the envelope is exonerated.
The difference between the app's non-organic install and our Organic one is
**outside the 192 bytes**: it is in the request — params, headers, or ordering.

Next target: field-by-field diff of a real app request against ours
(`attrq2.txt` is the app capture). The open blocker is still obtaining the
app's live traffic, since mitmproxy's CA is rejected by the app's TLS.

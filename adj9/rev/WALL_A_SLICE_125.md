---
title: WALL_A_SLICE_125
---

# SLICE 125 — the server's only input is the blob (no MAC is ever transmitted)

## 0. The measurement

`rev/auth_probe.py` and `rev/hdr_shape.py` parse every `authorization_header` block in
`device/adj9_wh4.log` and align it with the `nsign` blobs and the `nsign_in` MACs:

```
authorization_header=8  nsign=8
ts=1789240076149  blob=211c2cd4236fbed8 n=192  signing_id=1500000 headers_id=10 nver=5.0.0 verif=KlcAG2cbAAsKSl1KVi0FGiJbDHMI  ==nsign:True
ts=1789240076576  blob=380195de2110d57b n=192  …                                                                ==nsign:True
ts=1789240079874  blob=0374b81c29e848f4 n=192  …                                                                ==nsign:True
ts=1789240229309  blob=505f30c74f92913e n=192  …                                                                ==nsign:True
ts=1789240229915  blob=38cbb1815f6c3ba0 n=192  …                                                                ==nsign:True
ts=1789240340853  blob=61c5008a6fe93390 n=192  …                                                                ==nsign:True
ts=1789240341333  blob=2b2d9e8b3fa5df42 n=192  …                                                                ==nsign:True
ts=1789240514239  blob=5595c3c431567e63 n=192  …                                                                ==nsign:True
distinct adj_verification values: 1
```

The exact header form is:

```
Signature signature="<192-byte blob, base64>",adj_signing_id="1500000",algorithm="adj9",
          headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
```

## 1. What this closes

| question | answer |
|---|---|
| is the keystore MAC (`H`, `nsign_in.arg3`) transmitted? | **no** — not as hex, not as base64, in any header field |
| is the blob sent verbatim? | **yes** — the header's base64 decodes to the exact 192-byte nsign output for every aligned signing |
| do the envelope fields vary? | no — `adj_signing_id="1500000"`, `algorithm="adj9"`, `headers_id="10"`, `native_version="5.0.0"` are constant |
| does `adj_verification` vary per signing? | **no** — one value in all 8 blocks (`KlcA…DHMI`, 28 chars); it is the same token the server returns and the app echoes back, and it is the prefix of the canonical claim string |

⇒ **The server has no keyed material to verify.** It receives a *keyless* 192-byte blob whose
construction is a pure function of state the server cannot recompute, plus constant envelope
fields and the request's own claim parameters. Therefore its acceptance test can only be:

1. **stored-artifact matching** (the bytes must equal what the device once sent for that
   identity), or
2. **structural/self-consistency checking of the blob** (it is a self-describing
   serialization: `[len_B][len_dw]` sections — slice 121 — with the claim data inside), or
3. some combination (structure for first-seen installs, artifact match afterwards).

That matches every measurement in the campaign: genuine bytes → recognised (even when sent
from Python, `py_ladder` A0); any 1-bit change → not recognised; our re-mints (whose claim
set was both wrong *and* whose region was not the device's) → not recognised.

## 2. Consequence for the pure-Python goal

The 56-byte region (`#0` 20 informative bytes, `#4` 32 B, `#2` 4 B) is the **only** unknown
left, and this slice proves the server cannot be verifying it cryptographically — so either

* the region is *not* checked at all and the real gate is the claim set + envelope (in which
  case our crafted blobs should have worked once the claim set matched — they did **not**,
  slice 111 A1), or
* the region *is* part of what the blob must contain for the server's structural check
  (e.g. the sections' lengths/offsets must describe exactly the claim set that was sent).

The second reading is the one consistent with all evidence, and it is testable **offline**:
`pair_h3.json` gives 6 signings with `(claims, H, second) → #0/#2/#4`; the sections are
already understood (`[len_B][len_dw]` + content). The next concrete test is to check whether
the region's words can be *recomputed from the claim-string geometry*
(key lengths / value lengths / offsets of each claim in `#10`) — a hypothesis that has never
been tried, unlike PRNG/digest/H-transform which are all ruled out.

## 3. Correction discovered while testing the geometry hypothesis

`rev/geom_probe.py` was written to test "is the region derived from the claim-string
geometry?" — but the first run returned `entries=0` for every sample, because **#10 is not a
`key=value` list at all**: it is a *separator-less concatenation of the claim values* in the
law's fixed order. Sample 7's 360 bytes decode as:

```
KlcAG2cbAAsKSl1KVi0FGiJbDHMI        <- 28-char verification token (== header adj_verification)
d773f47f-fc0e-4994-9cf7-7c3cf5bb6368 <- android_uuid, 36 chars, no separator
31                                   <- api_level ("31")
jut9tib0eeps                         <- app_token
3.13.9                               <- app_version
2026-09-12T21:15:11.678Z+0200        <- created_at
moto g42 / phone / production / …
```

So `desc10_law`'s concatenation IS the real format (that is why it reproduces all 10 captured
variants byte-exactly), and any geometry test must segment the string using the law's key
order + the map, not by splitting on `=`/`,`.

That makes the geometry hypothesis **testable but not yet tested**: segment with
`desc10_law`'s order on a signing whose map is known (our own `wh_out.json` mint, where we
have both the map and `#0/#2/#4`), and cross-check any pattern against the 10 real samples.
It is the last untried family, and it fits the evidence: the region is unrelated to
`H`/`second`/digests, is not self-consistent under XOR, and the builder is a recursive walk —
i.e. a structure derived from *positions/sizes of the claims as laid out*, not from their
contents.

## 4. Artifacts

- `rev/auth_probe.py` + `auth_probe.log` — header vs nsign vs H alignment
- `rev/hdr_shape.py` + `hdr_shape.log` — per-signing header structure, blob match, token constancy
- `rev/geom_probe.py` + `geom_probe.log` — the geometry run that exposed the format correction
- `rev/WALL_A_SLICE_121.md` (sections), `rev/pair_h3.json` (6 clean rows), `rev/REMAINING_WORK.md`
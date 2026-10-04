---
title: WALL_A_SLICE_142
---

# SLICE 142 — the word gate: only 4/48 blob words are server-verifiable (decisive)

Date: 2026-09-21. Fully offline, one FinEx comparison. Scripts: `rev/blob_word_gate.py`
(+ `bwg.log`), `rev/find_pair_blobs*.py`, `rev/extract_wh4_blobs*.py`,
`rev/find_same_second_pair.py`, `rev/_tmp_pair.py`, `rev/_row9_check.py`.

## 0. The experiment

The campaign had the exact control needed all along and never ran it:
**`desc_det_result.json` rows 0 and 2 share sec=1789240512 AND byte-identical 360-B
claims, but have different regions** (slice 104/128: `d2=fb1a8296` vs `d2=4bce691e`,
different `#0/#4`). FinEx both descriptor sets at that second:

```
SAME words (4/48): [0, 1, 2, 3]
DIFF words (44/48): [4..47] — every body word differs
  [0] 5595c3c4  [1] 31567e63  [2] 1a7bf9b9  [3] 58dabea7  (the header)
```

`word_gate.json` holds the full 48/48 map.

## 1. What this closes — the user's question, answered by measurement

> *What does the Adjust server verify in the signature, given it cannot see key2 —
> and why don't we recover #0/#2/#4?*

**The body is 100% region-driven: 0 of 44 body words are recomputable from
(claims, second).** Combined with the established facts:

* H (`HMAC-SHA256(key2, canonical)`) is **not** a blob input (slice 103: blob =
  f(#0..#10), FinEx reproduces 48/48 with no H),
* no MAC is ever transmitted (slice 125: the 192-B nsign blob is sent verbatim;
  `nsign_in.arg3` never crosses the wire),
* the body contains no digest of the claims (this slice's battery: 0 hits for
  sha256/sha1/md5/sha512/blake2s/crc32/adler32 of claims, padded/trimmed — 
  `rev/digest_in_blob.py`),

...the server's verdict gate **cannot be a content check of the body** — there is
nothing in it the server could recompute, for a genuine signing or a crafted one.
The 4 header words are the only server-verifiable content, and they are
`Random3(second)`, i.e. public.

This does not change the operational conclusion (a crafted-created install reads
Organic, even to the app — the gate is real), but it bounds WHAT the gate can be:
it must be keyed on something else the request carries or doesn't carry —
transport/provenance (H1/H2/TLS arms all negative), the app's own SDK lifecycle
(the only positive, 11/11), or stored-history matching — never on proving the
44 body words correct, which is mathematically impossible for anyone without the
per-call region.

## 2. Row 9 correction (corollary)

Row 9's "6th distinct word" is not an extra tile word: its `#0` is
`[W0][P][T0 T1 T2 T3]×8 + [T1 T2]` where `P=9949bda6` is a one-off preamble word
(zero XOR relations to any row-9 word). Its bridge `a[6]=205f123f` satisfies the
corrected law `(R_K13<<16)|Xlo` exactly, so the 15/16 row coverage from slice 141
holds (row 9 included).

## 3. Artifacts

* `rev/blob_word_gate.py` + `bwg.log`, `rev/word_gate.json` (4 SAME / 44 DIFF)
* `rev/find_pair_blobs.py` + `blob_by_sec.json` (185 seconds covered; the pair's
  second carries only the golden blob in the header pool — entry 2's blob was
  reconstructed by FinEx, which is exactly the test)
* `rev/extract_wh4_blobs2.py` + `rev/wh_blobs2.json` (201-header + 201-nsign pool)
* `rev/blob_anatomy.py` / `blob_anatomy2.py` + logs (blob lives in seg 90 as a
  48-word stream, assembled from seg 64–68 intermediates — outputs, never inputs)
* `rev/digest_in_blob.py` (0 digest hits), `rev/find_same_second_pair.py`

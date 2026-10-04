# Wall A — slice 106: FinEx verified byte-exact on 6 independent device signings (incl. `push_token`)

Date: 2026-09-18. Scripts: `rev/corpus_e2e.py`, `rev/corpus_pair_audit.py`;
logs `rev/corpus_e2e.log`, `rev/corpus_pair_audit.log`.

## 0. Headline

The emulator's byte-exactness was previously established on **one** signing (the
360 B session golden). It is now established on **six independent device
signings**, including **two that carry a `push_token`** — which verifies the
descriptor path slice 105 discovered, end-to-end.

```
=== end-to-end VM reproduction per captured signing ===
  als[0 ] session token #10=504B sec=1789239390 status=exit-clean steps=10493669 BYTE-EXACT
  als[1 ] session token #10=504B sec=1789239528 status=exit-clean steps=10493669 BYTE-EXACT
  als[4 ] session plain #10=360B sec=1789240075 status=exit-clean steps=9871985  BYTE-EXACT
  als[5 ] session plain #10=360B sec=1789240228 status=exit-clean steps=9871985  BYTE-EXACT
  als[6 ] session plain #10=360B sec=1789240340 status=exit-clean steps=9871985  BYTE-EXACT
  als[7 ] session plain #10=360B sec=1789240512 status=exit-clean steps=9871985  BYTE-EXACT
```

Four plain sessions at **four different seconds** plus **two token sessions** —
same `ORDER`, same constants, no per-signing tuning.

## 1. Pairing, made unambiguous

`corpus_pair_audit.py` (no VM runs) shows the claim structure:

```
=== blob claims ===
  sec=1789239390  blob=1fcd5ee7…  UNIQUE       samples=[(0, '#10=504B')]
  sec=1789239528  blob=5b71ec7c…  UNIQUE       samples=[(1, '#10=504B')]
  sec=1789240075  blob=211c2cd4…  UNIQUE       samples=[(4, '#10=360B')]
  sec=1789240228  blob=505f30c7…  UNIQUE       samples=[(5, '#10=360B')]
  sec=1789240340  blob=61c5008a…  UNIQUE       samples=[(6, '#10=360B')]
  sec=1789240512  blob=5595c3c4…  SHARED by 3  samples=[(7,'#10=360B'), (8,'#10=388B'), (9,'#10=360B')]
  NO BLOB: samples [(2, '#10=504B'), (3, '#10=532B')]

unambiguous pairs: 5
ambiguous (own blob absent): als[8] (click 388B), als[9] (session 360B)
```

Pairing is by the **header law** (`make_header(ws-2 .. ws+3)` looked up in the
143-blob index built from `adj9_wh.log` + `adj9_wh2.log` + `adj9_wh4.log`), not by
a loose time window — an earlier loose version mispaired three samples onto the
golden blob, which is exactly the trap this audit closes.

**als[7] is the true owner** of blob `5595c3c4…` (it is the `fin_descs` golden and
was verified byte-exact before), so the verified set is als[0,1,4,5,6,7] = **6**.

## 2. What is verified, precisely

| path | status |
|---|---|
| session, 360 B, plain | **verified ×4** (4 distinct seconds) |
| session, 504 B, **with `push_token`** | **verified ×2** |
| click, 388 B | **unverified — no paired blob in the corpus** (not a failure) |
| click+token, 532 B | **unverified — no blob** |
| session/click, other seconds | unpaired (als[2], als[9]) |

Step counts are informative: plain sessions settle at **9 871 985** steps, token
sessions at **10 493 669** — more work for the longer `#10` (126 dwords vs 90),
and identical across the two token signings. als[9] runs **9 878 275** steps, a
third profile, so it is genuinely a different signing rather than a second view
of als[7].

## 3. Why the token result matters

Slice 105 proved the `push_token` claim is part of the signed claim set and that
the law + NUL padding reproduces the 504/532 B `#10` **bytes**. This slice proves
the **VM consumes that descriptor correctly** and lands on the device's own blob.
Together they mean a token-bearing map can be signed with a claim set and `#7`
that are correct by construction:

```
raw  = desc10_law.build_desc10(val, kind)        # law, token included if present
desc = raw + b'\0' * (-len(raw) % 4)             # descriptor #10
#7   = len(raw)                                   # UNPADDED length
```

i.e. `adj9_forge.claims_for_law(val, kind)`.

## 4. Remaining gap in the verification (honest statement)

The **click** path (387/388 B and 529/532 B) is not verified end-to-end because no
EMIT trace in the corpus is paired with a stored click blob: the only click blob
in the wh4 session (nsigns[1], [4], [6] = `380195de`, `38cbb181`, `2b2d9e8b`) sits
at other seconds (1789240076 / 1789240229 / 1789240341) and the corresponding
signings' descriptors are not in `all_signings`. Closing it needs one EMIT trace
covering a click signing whose blob is also recorded — a single device capture,
not an offline task.

## 5. Files

| file | role |
|---|---|
| `rev/corpus_e2e.py` / `.log` | header-law pairing + per-signing VM reproduction |
| `rev/corpus_pair_audit.py` / `.log` | claim-structure audit (no VM), proves which pairs are unambiguous |
| `rev/corpus_e2e_result.json` | machine-readable per-signing results |
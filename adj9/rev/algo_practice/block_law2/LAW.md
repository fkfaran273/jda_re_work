# block_law2 — SOLVED: the 32-byte block `record[46:78)` (sink words 11..19)

## The law (pure Python, no VM)

```python
SHA0 = sha256(b"").digest()

IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"     # VM hardcoded
                    "7a30ed9323473054bbe3cd00f1355ea5")    # chaining value

# msg  (descriptor #9 || record[1:19] || d2 || SHA256("") || 17 B const || #10)
msg  = record[25:45]              # D9 = APK certificate SHA-1 (descriptor #9)
       + record[1:19]             # 00 08 || the 16-byte d0 head
       + struct.pack("<I", S)     # S = BE32(record[20:24]), stored little-endian
       + SHA0                    # 32 B
       + b"\x01" + b"\x00"*16    # = record[112] || record[114:130]
       + claims                  # descriptor #10, UNPADDED

block = sha256_with_IV2(msg)      # standard SHA-256 padding + standard SHA-256
                                  # round constants, chained from IV2, not the
                                  # standard SHA-256 IV
```

`sha256_with_IV2` = the normal SHA-256 compression function (the VM's own
SHA-256 program, ~272 878 VM steps per 64-byte block) with the initial state
replaced by `IV2`. Implementation: `predict_block.py::sha256_iv2`,
`predict_block(claims, S, head16, d9)` /
`predict_block_from_record(record, claims)`.

**It is not SHA-256, not HMAC and not the digest law.** The only deviation from
FIPS-180-4 is the chaining value.

## Validation — 16/16 byte-exact, zero VM

| set | n/N | notes |
|---|---|---|
| A) VM probes `r0..r5` (`../probes/`) | **6/6** | the block is byte-identical for `second`+1/+2 (r1/r5) and changes for S (r2/r4) and for one claims byte (r3) — exactly the dependence the earlier probe study reported |
| B) 6 genuine penti winning blobs (`../../win_capture/`) | **6/6** | session, click and attribution kinds, two devices/uuid sets; claims rebuilt from the capture's own `sign_input map_order` |
| C) creditsea gold (`../../creditsea/`) | **1/1** | the only vector with a stored claims map (`gold_session.json`); its other two vectors store no claims map |
| D) fresh VM confirmations (`confirm_vm.py`) | **3/3** | claims lengths 359 / 361 / 365 with the same seed — proves the padding and bit-length rule on lengths that are not multiples of 4 |

`python validate_block.py` runs A/B/C (exit 0), `python confirm_vm.py` runs D.

## Provenance — how it was found

All step numbers are the synthetic r0 run (`second=1790625704`, `S=a6da5d2b`,
9 871 985 steps); the tool is `block_prov.py` (adapted from
`digest_law/digest_prov.py`, same `FinEx.run` rewrite: force `_fast = True`,
gate the step hook on a window, patch stores).

1. **`block_trace.md`'s "pure copy" is the last hop only.** The block is
   `BE(M[11])[2:4] ‖ BE(M[12..18]) ‖ BE(M[19])[:2]` read by `LENQ` at
   pc `0x11930c` (steps 2828853 … 2835373). Those 9 dwords are *record bytes
   [44:80)* re-serialised, so the block window contains no arithmetic — the
   question is what produced them.
2. Chasing the first writes of the 9 dwords backwards through
   `digest_law/digest_emits.json` (22 272 emits with step numbers) they first
   appear at **steps 2768429 … 2784654, stream `0x5450001000` idx 352..360**,
   assembled byte-by-byte (`byte << 24`, `OR`-ed in; `EMIT` w2=352 with
   `bd000000`, `bd040000`, `bd042700`, `bd0427e3`).
3. The dwords' real origin is **step 2741180, idx 65..72** (183 steps apart).
   `blockprov_2739900_2741300.txt` shows the exact computation of the first
   one:

   ```
   LENQ(MAIN, 0x41)  -> 342e6353      ; accumulator slot  64 + i   (i = 1..8)
   LENQ(MAIN, 0)     -> c9 = 201      ; MAIN[0], the state base
   LENQ(MAIN, 0x109) -> f3b4ef0b      ; state slot  MAIN[0] + 63 + i
   add -> 27e3525e                    ; == 0x342e6353 + 0xf3b4ef0b
   EMIT MAIN[65] = 27e3525e
   ```

   That is only the last `add` of a modular accumulator — the state it adds is
   produced by an 8-word sliding window at idx 265..272 (3111 steps per word).
4. **That window is a SHA-256 chain.** Grouping the writes to idx 685..692
   (`sha_state_chain.py`) shows the standard SHA-256 **IV**
   `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19`
   at steps 38208…38817 (H2 confirmed: SHA-256 IV literals are present, as
   8 `mov` immediates, exactly as `k_spy` found for the digest's K), then a
   state write every **272 878 steps** — the same ~272 k steps/compression the
   digest law measures.
5. The 8 compression states and the 8 message blocks staged at MAIN idx
   821..836 give an **exact** standard-SHA-256 chain:

   ```
   IV2 -> blk0 -> ... -> blk7 -> BLOCK
   ```

   verified `compress(IV2, m[0:64]) == s831034`, …,
   `compress(s2468302, m[448:512]) == BLOCK` (8/8, big-endian words,
   standard K constants, standard padding with a 451-byte message).

6. The 512-byte staging is `msg ‖ 0x80 ‖ 0-pad ‖ BE64(3608)` — the trailing
   length word is `0x0e18` = 3608 bits = **451 bytes**, exactly the length of
   the message reconstructed in step 5. `msg_r0.bin` is the raw capture.
7. The first message block is staged at MAIN idx 693..708 a few thousand steps
   earlier as a byte copy (`fad0f10d…`, `000869d5…`), confirming the message
   head is the D9 certificate followed by the record bytes.

## Message decomposition (r0, `msg_r0.bin`, 451 B)

| offset | bytes | content |
|---|---|---|
| `[0:20)` | 20 | D9 = APK certificate SHA-1 = descriptor #9 = `record[25:45]` |
| `[20:38)` | 18 | `record[1:19]` = `00 08` ‖ the 16-byte d0 head |
| `[38:42)` | 4 | `S` little-endian (`S = BE32(record[20:24])`) |
| `[42:74)` | 32 | `SHA256("")` = `record[79:111]` |
| `[74:91)` | 17 | `0x01` ‖ 16×`0x00` ( = `record[112]` ‖ `record[114:130]` ) |
| `[91:451)` | 360 | descriptor #10, the claims payload, **unpadded** |

## Dependence (probes r0..r5)

* independent of the signing second (r1/r5 byte-identical) — the second only
  enters via the header and the digest;
* dependent on `S` (r2/r4) through `record[20:24]`, and on the head
  `record[3:19]` (both are functions of `S`);
* dependent on the claims byte-for-byte;
* **D9 is per-build, not a constant**: `fad0f10d…` for com.penti.app,
  `06f5ffcee0541608765407ab9e0180e7b1b7e7d0` for com.creditsea.app. Always
  read it from `record[25:45]`; `predict_block.py`'s `D9` default is only the
  penti build.
* the block is the *input* of the digest law (`digest_law/LAW.md` hashes the
  whole whitened record), so both laws now compose into a full no-VM mint.

## What is refuted (H1/H3 hypotheses)

* `h1_battery.py`: **0 hits** over
  `sha256/sha1/md5/blake2s/sha512/sha3_256` × every pairwise composition of
  {claims, claims-padded, S, S-LE, d0, d4, d2, len} and over HMAC,
  digest-law two-pass, ipad-only and pad-twice forms keyed by the digest's
  hardcoded K, `S`, `d0`, `d4`, `sha256(d4)`, `sha256(S‖claims)`, … —
  0/4 probe cases. The reason is now clear: the chaining value is **IV2**, not
  the SHA-256 IV, so no off-the-shelf hash can match.
* H3 "custom byte-serial loop": the *byte assembly* is indeed a custom loop
  (`blockprov_*.txt`), but it is only the serialiser — the mixing is a stock
  SHA-256 compression function.

## Files

| file | purpose |
|---|---|
| `predict_block.py` | **the law** — `predict_block(claims, S, head16, d9)` / `sha256_iv2(msg)` / `predict_block_from_record(record, claims)` |
| `validate_block.py` | the A/B/C validation gate (exit 0 on success) |
| `confirm_vm.py` | D: fresh VM runs at odd claims lengths vs the law |
| `block_prov.py` | windowed per-step prover (adapted from `digest_law/digest_prov.py`) |
| `block_pass1.py` | pass-1 emit spy with step numbers, for any probe config → `emits_<tag>.json` |
| `sha_state_chain.py` | groups the idx 685..692 state writes, extracts the per-round message blocks, tests the compress() relations |
| `blockprov_2739900_2741300.txt/.json` | provenance of the accumulator `add` that produces block word 0 |
| `blockprov_2766400_2768600.txt/.json` | provenance of the byte-wise dword assembly at MAIN[352] |
| `msg_r0.bin` | the raw 512-byte captured SHA-256 message staging (451 B message + padding) |
| `emits_r2_seed.json`, `emits_r3_claim.json` | full emit traces proving IV2 is seed- and claims-independent |
| `h1_battery.py` | the refuted H1 battery (kept as evidence) |

## Reproduce

```
python validate_block.py      # A/B/C -> 13/13
python confirm_vm.py          # D     ->   3/3   (~45 s, 3 VM runs)
python sha_state_chain.py     # state rounds + message blocks
python block_prov.py 2739900 2741300     # re-derive blockprov_*.txt (~13 s)
```

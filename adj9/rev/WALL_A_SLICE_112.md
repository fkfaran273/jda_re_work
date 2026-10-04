# Wall A — slice 112: the per-call region is NOT derivable; the server demands the exact body

Date: 2026-09-19. Scripts/logs: `rev/gold_h.py`+`.log`, `rev/h_in_trace.py`+`.log`,
`rev/py_region.py`+`.log`, `rev/det_full.py`+`.log`, `rev/nsign_recon.py`+`.log`,
`rev/h_pair.py`+`.log`.

## 0. What was open, and what closed it

Remaining question was: *what must be computed to make a Python-signed package
recognized?* Four measurements close it.

## 1. `H = arg3 = HMAC-SHA256(key2, map_toString)` — and it is logged per signing

The device hook log (`device/adj9_wh.log`, 214 MB) contains, per signing, a
`jca_mac_doFinal` record followed **1 ms later** by an `nsign_in` record whose
`arg3_hex` is byte-identical to that MAC output:

```
jca_mac_update     ts=…137639  message = the map_toString (1297 chars)
jca_mac_doFinal    ts=…137643  out=32 → efa2f9b7afa849cd90ced890c5787848b362d86a2d1f0f66be7fa261fffbafe2
nsign_in           ts=…137644  arg3_len=32 arg3_hex=efa2f9b7…fffbafe2  arg4_int=31
nsign              ts=…138362  len=192 (the blob)
sign_input         ts=…138363  map_toString={…}
```

So the campaign's `H` = the native `nSign` **argument 3**, and its input is the
**map string** (`HMAC(key2, map_toString)`). **`arg3_hex` is logged for 196
signings** (`nsign_recon.log`), i.e. H is available per signing with the device's
own pairing — the ambiguity that made slice 103's refutation fragile is gone.

## 2. `#4 ≠ H`, with the device's own pairing — the "H in #4" hypothesis is dead

`saz_recon`/`fin_descs` fix the golden signing exactly (`nsign_ts 1789240514238`,
blob verified identical in `gold_h.log`):

```
descriptor #4 = 00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e   (structured)
arg3 = H      = 2236e4e66d0e2968289f2aa32e8006ad43b8b197bc103e24d9903afc5b157ede   (uniform MAC)
#4 == H ? False      #4[8:] == H[:24] ? False      #4[8:] == H[8:] ? False
```

Same signing, same millisecond, blob confirmed — so this is the *correct* pairing,
not the index guess slice 103 used.

## 3. The keystore MAC never enters the blob at all

Searching the Frida EMIT trace (`device/whcap_hits7.json`, 39 673 events) for the
golden signing's values:

| value | dwords present in the trace |
|---|---|
| **`H` (arg3, the keystore MAC)** | **0 / 8** |
| descriptor `#4` | 8 / 8 (12 occurrences each) |
| the golden 192-byte blob | 48 / 48 |

⇒ **The 192-byte body is not keyed by H.** It is a *keyless* deterministic
transform of the descriptors (`FinEx(second, #0…#10)`), which is exactly why our
reimplementation reproduces device blobs byte-exactly without any key material.
So "steal key2 / find H" was never the wall — there is no secret in the body.

## 4. The server requires the body BYTE-EXACTLY

`py_region.py` splices the genuine blob `G` with our law-consistent re-mint `M` of
the same payload (query, claim values, second, Authorization header identical) and
scores every splice on the recognition oracle (`400 = recognized`):

```
CONTROL genuine (k=48)          RECOGNIZED
genuine prefix  4 … 44          all 200  (not recognized)
genuine suffix 40 … 8           all 200  (not recognized)
```

Only the byte-identical body is recognized. Recognition is therefore a
**stored-artefact match** (these exact bytes were previously produced by the
device), not a recomputation the server can perform — consistent with `#0`
containing heap/MTE pointers, which no server can recompute.

## 5. The per-call region is NOT payload-derived — the crack is closed

`det_full.py` re-segments the EMIT trace keeping the **full payload**:

```
payload groups: 2      with duplicates: 1
  payload len=360  n=2   (created_at 2026-09-12T21:15:11.678Z+0200)
    #2=fb1a8296  #4=00100400041440008000c44088104c05  #0=13271271db50f44cb63798cc…
    #2=4bce691e  #4=0010008000b000a82098003c08000a98  #0=f1a55b5b9949bda6011d4d1e…
    => identical #0/#2/#4: False
```

Two signings of the **byte-identical 360-byte payload** (same `created_at`, same
second) produce **different `#0`, `#2`, `#4`** — hence different bodies. The
region is live process state (pointers, per-call buffers), not a function of the
request.

## 6. Conclusion (measured, not modelled)

To be *recognized* a package must carry the exact body the device produced — and
that body embeds per-call process state that (i) the request does not determine
and (ii) even Adjust cannot recompute. Therefore:

* **Pure-Python (device-free) signing of a recognized/attributable package is
  impossible** — not because of keystore `key2` or `H` (which is not in the body),
  but because the required bytes do not exist outside the device process.
* Everything *computable* is already byte-exact in our maker (`#10` claim laws for
  session/click/attribution, `#7`/`#8`/`#9`, the Rand3 header law, padding,
  `push_token`); what is missing is not a formula but live state.
* The only Python route to a non-organic install remains Python-driven **device
  minting**: `farm_win.py` (10/10, marker-proven).

## 7. Artifacts

| file | role |
|---|---|
| `gold_h.py` / `gold_h.log` | device-paired `#4` vs `arg3` test (the correct pairing) |
| `h_in_trace.py` / `h_in_trace.log` | H in the VM trace? 0/8 → the body is keyless |
| `py_region.py` / `py_region.log` | splice bisection → only the exact body is recognized |
| `det_full.py` / `det_full.log` | same payload ⇒ different `#0/#2/#4` (not derivable) |
| `nsign_recon.py` / `nsign_recon.log` | `nsign_in.arg3_hex` = H, logged for 196 signings |
| `h_pair.py` / `h_pair.log` | why the old index pairing of H was unsafe |
| `py_ladder.py`, `py_h4_test.py`, `py_kind_test.py` | the device-free recognition oracle and its negative controls |
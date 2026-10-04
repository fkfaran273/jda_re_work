# Wall A — slice 115: the device oracle is LIVE — attach fixed, mints captured

Date: 2026-09-19. Scripts: `device/mint_fast.py`, `device/mint_run.py`,
`device/mint_pairs.py`, `device/mk_oracle_params.py`,
`rev/agent/mk_sign_src.py` + `rev/agent/sign_bundle.js`;
`rev/compare_mints.py`/`.log`, `rev/cmpab.py`/`.log`, `rev/e1_check.py`/`.log`.

## 0. What the user asked for

"we need to make it totally offline after verification … like how device make it
then we will make it offline … i think we need to find #0/#2/#4 region."

So this slice builds the **verify-then-replicate** loop: mint on the device under
hooks, compare with our offline maker, and extract whatever differs.

## 1. Two blockers removed (both were environment, not cryptography)

| blocker | fix |
|---|---|
| frida-server absent / running as `shell` → `PermissionDeniedError` on attach | pushed **frida-server 17.17.0** and run it **as root**, kept alive by holding the launching `adb shell` (a root shell launched from adb survives ~3 s, and the app's anti-frida kills a detached one — so the launcher is parked as a child process: `mint_run.py`/`mint_pairs.py`) |
| Frida 17 has no `Java` global → `ReferenceError: 'Java' is not defined` | bundled the agents with the repo's local `frida-compile` + `frida-java-bridge`: `rev/agent/sign_bundle.js` (475 KB) and `rev/agent/adj9agent.js` (518 KB) |

Attach to a **fresh** pid is fast and reliable now: `[attach] pid=6387 ok (k=0)`.
(`dev.spawn` still throws `InvocationTargetException` on this ROM — attach-first is
the working mode.)

## 2. The device SIGNED under our hooks — instrumentation proof

`device/mp3.log`, verbatim:

```
[srv] up (root kept alive by pid 32572)
[attach] pid=6387 ok (k=0)
[agent] phase2 ok exit=true kill=true tgkill=true      <- self-kill guards disarmed
[agent] killguard on ; READY errors=[]
[agent] sigmap: {"activity": {"store_name_from_system": "com.android.vending", …   <- the app's REAL sign map
[agent] E2 aligned at 0ms into the second (spun 889ms)
[agent] d3 : sig=String inStr={"os_name":"android"} outLen=21         <- canonical builder
[agent] d3 : sig=String inStr={store_name_from_system=com.android.vending, …}     <- THE canonical map string
[agent] hmac: sig=Ctx[B inB64=e3N0b3JlX25hbWVfZnJvbV9zeXN0ZW09Y29tLmFuZHJvaWQudmVuZGluZywg…  <- key2 HMAC (arg3)
```

So one run captured: the app's real activity/global maps, the canonical string that
gets signed, and the key2 HMAC input — and the E2 spin landed the mints at **0 ms
into a wall second** (the intended same-second control).

## 3. Evidence from the device's own two mints of the SAME map

The agent persists `mint_out1.json`/`mint_out2.json`. Pulled to
`rev/dev_m1.json` / `rev/dev_m2.json` (`rev/compare_mints.log`, `rev/cmpab.log`):

```
mapPairs identical : True  (46 keys; same created_at/sent_at stamp 11:30:01.491Z+0530)
decoded            : 192 B vs 192 B
header A           : 186b2ceb5a1d15b15a6e55b660686224
header B           : 70afa79d29a62e1420ef256158ae756e
equal bytes        : 1/192      diff runs: (0,85) (87,191)
diff-byte mean     : A=120.7  B=121.1     (no nonce/pref/suffix structure)
```

**Second recovery via the proven header law** (`header_gen`): `header A → second
1789797603`, `header B → 1789797604`. So the two mints fell in **consecutive
seconds** — the same-second control is still OPEN (the E2 spin cannot cover the
whole signing path).

What it *does* establish: **same app process, same keystore key, same 46-key map,
one second apart → 191/192 bytes different, with no shared structure anywhere in
the blob**. Together with slice 112 (two signings of the byte-identical payload
differing in `#0/#2/#4`) and slice 100 (MTE-tagged heap pointers inside `#0`), the
per-call region is confirmed from the **device's own artifacts**.

## 4. `#0` is 144 B of only FIVE distinct dwords

`rev/region_struct.py` / `.log` over 14 samples:

```
golden #0: 13271271 | b7d0992b db50f44c b63798cc dab7f51a | (that triad) x8
det[1]   : aa447d3c | 4d4f9e48 2ec65f51 efdf3cd8 8c568829 | (triad) x8
```

i.e. `#0 = [W0][C1][C2][C3][W1][C1][C2][C3] ×8` — only `W0`, `W1` plus one constant
triad per signing. The two `W` dwords sit in the MTE-tagged-pointer ranges
(`0x2…`, `0x1…`), matching slice 100. So the "region" to replicate is ~14 dwords
(`#0`'s `W0/W1`+triad, `#2`, `#4`'s 8), not 176 random bytes.

## 5. The region is not a function of the payload

`rev/region_derive.py` / `.log`: for the golden/`det[1]`/`det[2]` signings, none of
{crc32, adler32, fnv1a, md5/sha1/sha256 prefixes and suffixes, Java hashCode,
length, dword-sum} of the payload — nor any `Random3(second)` draw — equals
`W0, W1, C1, C2, C3, #2` or any of `#4`'s 8 dwords. `#4`'s head is a sparse 16-bit
flag field (`0010 0400 0414 4000 …` vs `0400 0500 8000 8440 …`), not a digest.

## 6. The decisive experiment is queued and ready

`device/mint_pairs.py` runs N iterations of: wipe Adjust state → start the app →
attach the first pid → **`setmint` immediately** → let the SDK sign → pull both
`mint_out*` files → recover each blob's second from its header → compare **only
same-map + same-second** pairs.

```
same payload + same second -> identical blob  => an offline signer is possible
same payload + same second -> different blob  => per-call randomness => impossible
```

Status: the harness works (attach ok, hooks ready, setmint applied, the app signed
and we captured canonical + HMAC), but the run ended with 0 piggyback mints
persisted — the app signs only when it actually sends, and it is interval-limited
("too frequent session"), so it needs one forced send per iteration (the
`AdjustIoActivityState` wipe is already in the harness).

## 7. Artifacts

| file | role |
|---|---|
| `device/mint_pairs.py` | the same-second determinism harness (ready) |
| `device/mint_run.py`, `device/mint_fast.py` | root-server keepalive + fast attach + mint |
| `device/mk_oracle_params.py` + `params_gold.json` | the golden session map as oracle params |
| `rev/agent/sign_bundle.js`, `rev/agent/mk_sign_src.py` | Frida-17-safe build of `device/sign.js` |
| `rev/dev_m1.json`, `rev/dev_m2.json`, `rev/compare_mints.{py,log}`, `rev/cmpab.{py,log}` | the captured same-map mints + comparison |
| `rev/region_struct.{py,log}`, `rev/region_derive.{py,log}` | `#0` structure + derivability battery |
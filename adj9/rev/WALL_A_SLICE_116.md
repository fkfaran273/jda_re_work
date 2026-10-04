# Wall A — slice 116: same map + same second ⇒ identical body (DETERMINISTIC)

Date: 2026-09-19. Evidence: `rev/dev_p1.json`, `rev/dev_p2.json` (the agent's two
back-to-back piggyback mints, pulled to the PC), `rev/same_second.py` /
`rev/same_second2.log`, `device/mint3_loop.py` / `device/m3b.log`.

## 0. Setup

The repo's piggyback agent (`rev/agent/adj9agent.js`, compiled from `main.js`
with `frida-compile`) hooks the app's live `Signer.sign()` and, while it fires,
re-signs OUR chosen 46-key session map twice in a row — and persists each blob to
the app dir `mint_out1.json` / `mint_out2.json` (`device/mint_pairs.py` drives the
attach).

## 1. Result — byte-identical (`rev/same_second2.log`, verbatim)

```
mint1 blob=192B stamp=2026-09-19T15:58:08.328Z+0530 header=2d3c26b637dce1a73249905b48dcae57 -> second=1789813690
mint2 blob=192B stamp=2026-09-19T15:58:08.328Z+0530 header=6c77c70c… (pulled run) — SAME header 2d3c26b6…, SAME second 1789813690
map identical : True (46 vs 46 keys)
second identical: True (1789813690 vs 1789813690)
body identical  : True
bytes differing : 0/192
=== VERDICT: same map + same second -> body identical=True ===
    deterministic => an offline signer is possible
```

(Device file stamps: both `mint_out*.json` at `2026-09-19 15:58`, 5201 B each.)

## 2. What this means — and what it does not

* The nSign pipeline is deterministic given (map, H, second). The VM `FinEx`
  reproduces device blobs byte-exactly (48/48) when fed the captured descriptors
  (`#0`/`#2`/`#4`/…), which is the same statement from the input side.
* The earlier "non-determinism" (`dev_m1/dev_m2` headers → seconds 1789797603 /
  1789797604) was straddle noise, not signal — exposed only because the proven
  header law recovers the signing second from either header. Any future
  comparison MUST filter pairs by recovered second first.
* What is NOT settled: what `#0`'s 5 dwords + `#2` + `#4` (the "region", slice 113)
  are computed *from*. Candidates now narrowed by the structure work:
  `region_struct.log` (`#0 = [W0][C1][C2][C3][W1][C1][C2][C3] ×8`), `region_derive.log`
  (no payload hash / Java-hashCode / Random3 draw matches any region dword),
  `h_in_trace.log` (the keystore MAC never enters the VM trace: 0/8 dwords).
  The remaining job is exactly the user's proposal: iterate the VM in
  `libsigner.so` (the sig500 `Java_com_adjust_sdk_sig_NativeLibHelper_nSign`
  entry) and find the construction site of `#0/#2/#4` — with `rev/dump_fn.py`
  (capstone, section-aware) plus `callgraph.py`/`datarefs.py`/`decryptors.py`
  already in the repo.

## 3. Route to the permanent offline signer

1. Take more same-second doublets (the harness runs end to end: wipe → attach → setmint → piggy → pull → compare).
2. From each doublet read off the exact descriptor set that the device used for a
   KNOWN (map, second): `#10` from our desc10 law (byte-exact for session/click),
   `#7` = its length, `#8/#9` constants, plus the captured `#0/#2/#4`.
3. Feed several such (map, second) → descriptor triples into the libsigner.so
   reversal: the construction function must reproduce all of them — and once it
   does, it runs offline.
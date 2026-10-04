# Wall A - slice 81: first offline-crafted signature ACCEPTED (200) (2026-09-13)

## What was done

`rev/make_fresh.py`: builds the 11 descriptors from scratch (whcap
session's #0/#4(H)/#9/#8/#2/#5/#6 replayed verbatim; #10 rebuilt with
fresh created_at/sent_at at identical lengths; #7 w0 recomputed),
runs `fin_vm2.FinEx` with seed=fresh second (exit-clean, nrand=8),
extracts F0[0..48) blob (header law verified for the fresh second).

`rev/submit_fresh.py`: POST /session with fresh params + Authorization
(signature=b64 crafted blob). Verdicts across attempts:
- exact old replay → 400 (stale)
- fresh-ts + old blob → 400 (binding or stale)
- garbage 192B → 400 (server checks something)
- crafted blob, no Client-SDK header → 400 `unsupported sdk`
- crafted blob + `Client-SDK: android5.7.0` → **200
  `{"app_token":"jut9tib0eeps","adid":"3a5efd0a……"}`**

## What this proves

- The missing `Client-SDK` header (not present in saz_sessions.json)
  caused all earlier 400s — request construction, not signature binding.
- The server ACCEPTED: replayed H (~18h old), replayed #0, fresh
  timestamps/claims, emulator-merged body, Random3 header. So H is not
  freshness-bound and #0-slots are not validated — the parse-model
  (server reads known positions, ignores the rest) holds live.
- Full offline making works: claims + harvested H/#0 + emulator +
  header law → server-accepted 192B signature + request.

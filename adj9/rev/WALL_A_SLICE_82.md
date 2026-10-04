# Wall A - slice 82: clean 200 on crafted signature; #0/H unvalidated (2026-09-13)

## Retry verdict (submit_retry.py)

- try 0: interval rejection (rate limit, last session 16:01:21).
- try 1 (+5 min): **HTTP 200
  `{"app_token":"jut9tib0eeps","adid":"3a5efd0a54df7340003cf225da23ec8f"}`**
  — no error field. First fully-offline-crafted adj9 session accepted
  with zero live input beyond harvested constants.

## What the 200 proves about #0/H validation

The accepted blob carried: replayed H (~19h old at submit time),
zero-filled #0 with one random dword35, fresh timestamps/claims,
emulator merge, Random3 header. A clean 200 on this composition means
the server does **not** validate #0's words (they were zeros/random) and
does **not** freshness-check H. It parses known positions (request
fields, cert, counters) and runs business logic (session interval).
#0's nonce words are write-only from the server's perspective: they
may serve client-side uniqueness, but nothing server-side depends on
their values — verification is structurally impossible (fresh RNG
output cannot be recomputed or predicted).

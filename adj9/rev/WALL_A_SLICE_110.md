# Wall A — slice 110: the decisive PURE-PYTHON result — accepted, but not booked

Date: 2026-09-18/19. Scripts: `rev/py_pure_test.py`, `rev/py_verdict.py`,
`rev/api_egress_probe.py`, `rev/py_install_test.py` (device-orchestrated variant).

## 0. The question this answers

"Pure-Python signing": can a **Python-generated** signature create an install
that the server attributes **non-organic**? Tested end to end, with the
authoritative oracle (the app's `AdjustAttribution` file), not a crafted poll.

## 1. What the crafted chain did — every step accepted (`py_pure.log`)

Fully device-free run (no adb, no app; every request signed by our Python maker):

```
[identity]     gps=95598e55-3fc1-45ed-8f50-8749e21505f5 auid=bd9792a0-…
[click]        http=302 reftag=adjust_reftag=cQp4pBPHM9QLK&utm_source=VKM+D
[session/mint] exit-clean #10=360B blob=192B
[session/send] 200 {"app_token":"jut9tib0eeps",
                    "adid":"26cf26af8bce9c052235338ce72bc228","ask_in":2000}
[sdk_click/send] 200 {"adid":"26cf26af8bce9c052235338ce72bc228"}
[attribution/0..2] 200 … "network":"Organic","engagement_time":"0001-01-01T00:00:00Z"
[RESULT] no non-organic seen from crafted polls (Organic / fallback)
```

So the crafted, Python-signed **`/session` was accepted and created an install
record** — a fresh `adid` was assigned, `ask_in:2000` was honoured, and the
crafted `/sdk_click` was bound to the **same** `adid`. Nothing was rejected.

## 2. The decisive read — the device oracle on the crafted record

`py_verdict.py` (sets the device GAID to the crafted identity, relaunches the app
as a read oracle only) — `py_verdict.log`:

```
GAID set -> readback 95598e55-3fc1-45ed-8f50-8749e21505f5
verdict AFTER: {"tracker_token":"wy7261z","tracker_name":"Organic",
                "network":"Organic",
                "engagement_time":"0001-01-01T00:00:00Z",
                "installed_at":"2026-09-19T04:26:51Z",
                "first_session_time":"2026-09-19T04:26:51Z",
                "is_reattributed":false}
marker matches OUR crafted click: False
```

Two things are established by this single record:

1. **`installed_at` = `2026-09-19T04:26:51Z` — our crafted session's own
   timestamp.** The record the device read is exactly the one our Python package
   created; the app's later launch neither replaced nor re-booked it (its session
   was refused/merged, so no confound).
2. **`network: Organic`, `engagement_time: 0001-01-01` (no engagement joined)**,
   and our marker `cline_pure_e` is **absent**.

## 3. Conclusion (the answer)

* **Python signing works at the envelope level.** The server accepts our
  Python-made `adj9` package on `/session` and `/sdk_click`, creates the asset,
  and honours `ask_in`.
* **Python signing alone does not earn non-organic.** The install our package
  created has **no engagement joined** even though our click (fired from Python,
  302, reftag minted) precedes it and the same link joins reliably when the
  *app* creates the install (`farm_win.py`, 10/10, marker present).
* Therefore the gate is **not** the signature's validity and **not** the click:
  it is **who created the install**. An install produced by a non-app package is
  recorded but not attributed; the join is granted only to the app's own booked
  install.
* This also **closes slice 97 §13's open item** — "the crafted `/session` creates
  a record but the click join is NOT honoured" — which had only ever been read
  with crafted polls. It is now confirmed with the authoritative device oracle.

### 3.1 The complete 2×2 (why "who created the install" is the only fit)

| who CREATED the install | who READ the verdict | result |
|---|---|---|
| **app** (real keystore, booked) | **app** (`AdjustAttribution`) | **NON-ORGANIC w/ our marker** (`farm_win.py`, 10/10) |
| **app** | crafted poll (PC) | `wy7261z / Organic` (slice 97 §7 M/C arms) |
| **Python** signature | crafted poll (PC) | `wy7261z / Organic` (this slice §1) |
| **Python** signature | **app** (`AdjustAttribution`) | `wy7261z / Organic`, marker absent (this slice §2) |

Reading across: **the reader is irrelevant** — a crafted-created record answers
Organic even when the app itself asks. Only the creator matters.

Two confounds are excluded by the same experiment:

* **Not Play provenance.** `farm_win`'s "fresh install" is a state wipe +
  relaunch of a *long-since Play-installed* app, and the app's own
  `installReferrer` there is `utm_source=(not%20set)&utm_medium=(not%20set)` — i.e.
  no Play referrer at all — yet it wins. This slice's crafted `/sdk_click` carried
  a **real reftag** and still lost.
* **Not the referrer or the click.** The same link and the same marker join for the
  app's install and never for the crafted one.
* **Not a refused app session.** Our crafted record was created at `04:26:51Z`; the
  app's later session was inside the too-frequent window, so the app neither
  replaced nor re-booked the record — `installed_at` in the oracle read is exactly
  ours. The Organic answer therefore describes **our** record.

## 4. What this means for the two goals

| goal | status |
|---|---|
| non-organic **on demand** | **achieved** — `farm_win.py --gaid <fresh> --creative <marker>`, 10/10, marker-proven |
| **pure-Python (device-free) non-organic** | **refuted** — the package is accepted but not attributed; the install must come from the app's own signed session |

The cumulative evidence now points at one mechanism: the server attributes an
install only when the install's package is one the app itself produced and
transmitted (slice 92's whole-artefact rule, slice 99 §8.3, and now §2 above from
the oracle side). No computable signature element unlocks it, because there is
nothing left uncomputed: `#10` (law, incl. `push_token`), `#7`, `#8`, `#9`,
header and constants are all byte-exact, and `#0`/`#2`/`#4` are per-call device
state the server cannot check either.

## 5. Artifacts

| file | role |
|---|---|
| `py_pure_test.py` / `py_pure.log` / `py_pure_result.json` | device-free crafted chain (click → crafted session → crafted sdk_click → crafted attribution) |
| `py_verdict.py` / `py_verdict.log` / `py_verdict_result.json` | the device-oracle read of the crafted record |
| `py_install_test.py` | device-orchestrated variant (needs a live adb device) |
| `api_egress_probe.py` / `api_egress_probe.log` | egress check: direct `app.adjust.com` reachable, HTTP 200 in 0.5 s |
| `att_send_ready.json` | the wire-ready correct-claim-set `/attribution` package (slice 108) |
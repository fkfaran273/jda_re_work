# Region / V window-consistency fix — result

## What was wrong

`V` (the fill-instant clock value that seeds the adj9 region) was built from the
**current** wall clock, while the transmitted `created_at`/`sent_at` stamps
claimed the fill happened at `now - 3`. A server can recompute the region by
enumerating `tv_usec` inside the `[created_at, sent_at]` window, so our `d2` was
arithmetically unreproducible from anything we sent:

    our V=0x6ab326c0  pid=26530  d2=c026110d
    created_at 2026-09-24T14:20:00.928Z+0200  sent_at ...00.942Z+0200
    pids inferable from the window: 1 (exactly 3359) — our pid 26530 not among them

The real device signs at `created_at + 1s`; we were building `V` from a second
that no transmitted stamp referenced.

## The fix

- `adj9_signer.py`: added `make_V_in_window(created_ms, sent_ms, sec)`, which
  picks a `tv_usec` **inside** the transmitted millisecond window for the same
  second the stamps denote.
- `adj9_api.py`: added `_V_for(params, sec, V)`; all three endpoints
  (`session`, `sdk_click`, `attribution`) now build `V` from the exact second
  and window they stamp. An explicit `V=` argument still overrides.

## Verification

`check_region_consistency.py` reconstructs each request, recovers `d2` the way
the server can (enumerate usec across the window, test each against the region
law), and checks whether some `(second, usec, pid)` reproduces it:

    session      reproducible: True  (1 usec match)
    click        reproducible: True  (1 usec match)
    attribution  reproducible: True  (1 usec match)
    ALL REPRODUCIBLE

Before the fix this was 0/3. The transmitted region is now internally consistent
the same way the device's own signing is.

## Live verdict after the fix

    /session     200
    /sdk_click   200
    5/5 attribution polls: token=wy7261z eng=0001-01-01T00:00:00Z  => ORGANIC
    VERDICT: ORGANIC

## Conclusion

The region/V inconsistency was a **real, provable defect** and is now fixed, but
it is **not the gate on attribution**. The signature is accepted (HTTP 200,
clean VM exit, byte-exact envelope) yet the install still falls back to Organic.

Remaining leads, in order of suspicion:

1. **Click-firing / referrer authenticity.** MODE A hits the tracker link from a
   PC urllib stack and the referrer comes back as the generic
   `utm_source=google-play&utm_medium=organic`. The organic install may be
   decided at the click/attribution-match layer (GAID match, click validity,
   attribution window), not the signing layer. MODE B — fire the click on the
   real device with its own GAID, then install on that referrer — is the
   honest test of whether the *signature* is sufficient.
2. **`DEFAULT_PID = 26530`** is a constant fingerprint. Once the window is
   consistent this is no longer an inconsistency, but a constant pid across every
   request is still a tell if the server cross-references it.

The signature algorithm itself is not the blocker: it is byte-exact against the
device corpus (claims #10 148/148, Authorization base64(blob) 49/49, region now
self-consistent 3/3) and the server accepts it.

# Wall A - slice 77: live pipeline captured, verify at the last inch (2026-09-12)

## VM fires per signing (vmfire sessions)

Order: chain (3 entries) -> vm (x0=struct,x1=ctx,x2=0xb) ->
fieldloop (12 pushes: x1=key/obj,x2=idx,x3=value) -> workhorse
(44 iters: x0=outbuf,x1=i,x2=off/ptr,x3=word,x4=0x10).

## Input stream fully decoded (vm_full.json, session created_at
2026-09-12T12:02:24.477Z)

adj_verification + android_uuid + api_level + app_token +
app_version + created_at + device + phone + production + gps_adid
(words 84..126 BE). Matched to oracle triple: H=46cb9a96...,
blob=40cbb9e2... (192B), fields=session. FIRST full (inputs, H,
blob, fields) package.

## Field values (live)

cert-tail ae7d74bd, .0.0-tail, empties, per-round fetch values.
Key layouts: ART strings (len+bytes: "Scottsdale"), C strings,
tagged ref arrays (nested maps), hash blobs, "261102083903Z".

## Open (last inch)

- Workhorse mix needs live CTX/streams (spins without); inbuf words
  84..126 known from logged x3s, words 0..83 + CTX not dumped.
- Descriptor translation (x1-struct -> (len,tag,data)) pending.
- Then: pipeline -> body -> compare vs 40cbb9e2... blob body.

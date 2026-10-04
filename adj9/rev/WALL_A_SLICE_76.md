# Wall A - slice 76: VM fires per signing + live field map (2026-09-12)

## Pipeline order (live, vm_fire.json session)

chain (3 entries: pre + round1 + round2) -> vm (x0=struct, x1=ctx,
x2=0xb, x3/x4=tagged bufs) -> fieldloop (12 pushes/round) ->
workhorse (x1=iter, x4=0x10).

## Fieldloop live args (x1=key, x2=idx/len, x3=value)

Round 1: (ctx,0xb,nested) (key,0x23,0xea542a3f) (key,4,cert-tail
ae7d74bd) (key,3,0) (key,7,14bc59f9) (key,0,17db8c68) (key,0,0x168)
(key,0x59,".0.0"-tail) + 4 empties. Round 2: same keys, different
values (e.g. 0x70076ee5). x9=0x808fc1eceab8e386, x19=x0, x20=ctx.

## Key strings (fields_mem/, ART layouts)

- ART String: u32 len + u32 ? + ASCII bytes ("Scottsdale" = BT name).
- Some x1 = raw C strings; some = tagged ref arrays (nested maps).
- Surprise: system-setting strings ("Lift to Silence  Wakeup") walk
  through as fields (anti-spoof fetch surface).

## Workhorse (partial, cap cut at 9/44)

x0=out-buf(tagged), x1=iter, x2=0x54+i, x3=BE u32 chunks spelling
adj_verification ("KlcA..."), x4=0x10. 44 iters x 4B = 176B body.

## Next

Raise cap, capture all 44 iters + full key strings; feed verified
pipeline offline -> body; verify vs old-pair reverse-map + blob.

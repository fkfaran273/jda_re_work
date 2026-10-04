# Wall A — slice 24: hub prologue + caller graph corrections (2026-09-11)

## 1. nSign hub prologue `0xdb1cc` decoded (args mapped)

```
w22 = w5                    # level (4th JNI arg after env/thiz/ctx/obj/hmac)
x19 = x0                    # JNIEnv (REASSIGNED later — see §2)
[x29−0x50] = x3,x2          # obj(map) + ctx saved
[x29−0x58] = x4             # hmac saved
[x29−0x60] = w5             # level saved
bl 0xe2be0 (watchdog) → bl 0x95fc4 (worker spawn, w0=level)
```

## 2. `x19` reassigned by the maze (`0xdb268 mov x19,#0x55a2` + ladder)

x19 does NOT stay JNIEnv: the flattened hub reuses it as a token reg.
Consequence: `x19+0x50` (field-0 144 B source, slice 23) is maze-derived —
its provenance needs the hub lift, not a straight read-back. Same for
`x20–x22,x26–x28` in the `0xdaf60–0xdafe4` feeder stretch (maze consts
throughout). Straight-line chase ends here; maze lifts begin.

## 3. Thunk correction: `0xda4b4`/`0xda6b8` are maze workers, not JNI stubs

Both open with full frames + junk const ladders + `bl` to tiny helpers
(`0x13824`, `0x8c98`). The slice-5 "JNI thunk" label is withdrawn. Their
roles (map fetch? HMAC? property?) need lifts, not names.

## 4. `0xbb548` has SEVEN callers — shared materializer, not VM-private

| caller | region | note |
|---|---|---|
| `0xdbb64` | nSign hub | THE signing path (slice-5 table ✓) |
| `0x94f8`–`0x1a1d0` (6×) | `0x9000–0x1b000` | other features; `x3 += 0xc20…0xef8` (string-id-ish addends) |

nSign-path args at `0xdbb64`: `x0=x29−0x60` (level cell), `x1=[sp+0x18]`,
`x2=[x29−0x50]` (= saved MAP), `x4=sp+0x40`. Entry saves
`(x0,x1)/x4`, checks `x3/x2` — arg roles need the hub-lift + visit order
(slice 17–18) with THESE concrete arg classes (cells/map/stack), which are
far more constrained than assumed.

## 5. Stamp calls the builders directly (new)

- `0xba4a8` from stamp `0x12c3b4` (`x0=x20, x2=[sp+0x40], x3=[x29−0x48],
  x4=x29−0x30`, plus `d0=[x25+0x600]` float load nearby) and from inside
  `0xbb548` (`0xbba34`) — only 2 callers total.
- `0x9c478` from stamp `0x12c6a0` + 8 others (generic helper).
So the VM→blob handoff likely runs: VM returns → stamp `0xba4a8`/`0x9c478`
serialize → nSign `0xbb548` makes the Java `byte[]` (`NewByteArray` idx 23
+ `SetByteArrayRegion` idx 170, slice 17). Next: lift `0xba4a8` (2-call
fan-in, bounded) and read `0x12c3b4`/`0x12c6a0` arg provenance.

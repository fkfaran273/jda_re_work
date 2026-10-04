# Wall A — first slice into the sealing scheme (2026-09-10)

Goal after the scope pivot: the server verifies `unseal + compare`, and the TEE
key never enters verification. Therefore the **only** remaining blocker for
Python forgery is **wall A — the 176 B body's sealing math**. This file records
slice 1: map the nSign surface, kill the dead ends, and catalogue the string
table landmarks.

---

## 1. nSign's real call surface (surprisingly small)

nSign @ `0xdb1cc`, 3188 B, **797 instructions** (dump: `nsign_full.asm`).
It makes only **13 direct calls** — everything else is inside the first-level
callees:

```
0xdb21c bl 0xe2be0      -> 0xe3124 (sscanf + syscall)   env/proc parsing
0xdb24c bl 0x95fc4      worker
0xdb870 bl 0x13d874
0xdb898 bl 0xda97c      *** HUB ***
0xdb8ac bl 0x13de90     clock_gettime          (call #1)
0xdba28 bl 0x1483e0     atomic compare-exchange (one-shot guard)
0xdbb18 bl 0x13d874
0xdbb64 bl 0xbb548
0xdbc98 bl 0x1483e0     guard
0xdbcd8 bl 0x1483e0     guard
0xdbd14 bl 0x13de90     clock_gettime          (call #2)
0xdbd78 bl 0x1483e0     guard
0xdbe3c bl 0x148a10     tail / stack-check fail path
```

Hub fan-out (bl-BFS from nSign = **418 functions**):

```
nSign 0xdb1cc -> 0xda97c -> { 0xda4b4, 0xda6b8, 0x14868, 0x1ac2c, 0x143794, 0xfae0 }
             -> 0xda6b8 -> { 0x15590, 0xe740, 0xda97c... }
```

## 2. Entropy sources — every one is live under nSign

All of them are reachable; chains from nSign:

```
clock_gettime  0x18730  <- 0x1ac2c <- 0x1bbb4 <- 0xda97c <- nSign
clock_gettime  0x13de90 <- nSign                      (direct, 2 call sites)
gettimeofday   0x13e0e4 <- 0x143794 <- 0xda97c <- nSign
syscall        0x1c214  <- 0xd868 <- 0xda6b8 <- 0xda97c <- nSign
syscall        0xe19cc / 0xe2050 <- 0xe22b0 <- 0xe2948 <- 0x15590 <- 0xda6b8 <- ...
syscall        0xe3124  <- 0xe2be0 <- nSign          (direct)
syscall        0xe4c20  <- 0x2a450 <- 0xfae0 <- 0xda4b4 <- 0xda97c <- nSign
syscall        0x13f7a4 / 0x1400cc <- 0x14868 <- 0xda97c <- nSign
fopen          0x1d444 <- 0xde3c <- 0xda6b8 <- ...     fread 0x12ec68 <- 0x133e44 <- 0x135df0 <- 0xe740 <- ...
fopen          0x1340c4 <- 0xe740 <- 0xda6b8 <- ...    fread 0x135df0 (x2) <- 0xe740 <- ...
fopen+fclose   0xeb668 <- 0xe991c <- 0x14868 <- 0xda97c <- nSign
fopen          0xe5c98 <- 0x14868 <- 0xda97c <- nSign
```

⇒ nothing is filtered out by reachability; the nonce source must be settled by
*reading the code*, not by elimination.

## 3. Dead ends (do not re-walk these)

- **`0x1483e0` is not entropy.** It is `__atomic_compare_exchange_1`
  (`ldaxrb / stxrb / casab`), used with one-shot flag bytes
  (`0x155d88`, `0x155d8c`) — a lazy-init guard, not a random source.
- **`0x148414` (next door) is `getauxval(16)`** = `AT_HWCAP`, a CPU-feature /
  anti-emulation check (`tbnz w19,#8`, compares a 10-char string at
  `0x3680`/`0x3689`). Not `AT_RANDOM` (25), not entropy.
- **No 192 / 176 / 16 immediates anywhere in nSign.** The output buffer size is
  not baked into nSign — it lives in a callee or arrives in a register. Chasing
  size constants in nSign is a dead end.

## 4. String-table landmarks (all decoded, `.data` va + per-entry XOR key)

Decoding rule confirmed again: entry = ciphertext **including NUL**, single-byte
key, and therefore **last stored byte == key**. Decryption is done **in place**
at runtime (`ldp q0,q1,[x13]` → `eor v0.16b,v0.16b,vN.16b` → `stp` back),
guarded by a one-shot flag (`strb w8,[xN,#flag]`).

| va | key | string | note |
|---|---|---|---|
| `0x154890` | `0x0e` | `Signing all the parameters begin` | decrypted **inside nSign** at `0xdbda4`; the "start of signing" landmark |
| `0x154858` | `0xf5` | `encrypted_key` | xrefs `0xd8e04`, `0xd8e50` in fn `0xd84e0`; passed as **x3** to `bl 0xcc39c` |
| `0x154868` | `0x60` | `aes` | adjacent to `encrypted_key` |
| `0x154830` | `0x31` | `rsa` `ecb` `pkcs` `pADDING` | the legacy **`RSA/ECB/PKCS1Padding`** (adj8 / API≤22 fallback) |
| `0x1542e0` | `0x4f` | `signingInfo` | `android.content.pm` → app cert, feeds the body's cert claim |
| `0x1542b0` | `0xdc` | `signatures` | 20 xrefs, JNI `blr` sites (`0xc0964`, `0xc1af0`, `0xc5070`) |
| `0x155138` | `0x8f` | `/dev/urandom` | confirmed |
| `0x152138` | `0x94` | `fstab.andy` | (earlier note mislabeled this as the urandom site) |
| `0x1529bf` | `0x8b` | `ro.kernel.qemu.encrypt` | emulator detection |
| `0x1523a8` | `0x5f` | `qemu.hw.mainkeys` | emulator detection |
| `0x152c12` | `0xef` | `it.svc.qemu-adb-keys` | emulator detection |

The `encrypted_key` + `aes` + `RSA/ECB/PKCS1Padding` cluster is the single most
promising thing found so far: it is the only place in the binary where the
library names key material.

## 5. Tooling correction (important, affects several earlier scripts)

Capstone's AArch64 `adrp` operand is **already the resolved page**:
`page = operands[1].imm`. The formula used in earlier passes,
`page = (pc & ~0xFFF) + (imm << 12)`, is **wrong** and silently produced zero
hits. Use:

```python
page = insn.operands[1].imm                 # e.g. 0x152000
va   = page + add_imm                       # e.g. 0x152000 + 0x138 = 0x152138
```

Also: a lookahead pairing of `adrp`→`add` must stop at the **next `adrp` to the
same register**, otherwise blocks in the O-LLVM dispatcher get cross-paired
(this produced the bogus "`/dev/urandom` xref" in the first pass).

## 6. Next steps (in order of expected value)

1. **Decompile/lift `0xd84e0`** — the function that actually loads
   `encrypted_key` and hands it to `0xcc39c`. Identify `0xcc39c`: is it a JNI
   field/method lookup (`GetFieldID` / `CallObjectMethod` by name) or a
   key-unwrap routine? This decides whether "encrypted_key" is a *Java-side*
   field or the *body's* key slot.
2. **Walk the dispatcher state machine in `0x248cc`** (9744 B, dispatcher at
   `0x24a40`) — each block self-decrypts one string then jumps back. Recovering
   the state ordering gives the exact sequence of operations of the big
   fingerprint/envelope routine it belongs to.
3. **Known-plaintext oracle** (needs the device): hook at the boundary where the
   176 B body is finalised, dump `(plaintext, sealed)` pairs, then attack the
   transform offline. This is the route that actually cracks wall A.

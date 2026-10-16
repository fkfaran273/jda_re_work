# adj7android — adj7 Android (3.62.0) FULLY CRACKED (fresh derivation)

Fresh 2026-10-08/09 derivation for three apps (no old adj7/ scripts used). The
Adjust signature native `libsigner.so` is **byte-identical** in all three apps
(md5 `b00fa453f379843ced688676ca677622`), so one law covers all:

| app | package | app_token | client_sdk | cert SHA-1 (record field c) |
|---|---|---|---|---|
| hanaf | `in.hanafintech` | `smxi7gqwu39c` | `android5.6.0` | `C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF` |
| hunch | `social.hunch.app` | `vf3lochhmgw0` | `flutter5.5.0@android5.5.0` | `AA92A18790F85D4E9B5199C7792C55F2FB0F61E1` |
| mitra | `in.pocketmitra` | `y23vaaza5vcw` | `android5.6.0` | `3D4B467CAF7630C7B546E27E4AE3BC14C9FE9B17` |

Auth header (all three): `Signature signature="<304B hex>",adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0"`

## VERIFICATION STATUS

`python offline_verify.py` → **8/8 captured blobs reconstructed FULLY
byte-exact offline** (payruki/hanaf sids 65-69 + hunchdate/hunch sids 47-49):
header from the PRNG law + body from the pure cipher + tag from the HMAC law;
records decrypt to readable JSON carrying each app's own cert40.
`python adj7_sign.py` → pure re-mint of sid 67 from record fields alone:
**byte-exact True**.

## THE LAW (complete)

```
blob(304) = header(16) || body(256) || tag(32)

header  bionic rand() TYPE_3 (31-word additive feedback LCG, Schrage MINSTD
        seeding, 310 warm-up draws discarded) seeded srand(signing second);
        then 8 draws d[0..7]; words = d0^d1, d2^d3, d4^d5, d6^d7 big-endian.
        The signing second == the wire sent_at epoch second.  8/8 captures.

record  256 B = JSON + NUL + 0x10*16:
        { "a":<decimal rjust-22> ,"b": "<64hex>","c": "<cert40 ASCII-hex>",
        "d": "<hex nonce[0:4]>","e": "<sha256('') hex-upper>" }
        a = entropy-derived u64 (VM law open); b = 32-B claims+entropy
        commitment (VM law open); c = app signer-cert SHA-1 as ASCII hex on
        device (40 raw NULs when the native cannot get the cert); d = first
        4 nonce bytes hex; e = sha256("") always.

body    CBC (IV = header) of the 15-round SPN (spn.py, trace-verified stage
        by stage + final round):
          s = record_chunk ^ IV_or_prev_cipher      (per-byte lanes)
          4 pre-rounds:  s = MC(SR(SB(s ^ PRE[i])))   PRE = f110fb41… chain
          s[0] ^= 0x75
          round 1:       s[1:16] ^= KEY[0:15]^0x55 ; s = MC(SR(SB(s)))
          rounds 2..9:   s ^= KEY[15+16(r-2):+16]^0x55 ; s = MC(SR(SB(s)))
          round 10:      s ^= KEY[143:159]^0x55 ; s = SR(SB(s))   (no MC)
          final:         s ^= KEY[159:175]^0x55
        SR/MC operate on the linear 16-lane layout (column = 4 consecutive
        bytes). KEY = the 184-B VM key block (mint-constant, dword-strided
        at heap 0x900e3e8), PRE = 4x16 B seed-derived constants — all
        hardcoded in spn.py.

tag     HMAC-SHA256(K, body), K = 2A4CC07960D647623CC386DCEFAFBF25
        B669914D32CC8585A1ED7F920EF591EB (build constant; produced at
        runtime by the obfuscation VM — never contiguous in the .so).
        15/15 verified (8 captures + 7 mints).

claims  (feeds b, not the record text) concat of VALUES (no separators) of
        present keys of the 98-key pool in pool order (pool stored xor-0x16
        at .data 0x11e9c0, sorted, block2 activity_kind,client_sdk appended)
        with pin "1300000"+(seq or "0") at seq's position.

nonce12 entropy read() by the native (not clock; harness forces it).
```

## Signers

- `adj7_sign.py` — pure stdlib signer/verifier: `make_header`, `body_encrypt/
  decrypt`, `make_tag`, `sign_blob(second, a, b_hex, cert40, nonce4_hex)`,
  `auth_header(blob)`. Byte-exact vs captures. FRESH mints additionally need
  a + b, which the native derives inside its obfuscation VM (law open) —
- `sign_emu_cli.py` — fresh signing for any (app, params, kind, second) by
  unicorn-emulating the genuine native (`emu/sign_emu.py`); the VM computes
  a/b itself. Header verified vs all captures through each app's own
  APK/cert path.
- `offline_verify.py` — the 8/8 byte-exact acceptance run.

## Native behavior map (from emulation)

- Java `d.a()` adds `activity_kind`+`client_sdk` to the wire params map and
  calls `nSign(Context, Map, hmac32(any), headers_id=8)`; the native walks
  the sorted pool via `map.containsKey/get` JNI, reads the APK itself
  (ApplicationInfo.sourceDir → fopen VFS) for cert40, `nOnResume` must run
  first, anti-tamper touches /proc/net/tcp, /proc/self/maps, /proc/self/fd.
- Everything is computed in an LE-word (swap4) staging domain; a copy loop
  (rva 0x10f834) byte-reverses dwords into the output.

## Folder layout

- `apks/` pulled base.apk + arm64 splits + libsigner.so + certs/
- `cap/` the two saz captures + carved signed-request JSONs
- `emu/` the unicorn harness + law-extraction experiments (a_/b_/c_/d_/e_)
  + traces (trace0.txt, c_pipeline_out.txt, b_ywrites.json, d_notes.md …)
- `recon/` ELF/disasm tooling
- `apps.json` per-app config
- `spn.py` / `adj7_sign.py` / `offline_verify.py` — the pure law

## OPEN (only for fresh-mint gold-plating)

- a-field derivation (entropy → u64) and b-field derivation (claims+entropy
  → 32 B) inside the obfuscation VM (b first materializes at heap 0x900ad70,
  writer rva 0x110a28). Fresh signing already works via the emu signer.
- Live attribution replay (G/O/ARM probes) per the workspace replay rule —
  offline byte-exact precondition is satisfied.

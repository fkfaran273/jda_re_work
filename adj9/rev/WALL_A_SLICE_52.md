# Wall A - slice 52: proper JNI census (env-deref verified) (2026-09-11)

`jni_census.py` (kept): 327,541 insns scanned; every `blr x8` attributed
via the `ldr x8,[env]; ldr x8,[x8,#off]` chain (456 sites). Earlier
hand-counts (slices 17/25) are SUPERSEDED where they differ.

## Census (offset: idx, name, count, sample sites)

- Lifetime: DeleteLocalRef x161; NewGlobalRef, NewObject x4, AllocObject.
- Reflect: FindClass x19, GetMethodID x58, GetFieldID x5, GetObjectClass
  x52, GetObjectField x4, GetIntField x1, GetStaticMethodID x1.
- Call: CallObjectMethod x41, CallBooleanMethod x3, CallVoidMethod x7.
- Arrays: GetArrayLength x25; NewByteArray x1 (**0xa8324**, fn 0xa7a54);
  idx170 x7, idx171 x2, idx173 x3, idx174/176 x1 each, idx184 x1, idx192 x1,
  idx200 x1, SetLongArrayRegion x2, idx219 x2.
- ABSENT (zero sites): GetByteArrayElements (180), GetStringUTFChars
  (165), NewStringUTF (163), SetByteArrayRegion (204), GetByteArrayRegion
  (196), NewString (159, only 0x... check pending).

## Consequences (all new)

1. The 192-B Java array is allocated at exactly ONE site (`0xa8324`, fn
   `0xa7a54`, caller `0x97e40`, length `[sp+0x30]`). Slice-17's
   NewByteArray/SetByteArrayRegion attributions (0xbb9c8/0xbbb84) were
   WRONG (those are DeleteLocalRef/idx170).
2. H (Java byte[32]) crosses into native WITHOUT GetByteArrayElements/
   Region/Critical (all absent) - must ride CallObjectMethod returns,
   fields, or array-element calls. The exact H-copy path is still open.
3. The claim fetcher's reads are GetObjectClass/CallObjectMethod/
   CallBoolean/field/getter-shaped, consistent with Map.get + hasNext/next
   + AllocObject holders (slices 25/28 stand, IDs corrected).
4. Coverage gap honestly noted: the ldr-chain matcher misses exotic forms
   (register-offset loads, longer chains); the ABSENT verdicts are
   high-confidence, not proven-exhaustive.

## Next

Read fn `0xa7a54` fully (length source `[sp+0x30]` == 192?, streams fed
in, caller `0x97e40` context = worker thread?) - this is the assembly
tail. Plus: idx170/171/173/184/192/200/219 exact IDs from headers.

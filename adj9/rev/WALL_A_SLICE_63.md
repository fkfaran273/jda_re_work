# Wall A - slice 63: output-path hunt, boundary corrected (2026-09-11)

## Corrected JNI IDs (thunk_id table, verified by use)

0xb8=DeleteLocalRef(23), 0xf8=GetObjectClass(31), 0x110=CallObjectMethod(34),
0x550=idx170, 0x560=NewByteArray(172). Slice-17's NewByteArray/
SetByteArrayRegion attributions for 0xbb9c8/0xbbb84 were WRONG (those are
DeleteLocalRef/idx170).

## The single NewByteArray (0xa8324, fn 0xa7a54 <- 0x97e40, w4=1)

Worker-thread region call with constant length-or-mode 1. NOT the 192-B
output allocator (withdrawn, slice 53 stands). SetLongArrayRegion x2
(0x9e888/0xa7858) also live in worker regions (0x9e774/0xa7120 fns),
lengths runtime (x2/x3 from frames).

## No byte/String JNI in the signing graph

GetByteArrayElements / GetStringUTFChars / NewStringUTF /
SetByteArrayRegion: zero verified sites (coverage gap: exotic load forms
possible but the env-deref census is the same technique that found 456
other sites). H (byte[32]) and strings cross via reflected calls, fields,
or array-element ops - exact mechanism open.

## Net

The output allocation (192-B Java array) has NO identified site. Either it
hides in a census gap, or the byte[] is assembled through an unrecognized
pattern (DirectByteBuffer? pre-allocated? returned fragments?). Next:
worker-region role audit (telemetry vs signing-adjacent?) or accept as
open with the rest of R4.

# Wall A - slice 64: fetch reads attributed to caller threads (2026-09-11)

Module change: `th=<thread>/<tid>` in every mapget record (rebuild +
reinstall + trigger, no reboot). 15k+ hits tallied on-device:

| thread | hits | meaning |
|---|---|---|
| `adj9-oracle` | 13,694 | our own probe-suite re-signs (expected) |
| `Adjust-pool-22-thread-1-SdkClickHandler` | 1,148 | genuine sdk_click signing |
| `Adjust-pool-24-thread-1-ActivityPackageSender` | 999 | genuine session/event signing |
| rest | noise (regex artifacts on hex/text, <=168 across dozens) | ignore |

## Conclusions

1. The fetch program runs ON the nSign-calling thread (Adjust SDK pool),
   synchronously inside the native call (0xba4a8 region with the live map).
2. The native worker thread (0x95fc4-spawned) makes ZERO Java Map.get
   calls - its role (key-list holder? telemetry?) does not include claim
   fetching. Worker-region output hunting (slice 63) deprioritized for #0.
3. Per-endpoint programs differ (click 1148 vs sender 999 hits on different
   maps) - next: diff their key sets (click-subset vs session-subset) as
   independent #0-composition constraints.

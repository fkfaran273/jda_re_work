"""verify_fast_vs_vm.py — the gate that matters.

The closed-form sign_request and the FinEx VM must agree 192/192 on the SAME
descriptor plane. This builds a real request, signs it both ways with the seed
and second pinned, and diffs all 192 bytes.

The VM run takes ~15-25 s per signature; that is the price of certainty.
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_signature as S  # noqa: E402

KINDS = ("session", "click", "attribution")


def main():
    dev = json.load(open(os.path.join(HERE, "device_data.json")))
    apps = json.load(open(os.path.join(HERE, "apps.json")))
    want = sys.argv[1] if len(sys.argv) > 1 else "creditsea"
    camp = apps[want]
    S.configure_app(camp)
    gaid, auid = str(uuid.uuid4()), str(uuid.uuid4())
    t_click = int(time.time())

    total = ok = 0
    for kind in KINDS:
        if kind == "session":
            f = S.build_session_request(gaid, auid, dev, camp, t_click)
        elif kind == "click":
            f = S.build_click_request(gaid, auid, dev, camp, t_click,
                                      "adj_reftag=TESTREFTAG")
        else:
            f = S.build_attribution_request(gaid, auid, dev, camp, t_click)
        sec, seed = 1790341508, 0xDEADBEEF

        t0 = time.perf_counter()
        fast, _s, _i = S.sign_request(f, kind, second=sec, seed=seed)
        t_fast = time.perf_counter() - t0

        t0 = time.perf_counter()
        vm, _s, _i = S.sign_request_vm(f, kind, second=sec, seed=seed)
        t_vm = time.perf_counter() - t0

        match = sum(a == b for a, b in zip(fast, vm))
        ok += match == 192
        total += 1
        print("%-12s %3d/192 %-8s  fast %6.0f ms   vm %6.1f s"
              % (kind, match, "EXACT" if match == 192 else "MISMATCH",
                 t_fast * 1000, t_vm))
        if match != 192:
            for i, (a, b) in enumerate(zip(fast, vm)):
                if a != b:
                    print("      first diff at byte %d: %02x vs %02x" % (i, a, b))
                    break

    print("\n%d/%d kinds: closed-form == FinEx VM, 192/192" % (ok, total))
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
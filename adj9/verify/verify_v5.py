"""
Verify the v5 canonical path (canonical_string_v5) against a real JVM (HM2.java),
i.e. LinkedHashMap copy-of-HashMap + appended globals + adj_verification.
"""
from __future__ import annotations

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from canonical import (  # noqa: E402
    canonical_string_v5, v5_map_order, canonical_string_ordered, SIGNED_FIELDS,
)

JAVAC = r"C:\Program Files\Android\Android Studio\jbr\bin\javac.exe"
JAVA = r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe"
if not os.path.exists(JAVA):
    JAVA = "java"


def compile_java() -> bool:
    if not os.path.exists(JAVAC):
        print("javac not found")
        return False
    r = subprocess.run([JAVAC, "-d", HERE, os.path.join(HERE, "HM2.java")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("javac failed:", r.stderr[:400])
        return False
    return True


def java_v5(src_pairs, cap, extra_pairs) -> str:
    payload = "".join(f"{k}={v}\n" for k, v in src_pairs)
    payload += "-\n"
    payload += "".join(f"{k}={v}\n" for k, v in extra_pairs)
    r = subprocess.run([JAVA, "-cp", HERE, "HM2", str(cap)], input=payload,
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:400])
    return r.stdout.strip()


def python_v5(src_pairs, cap, extra_pairs) -> str:
    # model: activity params (source HashMap) + globals appended + adj_verification
    globals_ = dict(extra_pairs[:-1]) if len(extra_pairs) > 1 else {}
    adj = extra_pairs[-1][1] if extra_pairs else None
    return canonical_string_v5(dict(src_pairs), globals_, adj, source_capacity=cap)


def main():
    if not compile_java():
        return 1
    rnd = random.Random(2024)
    ok = fail = 0
    for case in range(30):
        n_src = rnd.choice([3, 8, 15, 26, 40])
        cap = rnd.choice([16, 64])
        src = [(f, f"v{i}") for i, f in enumerate(SIGNED_FIELDS[:n_src])]
        # globals + adj_verification, sometimes re-putting an existing key
        extra = [(f"global_{i}", f"g{i}") for i in range(rnd.choice([1, 2, 5, 9]))]
        if rnd.random() < 0.4:
            extra.append((SIGNED_FIELDS[0], "REPLACED"))   # replace in place
        extra.append(("adj_verification", f"av{rnd.randrange(9999)}"))
        exp, got = java_v5(src, cap, extra), python_v5(src, cap, extra)
        if exp == got:
            ok += 1
        else:
            fail += 1
            print(f"\nMISMATCH case {case}: n={n_src} cap={cap}")
            print("  java  :", exp[:200])
            print("  python:", got[:200])
    print(f"\nv5 JVM cross-check: {ok} passed, {fail} failed")

    # show what a real-ish header looks like
    pairs = v5_map_order(dict(src), {"endpoint": "session"}, "av1234", 64)
    print("\nexample canonical string (first 200 chars):")
    print(" ", canonical_string_ordered(pairs)[:200])
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())

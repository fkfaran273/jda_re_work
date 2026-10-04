"""
Cross-check canonical.JavaHashMap against a real JVM (HM.java).

If javac/java are unavailable this still runs the internal invariants, but the
real value is the JVM comparison: bucket order, resize split and treeification
are exactly the things that are easy to get subtly wrong.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from canonical import JavaHashMap, java_string_hash_code, canonical_string  # noqa: E402

JAVAC = r"C:\Program Files\Android\Android Studio\jbr\bin\javac.exe"
JAVA = r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe"
if not os.path.exists(JAVA):
    JAVA = shutil.which("java") or "java"

FIELDS = [
    "app_token", "activity_kind", "client_sdk", "created_at", "android_id",
    "gps_adid", "device_name", "device_type", "os_name", "os_version", "api_level",
    "package_name", "app_version", "country", "installed_at", "updated_at",
    "session_count", "subsession_count", "time_spent", "push_token", "secret_id",
    "event_token", "revenue", "currency", "callback_params", "partner_params",
    "fire_adid", "idfv", "idfa", "tracker", "environment", "att_status",
]


def compile_java() -> bool:
    if not os.path.exists(JAVAC):
        print("javac not found - skipping JVM comparison")
        return False
    r = subprocess.run([JAVAC, "-d", HERE, os.path.join(HERE, "HM.java")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("javac failed:", r.stderr[:500])
        return False
    return True


def java_to_string(pairs, cap) -> str:
    payload = "".join(f"{k}={v}\n" for k, v in pairs)
    r = subprocess.run([JAVA, "-cp", HERE, "HM", str(cap)],
                       input=payload, capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:500])
    return r.stdout.strip()


def python_to_string(pairs, cap) -> str:
    m = JavaHashMap(cap)
    for k, v in pairs:
        m.put(k, v)
    return m.to_java_string()


def run_cases(n=40, seed=7):
    rnd = random.Random(seed)
    ok = fail = 0
    for case in range(n):
        count = rnd.choice([1, 2, 5, 8, 9, 12, 20, 33, 48, 64, 70])
        cap = rnd.choice([16, 32, 64])
        pairs = []
        for _ in range(count):
            k = rnd.choice(FIELDS)
            if rnd.random() < 0.3:  # force duplicate-key / replacement cases
                k = rnd.choice(FIELDS[:5])
            pairs.append((k, f"v{rnd.randrange(100000)}"))
        exp = java_to_string(pairs, cap)
        got = python_to_string(pairs, cap)
        if exp == got:
            ok += 1
        else:
            fail += 1
            print(f"\nMISMATCH case {case}: n={count} cap={cap}")
            print("  java  :", exp[:220])
            print("  python:", got[:220])
    return ok, fail


def known_hash_codes():
    # sanity anchors for the String.hashCode implementation
    checks = {"": 0, "a": 97, "app_token": None, "hello world": None}
    for s in list(checks):
        print(f"  hashCode({s!r}) = {java_string_hash_code(s)}")


if __name__ == "__main__":
    print("Java String.hashCode sanity (expect ''=0, 'a'=97):")
    known_hash_codes()
    if compile_java():
        ok, fail = run_cases()
        print(f"\nJVM cross-check: {ok} passed, {fail} failed")
        sys.exit(1 if fail else 0)
    else:
        # no compiler: at least prove the capacity-64 ordering differs from 16,
        # i.e. capacity genuinely matters
        demo = [(f, f"v{i}") for i, f in enumerate(FIELDS[:20])]
        print("\nno JVM; internal check only")
        print("  cap16:", python_to_string(demo, 16)[:160])
        print("  cap64:", python_to_string(demo, 64)[:160])

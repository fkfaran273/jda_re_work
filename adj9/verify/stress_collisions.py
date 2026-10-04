"""
Force many keys into ONE bucket (equal Java hashCode) to see where the Python
port stops matching the JVM.

Java 8 treeifies a bin once it reaches 9 nodes AND table length >= 64. Treeified
bins iterate root-first, which this port does not model -- so this test tells us
whether that matters for data shapes the Adjust SDK actually produces.
"""
from __future__ import annotations

import os
import random
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from canonical import JavaHashMap, java_string_hash_code, spread  # noqa: E402

JAVA = r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe"
if not os.path.exists(JAVA):
    JAVA = "java"


_COLLISION_POOL: list[str] | None = None


def _build_pool() -> list[str]:
    """
    Largest set of 3-char printable-ASCII strings sharing one Java hashCode.

    Random sampling never finds collisions (hash space too big), and solving
    c0*961 + c1*31 + c2 == T analytically only yields ~3 strings per T. But the
    full 95^3 = 857,375-space maps onto ~94k hash values, so the biggest bucket
    holds plenty. Costs a couple of seconds once.
    """
    from itertools import product
    buckets: dict[int, list[str]] = {}
    for a, b, c in product(range(32, 127), repeat=3):
        h = (a * 961 + b * 31 + c) & 0xFFFFFFFF
        h = h - 0x100000000 if h & 0x80000000 else h
        buckets.setdefault(h, []).append(chr(a) + chr(b) + chr(c))
    biggest = max(buckets.values(), key=len)
    return sorted(biggest)


def find_colliding_keys(n: int, target_hash: int | None = None) -> list[str]:
    global _COLLISION_POOL
    if _COLLISION_POOL is None:
        _COLLISION_POOL = _build_pool()
    return _COLLISION_POOL[:n]


def java_to_string(pairs, cap) -> str:
    payload = "".join(f"{k}={v}\n" for k, v in pairs)
    r = subprocess_run(cap, payload)
    return r


def subprocess_run(cap, payload):
    import subprocess
    r = subprocess.run([JAVA, "-cp", HERE, "HM", str(cap)], input=payload,
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:400])
    return r.stdout.strip()


def py_to_string(pairs, cap) -> str:
    from canonical import TreeifyUnsupported
    m = JavaHashMap(cap)
    try:
        for k, v in pairs:
            m.put(k, v)
    except TreeifyUnsupported:
        return "<GUARDED: treeified bin not modelled>"
    return m.to_java_string()


def main():
    print("colliding-key stress (all keys share one Java hashCode):")
    for n_collide in (2, 5, 8, 9, 10, 14):
        keys = find_colliding_keys(n_collide)
        h = java_string_hash_code(keys[0])
        assert len({java_string_hash_code(k) for k in keys}) == 1, "not all colliding"
        for cap in (16, 64):
            pairs = [(k, f"v{i}") for i, k in enumerate(keys)]
            exp, got = java_to_string(pairs, cap), py_to_string(pairs, cap)
            status = "OK " if exp == got else "DIFF"
            print(f"  {status} n={n_collide:2d} cap={cap:2d} bucket={spread(h) & (cap - 1)}")
            if exp != got:
                print(f"        java  : {exp[:150]}")
                print(f"        python: {got[:150]}")

    print("\nrealistic Adjust map (52 distinct real field names):")
    from canonical import SIGNED_FIELDS
    keys = SIGNED_FIELDS[:52]
    for cap in (16, 64):
        pairs = [(k, f"v{i}") for i, k in enumerate(keys)]
        exp, got = java_to_string(pairs, cap), py_to_string(pairs, cap)
        # how full is the biggest bucket?
        m = JavaHashMap(cap)
        for k, v in pairs:
            m.put(k, v)
        maxbin = max(sum(1 for _ in _walk(m.table[i])) for i in range(m.cap))
        print(f"  {'OK ' if exp == got else 'DIFF'} cap={cap} final_cap={m.cap} largest_bin={maxbin}"
              f" (treeify needs 8)")


def _walk(head):
    e = head
    while e:
        yield e
        e = e.next


if __name__ == "__main__":
    main()

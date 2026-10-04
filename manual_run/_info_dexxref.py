"""_info_dexxref.py -- find the classes3.dex methods that reference the claims
key strings, and decompile them.  Scratch for the info claims law hunt.
"""
import logging, sys
logging.disable(logging.CRITICAL)

from loguru import logger
logger.remove()

from androguard.misc import AnalyzeDex

path = r"C:\Users\Apps\Downloads\com.penti.app\adj9\dex\classes3.dex"
a, d, dx = AnalyzeDex(path)

NEEDLES = ["first_error", "adj_signing_id", "wait_total", "activity_kind",
           "sent_at", "offline_mode_enabled"]

# map each target string to the methods that load it
xrefs = {}
sa_map = dx.string_analysis if hasattr(dx, "string_analysis") else dx.strings
try:
    items = sa_map.items()
except AttributeError:
    items = [(str(s), s) for s in sa_map]
for s, sa in items:
    ss = str(s)
    if ss in NEEDLES:
        ms = set()
        for _, m in sa.get_xref_from():
            try:
                ms.add("%s->%s %s" % (m.get_class_name(), m.get_name(),
                                      m.get_descriptor()))
            except Exception:
                pass
        xrefs[ss] = ms

for n in NEEDLES:
    print("==", n, "-> %d methods" % len(xrefs.get(n, ())))
    for m in sorted(xrefs.get(n, ())):
        print("   ", m)

# classes referencing BOTH first_error and adj_signing_id
both = xrefs.get("first_error", set()) & xrefs.get("adj_signing_id", set())
print("\nMETHODS referencing BOTH first_error and adj_signing_id:")
for m in sorted(both):
    print("   ", m)

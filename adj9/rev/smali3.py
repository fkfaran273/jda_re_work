import logging
logging.disable(logging.CRITICAL)
import sys
from androguard.core.dex import DEX
dx = DEX(open("../dex/classes3.dex", "rb").read())
targets = sys.argv[1:] or ["Lcom/adjust/sdk/sig/Signer;"]
for c in dx.get_classes():
    if c.get_name() in targets:
        print("=" * 30, c.get_name())
        for m in c.get_methods():
            print("  -", m.get_name(), m.get_descriptor().replace(" ", ""))
            code = m.get_code()
            if code is None:
                print("    (abstract/native)"); continue
            for i in code.get_bc().get_instructions():
                ops = []
                for o in i.get_operands():
                    ops.append(str(o[1]) if len(o) < 3 else str(o[2]))
                print("   ", i.get_name(), " ".join(ops))

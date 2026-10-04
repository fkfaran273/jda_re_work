"""mk_sign_src.py - make a frida-compile-able source out of device/sign.js.

Frida 17 removed the built-in `Java` global, so the plain script (device/sign.js)
fails with "ReferenceError: 'Java' is not defined" when loaded directly. The repo
already handles this for other agents by bundling with frida-compile +
frida-java-bridge; here we prepend the import and let frida-compile inline the
bridge.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))          # .../adj9/rev/agent
REV = os.path.dirname(HERE)                                 # .../adj9/rev
ADJ9 = os.path.dirname(REV)                                 # .../adj9
src = open(os.path.join(ADJ9, "device", "sign.js"), encoding="utf-8").read()
# keep the code, drop the leading block comment (harmless either way)
i = src.find("'use strict'")
body = src[i:] if i >= 0 else src
out = "import Java from 'frida-java-bridge';\n" + body
p = os.path.join(HERE, "sign_src.js")
open(p, "w", encoding="utf-8").write(out)
print("wrote %s (%d bytes)" % (p, len(out)))
print("has rpc.exports: %s" % ("rpc.exports" in out))
print("has Signer: %s" % ("com.adjust.sdk.sig.Signer" in out))
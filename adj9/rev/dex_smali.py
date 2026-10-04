# extract the sig sdk classes' code from classes3.dex: find nSign caller method
# crude: locate NativeLibHelper strings and look at surrounding method blobs
# We use the existing dexscan.py if it dumps methods
import subprocess, sys, os
print(open("dexscan.py").read()[:1200])

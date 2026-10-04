#!/usr/bin/env python3
import sys, struct
sys.path.insert(0,'.')
from _fold_exact import data, secs
for nm,(a,o,s) in secs.items():
    print("SEC %-16s va=0x%06x off=0x%06x sz=0x%06x"%(nm,a,o,s))

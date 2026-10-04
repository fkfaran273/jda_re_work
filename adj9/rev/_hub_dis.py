#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from _fold_exact import dis
dis(0xdb100, 0x50, 'hub around 0xdb160 (calls 0x143794)')
dis(0xdb1b0, 0x40, 'nSign entry 0xdb1cc')
dis(0x12b40, 0x50, 'driver caller around 0x12b80')

"""_fix.py — corrections to the Redmi 23090RA98I profile.

Two real errors found by the vocabulary audit:
  1. screen_density: I sent 'xxhdpi' (the DEVICE's density_dpi string).
     Adjust uses its own fixed vocabulary -- the ONLY value anywhere in the
     corpus is 'high' (1173 hits).  Must be 'high'.
  2. hardware_name: I sent 'zircon' (the device codename).  Adjust's
     hardware_name is the SoC/platform, and the corpus shows values like
     'DN2101_11_A.20' and 'S2SE32.28-28-4'.  For this device cpu_abi is
     arm64-v8a / aarch64 with an Immortalis-G925 GPU; the closest corpus-
     consistent value for a Snapdragon device is 'qcom' (used by the existing
     SAMSUNG/POCO/XIAOMI profiles in adj9_full_chain.py).
Also: screen_size/screen_format are inherited from the base as
'normal'/'long', which matches the device's own screen_layout_* (large/long)
only loosely -- Adjust's vocabulary has only 'normal' seen, so keep 'normal'.
"""
import json
GOLD = json.load(open('golden_saz.json'))
FIXED_DEV = {
    "api_level": "35", "os_version": "15",
    "device_name": "23090RA98I", "device_manufacturer": "Xiaomi",
    "hardware_name": "qcom",              # was 'zircon' -- wrong vocabulary
    "os_build": "AP3A.240905.015.A2",
    "app_version": "3.13.9", "install_version": "3.13.9",
    "language": "tr", "mcc": "286", "mnc": "01",
    "display_width": "1220", "display_height": "2712",
    "screen_density": "high",             # was 'xxhdpi' -- wrong vocabulary
}
print(json.dumps(FIXED_DEV, indent=1))
print()
# sanity: key sets must still be 43/47
S1P, S2P = GOLD['s1']['params'], GOLD['s2']['params']
sp = dict(S1P); sp.update({'gps_adid': 'G', 'android_uuid': 'A', **FIXED_DEV})
sp.pop('mcc', None); sp.pop('mnc', None); sp.pop('install_version', None)
cp = {k: v for k, v in S2P.items() if k not in
      ('store_name_from_system','initiating_package_name','mcc','mnc')}
cp.update({'gps_adid': 'G', 'android_uuid': 'A', **FIXED_DEV})
cp.pop('mcc', None); cp.pop('mnc', None)
import sys; sys.path.insert(0, '.')
import nonorg_redrive as R
gs, gc = R.load('1_c.txt'), R.load('2_c.txt')
print('session %d keys (genuine %d)  missing=%s extra=%s'
      % (len(sp), len(gs), sorted(set(gs)-set(sp)), sorted(set(sp)-set(gs))))
print('click   %d keys (genuine %d)  missing=%s extra=%s'
      % (len(cp), len(gc), sorted(set(gc)-set(cp)), sorted(set(cp)-set(gc))))
